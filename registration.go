package doauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrAuthNotRequired is returned by Register when the resource does not require authentication.
	ErrAuthNotRequired = errors.New("resource does not require authentication")
	// ErrRegistrationNotSupported is returned by Register when no registration endpoint is known.
	ErrRegistrationNotSupported = errors.New("authorization server does not support dynamic client registration")
)

// WithInitialAccessToken sets the bearer token sent with the registration request,
// for authorization servers that restrict registration (RFC 7591 §3).
func WithInitialAccessToken(token string) Option {
	return func(a *Authenticator) {
		a.initialAccessToken = token
	}
}

// WithClientName sets the client_name announced by Register, shown to users on consent screens.
func WithClientName(name string) Option {
	return func(a *Authenticator) {
		a.clientName = name
	}
}

// WithTokenEndpointAuthMethod sets the token_endpoint_auth_method requested by Register,
// e.g. AuthMethodNone for a public client. When unset the server applies its default,
// which is client_secret_basic (RFC 7591 §2).
func WithTokenEndpointAuthMethod(method string) Option {
	return func(a *Authenticator) {
		a.tokenEndpointAuthMethod = method
	}
}

// ClientRegistration holds the client information issued by the authorization server (RFC 7591 §3.2.1).
// It is meant to be persisted by the caller and fed back into Config for the authorization flow.
type ClientRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`

	// Issuer is the authorization server the client was registered with, when known.
	// Not part of the registration response; set by Register.
	Issuer string `json:"issuer,omitempty"`
	// RegistrationEndpoint is where the client was registered.
	// Not part of the registration response; set by Register.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
}

// SecretExpired reports whether the client secret has expired and the client must be registered again.
// A zero ClientSecretExpiresAt means the secret never expires.
func (r *ClientRegistration) SecretExpired() bool {
	return r.ClientSecretExpiresAt != 0 && time.Now().Unix() >= r.ClientSecretExpiresAt
}

// RegistrationError is the error response of the registration endpoint (RFC 7591 §3.2.2).
type RegistrationError struct {
	StatusCode  int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *RegistrationError) Error() string {
	msg := fmt.Sprintf("client registration failed with status %d", e.StatusCode)
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.Description != "" {
		msg += " (" + e.Description + ")"
	}
	return msg
}

// registrationRequest is the client metadata sent to the registration endpoint (RFC 7591 §2).
type registrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// Register performs Dynamic Client Registration (RFC 7591) and returns the issued client credentials.
// It does not authenticate anyone: the caller stores the result and later passes ClientID and
// ClientSecret to NewAuthenticator, using the same RedirectURL and Scopes it registered with.
//
// The registration endpoint is found by discovery from cfg.BaseURL unless cfg.RegistrationURL is set.
// The request is built from cfg: RedirectURL as the only redirect URI,
// the authorization_code and refresh_token grants when RedirectURL is set, client_credentials
// when AllowClientCredentials is set, and the configured or discovered scopes. The client_name
// is set with WithClientName.
func Register(ctx context.Context, cfg Config, opts ...Option) (*ClientRegistration, error) {
	if cfg.RedirectURL == "" && !cfg.AllowClientCredentials {
		return nil, fmt.Errorf("RedirectURL is required when client credentials are not allowed")
	}

	a := newAuthenticator(cfg, opts...)

	endpoint := cfg.RegistrationURL
	if endpoint == "" {
		required, err := a.Discover(ctx)
		if err != nil {
			return nil, fmt.Errorf("discovery failed: %w", err)
		}
		if !required {
			return nil, ErrAuthNotRequired
		}
		endpoint = a.metadata.RegistrationEndpoint
	}
	if endpoint == "" {
		return nil, ErrRegistrationNotSupported
	}

	reg, err := a.register(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	reg.RegistrationEndpoint = endpoint
	if a.metadata != nil {
		reg.Issuer = a.metadata.Issuer
	}
	return reg, nil
}

// register sends the registration request to endpoint and decodes the response.
func (a *Authenticator) register(ctx context.Context, endpoint string) (*ClientRegistration, error) {
	body, err := json.Marshal(a.registrationRequest())
	if err != nil {
		return nil, fmt.Errorf("failed to encode registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if a.initialAccessToken != "" {
		req.Header.Set(HeaderAuthorization, BearerPrefix+a.initialAccessToken)
	}

	a.logger.Debug("registering client", "registration_endpoint", endpoint)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client registration request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read registration response: %w", err)
	}

	// RFC 7591 mandates 201 Created, but some servers answer 200 OK.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		regErr := &RegistrationError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(data, regErr)
		return nil, regErr
	}

	var reg ClientRegistration
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}
	if reg.ClientID == "" {
		return nil, fmt.Errorf("registration response has no client_id")
	}

	a.logger.Debug("client registration successful",
		"client_id", reg.ClientID,
		"confidential", reg.ClientSecret != "",
		"secret_expires_at", reg.ClientSecretExpiresAt)
	return &reg, nil
}

// registrationRequest builds the client metadata from the configuration and the discovered scopes.
func (a *Authenticator) registrationRequest() registrationRequest {
	req := registrationRequest{
		ClientName:              a.clientName,
		TokenEndpointAuthMethod: a.tokenEndpointAuthMethod,
		Scope:                   strings.Join(a.oauth2Cfg.Scopes, " "),
	}
	if a.cfg.RedirectURL != "" {
		req.RedirectURIs = []string{a.cfg.RedirectURL}
		req.GrantTypes = append(req.GrantTypes, GrantAuthorizationCode, GrantRefreshToken)
		req.ResponseTypes = []string{ResponseTypeCode}
	}
	if a.cfg.AllowClientCredentials {
		req.GrantTypes = append(req.GrantTypes, GrantClientCredentials)
	}
	return req
}
