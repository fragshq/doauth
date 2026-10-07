package doauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Config represents the configuration for the Authenticator.
type Config struct {
	// Name is the application's name
	Name string
	// BaseURL is the authorization server's base URL used for discovery.
	BaseURL string
	// ClientID is the application's ID.
	ClientID string
	// ClientSecret is the application's secret. Prefer PKCE if possible.
	ClientSecret string
	// RedirectURL is where the user will be sent after authorization.
	RedirectURL string
	// Scopes is a list of requested permissions.
	Scopes []string

	// AllowClientCredentials enables client-credentials flow as an alternative to 3-legged flow.
	AllowClientCredentials bool

	// AuthorizationURL and TokenURL can be provided manually to bypass discovery.
	AuthorizationURL string
	TokenURL         string
}

func (c *Config) McpFingerprint() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(c.BaseURL+"|"+c.ClientID)))
}

// Authenticator handles the OAuth2 flow including discovery, URL generation, and token exchange.
type Authenticator struct {
	cfg       Config
	oauth2Cfg *oauth2.Config
	metadata  *Metadata
	client    *http.Client
	logger    *slog.Logger
}

// Option defines a functional option for configuring the Authenticator.
type Option func(*Authenticator)

// WithHTTPClient sets a custom HTTP client for discovery and token exchange.
func WithHTTPClient(client *http.Client) Option {
	return func(a *Authenticator) {
		a.client = client
	}
}

// WithLogger sets a custom slog logger for the Authenticator.
func WithLogger(logger *slog.Logger) Option {
	return func(a *Authenticator) {
		a.logger = logger
	}
}

// NewAuthenticator creates a new Authenticator instance.
func NewAuthenticator(cfg Config, opts ...Option) (*Authenticator, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("ClientID is required")
	}
	if cfg.RedirectURL == "" && !cfg.AllowClientCredentials {
		return nil, fmt.Errorf("RedirectURL is required when client credentials are not allowed")
	}

	auth := &Authenticator{
		cfg:    cfg,
		client: http.DefaultClient,
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(auth)
	}

	// Initialize with provided endpoints if available
	endpoint := oauth2.Endpoint{}
	if cfg.AuthorizationURL != "" && cfg.TokenURL != "" {
		auth.logger.Debug("using manually provided endpoints",
			"auth_url", cfg.AuthorizationURL,
			"token_url", cfg.TokenURL)
		endpoint.AuthURL = cfg.AuthorizationURL
		endpoint.TokenURL = cfg.TokenURL
		auth.metadata = &Metadata{
			AuthorizationURL: cfg.AuthorizationURL,
			TokenURL:         cfg.TokenURL,
		}
	}

	auth.oauth2Cfg = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint:     endpoint,
	}

	return auth, nil
}

// Discover attempts to find OAuth2 metadata.
// It returns true if authentication is required, false otherwise.
func (a *Authenticator) Discover(ctx context.Context) (bool, error) {
	// If endpoints are already provided, assume auth is required
	if a.oauth2Cfg.Endpoint.AuthURL != "" && a.oauth2Cfg.Endpoint.TokenURL != "" {
		a.logger.Debug("endpoints already set, skipping discovery")
		return true, nil
	}

	if a.cfg.BaseURL == "" {
		return false, fmt.Errorf("BaseURL is required for discovery")
	}

	a.logger.Debug("starting discovery", "base_url", a.cfg.BaseURL)

	// 1. Probe the resource first: a 401 challenge pointing at the resource metadata
	// is authoritative (MCP / RFC 9728) and must win over guessed well-known paths.
	probeMeta, authRequired, probeErr := ProbeMetadata(ctx, a.cfg.BaseURL, a.client, a.logger)
	if probeErr == nil && probeMeta != nil && probeMeta.AuthorizationURL != "" && probeMeta.TokenURL != "" {
		a.logger.Debug("probe discovery successful")
		a.ApplyMetadata(probeMeta)
		return true, nil
	}

	a.logger.Debug("probe did not yield metadata, trying standard discovery", "error", probeErr)

	// 2. Fall back to standard discovery locations
	meta, err := DiscoverMetadata(ctx, a.cfg.BaseURL, a.client, a.logger)
	if err == nil {
		a.logger.Debug("standard discovery successful")
		a.ApplyMetadata(meta)
		return true, nil
	}

	if probeErr != nil {
		return authRequired, fmt.Errorf("discovery and probing failed: %w", probeErr)
	}

	if authRequired {
		a.logger.Debug("authentication required but no discovery info found")
		return true, fmt.Errorf("authentication required but endpoints not found")
	}

	a.logger.Debug("no authentication required for this resource")
	return false, nil
}

// ApplyMetadata updates the internal oauth2.Config with endpoints and scopes from discovery.
func (a *Authenticator) ApplyMetadata(meta *Metadata) {
	a.metadata = meta
	a.oauth2Cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  meta.AuthorizationURL,
		TokenURL: meta.TokenURL,
	}
	a.logger.Debug("metadata applied",
		"auth_url", meta.AuthorizationURL,
		"token_url", meta.TokenURL)

	// Use server-supported scopes if none provided in config
	if len(a.oauth2Cfg.Scopes) == 0 && len(meta.ScopesSupported) > 0 {
		a.oauth2Cfg.Scopes = meta.ScopesSupported
		a.logger.Debug("using server supported scopes", "scopes", meta.ScopesSupported)
	}
}

// AuthURLOption defines a functional option for GetAuthURL.
type AuthURLOption func(*authURLOptions)

// authURLOptions holds internal settings for generating an authorization URL.
type authURLOptions struct {
	verifier string
	state    string
	usePKCE  bool
}

// WithState sets a custom state for the authorization URL.
func WithState(state string) AuthURLOption {
	return func(o *authURLOptions) {
		o.state = state
	}
}

// WithVerifier sets a custom code verifier for the authorization URL.
func WithVerifier(verifier string) AuthURLOption {
	return func(o *authURLOptions) {
		o.verifier = verifier
	}
}

// WithPKCE enables or disables PKCE (enabled by default).
func WithPKCE(enabled bool) AuthURLOption {
	return func(o *authURLOptions) {
		o.usePKCE = enabled
	}
}

// GetAuthURL generates the authorization URL.
// It returns the URL, the state, and the code verifier if PKCE was used.
func (a *Authenticator) GetAuthURL(opts ...AuthURLOption) (string, string, string, error) {
	if a.oauth2Cfg.Endpoint.AuthURL == "" {
		return "", "", "", fmt.Errorf("authorization endpoint missing; call Discover() first")
	}

	options := &authURLOptions{usePKCE: true}
	for _, opt := range opts {
		opt(options)
	}

	state := options.state
	if state == "" {
		var err error
		state, err = GenerateVerifier()
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate state: %w", err)
		}
	}

	var verifier string
	var oauthOpts []oauth2.AuthCodeOption
	if options.usePKCE {
		var err error
		verifier = options.verifier
		if verifier == "" {
			verifier, err = GenerateVerifier()
			if err != nil {
				return "", "", "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
			}
		}
		oauthOpts = append(oauthOpts,
			oauth2.SetAuthURLParam(ParamCodeChallenge, GenerateChallenge(verifier)),
			oauth2.SetAuthURLParam(ParamCodeChallengeMethod, MethodS256),
		)
		a.logger.Debug("PKCE enabled for auth URL")
	}

	authURL := a.oauth2Cfg.AuthCodeURL(state, oauthOpts...)

	// Append resource parameter if available (RFC 9728)
	if a.cfg.BaseURL != "" {
		parsed, _ := url.Parse(authURL)
		q := parsed.Query()
		q.Add(ParamResource, a.cfg.BaseURL)
		parsed.RawQuery = q.Encode()
		authURL = parsed.String()
	}

	a.logger.Debug("generated auth URL", "url", authURL, "state", state)
	return authURL, state, verifier, nil
}

// Exchange exchanges an authorization code for a token.
func (a *Authenticator) Exchange(ctx context.Context, code, state, verifier string) (*oauth2.Token, error) {
	a.logger.Debug("exchanging code for token", "state", state, "pkce", verifier != "")
	var opts []oauth2.AuthCodeOption
	if verifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam(ParamCodeVerifier, verifier))
	}

	// Inject the custom client into the context for the oauth2 package
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)
	token, err := a.oauth2Cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	a.logger.Debug("token exchange successful", "expiry", token.Expiry)
	return token, nil
}

// GetMetadata returns the retrieved metadata.
func (a *Authenticator) GetMetadata() *Metadata {
	return a.metadata
}

// AuthorizeRequest injects the token as a Bearer token in the request header.
func (a *Authenticator) AuthorizeRequest(token *oauth2.Token, req *http.Request) {
	req.Header.Set(HeaderAuthorization, BearerPrefix+token.AccessToken)
}

// RefreshToken returns a fresh token, using the refresh token if the current one is expired.
// If the token is expired and was obtained via client credentials (no refresh token),
// it will automatically request a new one via the client credentials flow if available.
func (a *Authenticator) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	a.logger.Debug("refreshing token")

	if token.Valid() {
		a.logger.Debug("token is still valid, no refresh needed")
		return token, nil
	}

	// Inject the custom client into the context for the oauth2 package
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)

	if token.RefreshToken == "" && a.CanUseClientCredentials() {
		a.logger.Debug("refresh token is empty but client credentials flow is available; requesting new token")
		return a.ClientCredentialsToken(ctx)
	}

	ts := a.oauth2Cfg.TokenSource(ctx, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	a.logger.Debug("token refresh successful", "expiry", newToken.Expiry)
	return newToken, nil
}

// CanUseClientCredentials returns true if the client credentials flow is opted-in,
// a client secret is configured, and the server metadata lists "client_credentials" in
// its supported grant types (or endpoints are manually configured).
func (a *Authenticator) CanUseClientCredentials() bool {
	if !a.cfg.AllowClientCredentials {
		return false
	}
	if a.cfg.ClientSecret == "" {
		return false
	}
	if a.metadata == nil {
		return false
	}
	if len(a.metadata.GrantTypes) > 0 {
		for _, gt := range a.metadata.GrantTypes {
			if gt == "client_credentials" {
				return true
			}
		}
		return false
	}
	// If metadata doesn't specify grant types, and manual endpoints are used, assume true.
	if a.cfg.AuthorizationURL != "" && a.cfg.TokenURL != "" {
		return true
	}
	return false
}

// ClientCredentialsToken retrieves a token using the client credentials grant flow.
func (a *Authenticator) ClientCredentialsToken(ctx context.Context) (*oauth2.Token, error) {
	if a.oauth2Cfg.Endpoint.TokenURL == "" {
		return nil, fmt.Errorf("token endpoint missing; call Discover() first")
	}
	if a.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("ClientSecret is required for client credentials flow")
	}

	ccCfg := &clientcredentials.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		TokenURL:     a.oauth2Cfg.Endpoint.TokenURL,
		Scopes:       a.oauth2Cfg.Scopes,
	}

	// Inject the custom client into the context for the oauth2 package
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)

	a.logger.Debug("requesting token via client credentials flow")
	token, err := ccCfg.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("client credentials token request failed: %w", err)
	}
	a.logger.Debug("client credentials token request successful", "expiry", token.Expiry)
	return token, nil
}
