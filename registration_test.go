package doauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRegistrationServer starts an authorization server whose registration endpoint answers with
// handler. The metadata advertises the endpoint only when advertise is true.
func newRegistrationServer(t *testing.T, advertise bool, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var ts *httptest.Server
	mux.HandleFunc(PathOAuthAuthServer, func(w http.ResponseWriter, r *http.Request) {
		meta := map[string]any{
			"issuer":                 ts.URL,
			"authorization_endpoint": ts.URL + "/authorize",
			"token_endpoint":         ts.URL + "/token",
		}
		if advertise {
			meta["registration_endpoint"] = ts.URL + "/register"
		}
		json.NewEncoder(w).Encode(meta)
	})
	mux.HandleFunc("/register", handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// captureRegistration answers with response and stores the decoded request in got.
func captureRegistration(t *testing.T, got *registrationRequest, header *http.Header, response map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(got))
		if header != nil {
			*header = r.Header.Clone()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	}
}

func TestRegister_Discovered(t *testing.T) {
	var got registrationRequest
	ts := newRegistrationServer(t, true, captureRegistration(t, &got, nil, map[string]any{
		"client_id":                "new-client",
		"client_secret":            "new-secret",
		"client_secret_expires_at": 0,
	}))

	reg, err := Register(context.Background(), Config{
		Name:        "github",
		BaseURL:     ts.URL,
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"read", "write"},
	}, WithClientName("my-app"))
	require.NoError(t, err)

	assert.Equal(t, "new-client", reg.ClientID)
	assert.Equal(t, "new-secret", reg.ClientSecret)
	assert.Equal(t, ts.URL, reg.Issuer)
	assert.Equal(t, ts.URL+"/register", reg.RegistrationEndpoint)
	assert.False(t, reg.SecretExpired())

	assert.Equal(t, "my-app", got.ClientName)
	assert.Equal(t, []string{"http://localhost:8080/callback"}, got.RedirectURIs)
	assert.Equal(t, []string{GrantAuthorizationCode, GrantRefreshToken}, got.GrantTypes)
	assert.Equal(t, []string{ResponseTypeCode}, got.ResponseTypes)
	assert.Equal(t, "read write", got.Scope)
	assert.Empty(t, got.TokenEndpointAuthMethod, "server default applies when unset")
}

func TestRegister_UsesDiscoveredScopes(t *testing.T) {
	var got registrationRequest
	ts := newRegistrationServer(t, true, captureRegistration(t, &got, nil, map[string]any{"client_id": "c"}))

	muxRes := http.NewServeMux()
	muxRes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderWWWAuthenticate, `Bearer issuer="`+ts.URL+`", scope="tools:read"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	tsRes := httptest.NewServer(muxRes)
	defer tsRes.Close()

	_, err := Register(context.Background(), Config{Name: "tools", BaseURL: tsRes.URL, RedirectURL: "http://localhost/cb"})
	require.NoError(t, err)
	assert.Equal(t, "tools:read", got.Scope)
	assert.Empty(t, got.ClientName, "Config.Name must not be announced as client_name")
}

func TestRegister_ClientCredentialsAndOptions(t *testing.T) {
	var got registrationRequest
	var header http.Header
	ts := newRegistrationServer(t, true, captureRegistration(t, &got, &header, map[string]any{
		"client_id":     "c",
		"client_secret": "s",
	}))

	_, err := Register(context.Background(),
		Config{BaseURL: ts.URL, AllowClientCredentials: true},
		WithInitialAccessToken("iat"),
		WithTokenEndpointAuthMethod(AuthMethodClientSecretPost),
	)
	require.NoError(t, err)

	assert.Equal(t, BearerPrefix+"iat", header.Get(HeaderAuthorization))
	assert.Equal(t, []string{GrantClientCredentials}, got.GrantTypes)
	assert.Empty(t, got.RedirectURIs)
	assert.Empty(t, got.ResponseTypes)
	assert.Equal(t, AuthMethodClientSecretPost, got.TokenEndpointAuthMethod)
}

func TestRegister_ManualURLSkipsDiscovery(t *testing.T) {
	var got registrationRequest
	discovered := false
	mux := http.NewServeMux()
	mux.HandleFunc("/register", captureRegistration(t, &got, nil, map[string]any{"client_id": "c"}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		discovered = true
		w.WriteHeader(http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reg, err := Register(context.Background(), Config{
		BaseURL:         ts.URL,
		RedirectURL:     "http://localhost/cb",
		RegistrationURL: ts.URL + "/register",
	})
	require.NoError(t, err)
	assert.False(t, discovered)
	assert.Equal(t, "c", reg.ClientID)
	assert.Equal(t, ts.URL+"/register", reg.RegistrationEndpoint)
	assert.Empty(t, reg.Issuer)
}

func TestRegister_PublicClient(t *testing.T) {
	var got registrationRequest
	ts := newRegistrationServer(t, true, captureRegistration(t, &got, nil, map[string]any{
		"client_id":                  "public",
		"token_endpoint_auth_method": AuthMethodNone,
	}))

	reg, err := Register(context.Background(),
		Config{BaseURL: ts.URL, RedirectURL: "http://localhost/cb"},
		WithTokenEndpointAuthMethod(AuthMethodNone),
	)
	require.NoError(t, err)
	assert.Equal(t, AuthMethodNone, got.TokenEndpointAuthMethod)
	assert.Equal(t, "public", reg.ClientID)
	assert.Empty(t, reg.ClientSecret)
}

func TestRegister_NotSupported(t *testing.T) {
	ts := newRegistrationServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("registration endpoint must not be called")
	})

	_, err := Register(context.Background(), Config{BaseURL: ts.URL, RedirectURL: "http://localhost/cb"})
	assert.ErrorIs(t, err, ErrRegistrationNotSupported)
}

func TestRegister_AuthNotRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	_, err := Register(context.Background(), Config{BaseURL: ts.URL, RedirectURL: "http://localhost/cb"})
	assert.ErrorIs(t, err, ErrAuthNotRequired)
}

func TestRegister_ErrorResponse(t *testing.T) {
	ts := newRegistrationServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri","error_description":"not allowed"}`))
	})

	_, err := Register(context.Background(), Config{BaseURL: ts.URL, RedirectURL: "http://localhost/cb"})
	var regErr *RegistrationError
	require.ErrorAs(t, err, &regErr)
	assert.Equal(t, http.StatusBadRequest, regErr.StatusCode)
	assert.Equal(t, "invalid_redirect_uri", regErr.Code)
	assert.Equal(t, "not allowed", regErr.Description)
}

func TestRegister_MissingClientID(t *testing.T) {
	ts := newRegistrationServer(t, true, captureRegistration(t, &registrationRequest{}, nil, map[string]any{
		"client_secret": "s",
	}))

	_, err := Register(context.Background(), Config{BaseURL: ts.URL, RedirectURL: "http://localhost/cb"})
	assert.ErrorContains(t, err, "no client_id")
}

func TestRegister_RequiresRedirectOrClientCredentials(t *testing.T) {
	_, err := Register(context.Background(), Config{BaseURL: "http://example.com"})
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrRegistrationNotSupported))
}

func TestClientRegistration_SecretExpired(t *testing.T) {
	assert.False(t, (&ClientRegistration{}).SecretExpired())
	assert.False(t, (&ClientRegistration{ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix()}).SecretExpired())
	assert.True(t, (&ClientRegistration{ClientSecretExpiresAt: time.Now().Add(-time.Hour).Unix()}).SecretExpired())
}
