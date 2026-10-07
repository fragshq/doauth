package doauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestDiscovery_Standard(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Since we use custom UnmarshalJSON, we need to simulate how it's sent
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"http://example.com","authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	auth, err := NewAuthenticator(Config{BaseURL: ts.URL, ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)

	authURLStr, _, _, _ := auth.GetAuthURL()
	assert.Contains(t, authURLStr, "resource="+url.QueryEscape(ts.URL))
	assert.Equal(t, "http://example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestDiscovery_Probe_MCP(t *testing.T) {
	muxAS := http.NewServeMux()
	muxAS.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
	})
	tsAS := httptest.NewServer(muxAS)
	defer tsAS.Close()

	muxResMeta := http.NewServeMux()
	muxResMeta.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		resMeta := Metadata{
			Resource:             "http://example.com/resource",
			AuthorizationServers: []string{tsAS.URL},
		}
		json.NewEncoder(w).Encode(resMeta)
	})
	tsResMeta := httptest.NewServer(muxResMeta)
	defer tsResMeta.Close()

	muxRes := http.NewServeMux()
	muxRes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="example", resource_metadata="`+tsResMeta.URL+`/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	tsRes := httptest.NewServer(muxRes)
	defer tsRes.Close()

	auth, err := NewAuthenticator(Config{BaseURL: tsRes.URL, ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)

	authURLStr, _, _, _ := auth.GetAuthURL()
	assert.Contains(t, authURLStr, "resource="+url.QueryEscape(tsRes.URL))
	assert.Equal(t, "http://example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestDiscovery_Probe_PreferredOverWellKnown(t *testing.T) {
	muxAS := http.NewServeMux()
	muxAS.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"authorization_endpoint":"http://right.example.com/auth","token_endpoint":"http://right.example.com/token"}`))
	})
	tsAS := httptest.NewServer(muxAS)
	defer tsAS.Close()

	// Shared host: the root advertises some other AS, the tenant's MCP resource points elsewhere.
	var tsRes *httptest.Server
	muxRes := http.NewServeMux()
	muxRes.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"authorization_endpoint":"http://wrong.example.com/auth","token_endpoint":"http://wrong.example.com/token"}`))
	})
	muxRes.HandleFunc("/prm/tenantA", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Metadata{Resource: tsRes.URL + "/tenantA/mcp", AuthorizationServers: []string{tsAS.URL}})
	})
	muxRes.HandleFunc("/tenantA/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+tsRes.URL+`/prm/tenantA"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	tsRes = httptest.NewServer(muxRes)
	defer tsRes.Close()

	auth, err := NewAuthenticator(Config{BaseURL: tsRes.URL + "/tenantA/mcp", ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)
	assert.Equal(t, "http://right.example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestGetWellKnownURLs_Order(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, []string{
		"https://h/.well-known/oauth-protected-resource/mcp",
		"https://h/mcp/.well-known/oauth-protected-resource",
		"https://h/.well-known/oauth-protected-resource",
		"https://h/.well-known/oauth-authorization-server/mcp",
		"https://h/.well-known/openid-configuration/mcp",
		"https://h/mcp/.well-known/openid-configuration",
		"https://h/mcp/.well-known/oauth-authorization-server",
		"https://h/.well-known/oauth-authorization-server",
		"https://h/.well-known/openid-configuration",
	}, a.getWellKnownURLs("https://h/mcp", roleResource))
	assert.Equal(t, []string{
		"https://h/.well-known/oauth-protected-resource",
		"https://h/.well-known/oauth-authorization-server",
		"https://h/.well-known/openid-configuration",
	}, a.getWellKnownURLs("https://h", roleResource))
	assert.Equal(t, []string{
		"https://h/.well-known/oauth-authorization-server",
		"https://h/.well-known/openid-configuration",
	}, a.getWellKnownURLs("https://h", roleAuthServer))
}

func TestDiscovery_PRMPreferredOverASMetadata(t *testing.T) {
	muxAS := http.NewServeMux()
	muxAS.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"authorization_endpoint":"http://right.example.com/auth","token_endpoint":"http://right.example.com/token"}`))
	})
	tsAS := httptest.NewServer(muxAS)
	defer tsAS.Close()

	var tsRes *httptest.Server
	muxRes := http.NewServeMux()
	muxRes.HandleFunc("/.well-known/openid-configuration/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"authorization_endpoint":"http://wrong.example.com/auth","token_endpoint":"http://wrong.example.com/token"}`))
	})
	muxRes.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Metadata{Resource: tsRes.URL + "/mcp", AuthorizationServers: []string{tsAS.URL}})
	})
	tsRes = httptest.NewServer(muxRes)
	defer tsRes.Close()

	auth, err := NewAuthenticator(Config{BaseURL: tsRes.URL + "/mcp", ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	_, err = auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "http://right.example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestDiscovery_ContinuesPastUnresolvablePRM(t *testing.T) {
	var tsRes *httptest.Server
	muxRes := http.NewServeMux()
	muxRes.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Metadata{Resource: tsRes.URL + "/mcp", AuthorizationServers: []string{"http://127.0.0.1:1/unreachable"}})
	})
	muxRes.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
	})
	tsRes = httptest.NewServer(muxRes)
	defer tsRes.Close()

	auth, err := NewAuthenticator(Config{BaseURL: tsRes.URL + "/mcp", ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	_, err = auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestDiscovery_Probe_401(t *testing.T) {
	muxDisc := http.NewServeMux()
	muxDisc.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
	})
	tsDisc := httptest.NewServer(muxDisc)
	defer tsDisc.Close()

	muxRes := http.NewServeMux()
	muxRes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="example", issuer="`+tsDisc.URL+`"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	tsRes := httptest.NewServer(muxRes)
	defer tsRes.Close()

	auth, err := NewAuthenticator(Config{BaseURL: tsRes.URL, ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)

	authURLStr, _, _, _ := auth.GetAuthURL()
	assert.Contains(t, authURLStr, "resource="+url.QueryEscape(tsRes.URL))
	assert.Equal(t, "http://example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestDiscovery_Probe_RequiredButNoInfo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	auth, err := NewAuthenticator(Config{BaseURL: ts.URL, ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.Error(t, err)
	assert.True(t, required)
	assert.Contains(t, err.Error(), "authentication required but endpoints not found")
}

func TestDiscovery_DirectMetadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	auth, err := NewAuthenticator(Config{BaseURL: ts.URL, ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)
	assert.Equal(t, "http://example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestDiscovery_ManualEndpoints(t *testing.T) {
	auth, err := NewAuthenticator(Config{
		ClientID:         "id",
		RedirectURL:      "url",
		AuthorizationURL: "https://manual.example.com/auth",
		TokenURL:         "https://manual.example.com/token",
	})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)
	assert.Equal(t, "https://manual.example.com/auth", auth.GetMetadata().AuthorizationURL)
}

func TestExchange_CrossInstanceManual(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") == "secret-code" && r.FormValue("code_verifier") == "my-verifier" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token": "success-token", "token_type": "Bearer"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer ts.Close()

	authA, err := NewAuthenticator(Config{
		ClientID:         "client-id",
		RedirectURL:      "http://localhost/callback",
		AuthorizationURL: "https://example.com/auth",
		TokenURL:         ts.URL,
	})
	require.NoError(t, err)

	_, _, verifier, err := authA.GetAuthURL(WithPKCE(true))
	require.NoError(t, err)
	verifier = "my-verifier"

	authB, err := NewAuthenticator(Config{
		ClientID:         "client-id",
		RedirectURL:      "http://localhost/callback",
		AuthorizationURL: "https://example.com/auth",
		TokenURL:         ts.URL,
	})
	require.NoError(t, err)

	token, err := authB.Exchange(context.Background(), "secret-code", "ignored-state", verifier)
	assert.NoError(t, err)
	assert.Equal(t, "success-token", token.AccessToken)
}

func TestDiscovery_Probe_NoAuth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	auth, err := NewAuthenticator(Config{BaseURL: ts.URL, ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.False(t, required)
}

func TestAuthenticator_GetAuthURL_PKCE(t *testing.T) {
	cfg := Config{
		ClientID:         "client-id",
		RedirectURL:      "http://localhost/callback",
		AuthorizationURL: "http://example.com/auth",
		TokenURL:         "http://example.com/token",
	}

	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)

	required, err := auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.True(t, required)

	customState := "my-custom-state"
	authURLStr, state, verifier, err := auth.GetAuthURL(WithState(customState), WithPKCE(true))
	assert.NoError(t, err)
	assert.Equal(t, customState, state)
	assert.NotEmpty(t, verifier)

	u, err := url.Parse(authURLStr)
	require.NoError(t, err)

	q := u.Query()
	assert.Equal(t, customState, q.Get("state"))
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
}

func TestAuthenticator_AutoScopes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token","scopes_supported":["openid","profile","email"]}`))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := Config{
		BaseURL:     ts.URL,
		ClientID:    "client-id",
		RedirectURL: "http://localhost/callback",
	}

	auth, err := NewAuthenticator(cfg)
	assert.NoError(t, err)

	_, err = auth.Discover(context.Background())
	assert.NoError(t, err)

	authURLStr, _, _, _ := auth.GetAuthURL()
	u, _ := url.Parse(authURLStr)
	scope := u.Query().Get("scope")

	assert.Equal(t, "openid profile email", scope)
}

// newScopeChallengeServer serves a resource whose 401 challenge asks for "files:read", backed by
// an AS that supports more scopes.
func newScopeChallengeServer(t *testing.T) *httptest.Server {
	var ts *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token","scopes_supported":["files:read","files:write","admin"]}`))
	})
	mux.HandleFunc("/prm", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Metadata{Resource: ts.URL + "/mcp", AuthorizationServers: []string{ts.URL}})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+ts.URL+`/prm", scope="files:read"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func scopeFromAuthURL(t *testing.T, auth *Authenticator) string {
	authURLStr, _, _, err := auth.GetAuthURL()
	require.NoError(t, err)
	u, err := url.Parse(authURLStr)
	require.NoError(t, err)
	return u.Query().Get("scope")
}

func TestAuthenticator_ChallengeScopes(t *testing.T) {
	ts := newScopeChallengeServer(t)

	auth, err := NewAuthenticator(Config{BaseURL: ts.URL + "/mcp", ClientID: "id", RedirectURL: "url"})
	require.NoError(t, err)

	_, err = auth.Discover(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"files:read"}, auth.GetMetadata().ChallengeScopes)
	assert.Equal(t, "files:read", scopeFromAuthURL(t, auth))
}

func TestAuthenticator_ConfigScopesOverrideChallenge(t *testing.T) {
	ts := newScopeChallengeServer(t)

	auth, err := NewAuthenticator(Config{BaseURL: ts.URL + "/mcp", ClientID: "id", RedirectURL: "url", Scopes: []string{"admin"}})
	require.NoError(t, err)

	_, err = auth.Discover(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "admin", scopeFromAuthURL(t, auth))
}

func TestAuthenticator_Exchange(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		err := r.ParseForm()
		assert.NoError(t, err)

		assert.Equal(t, "valid-code", r.FormValue("code"))
		assert.Equal(t, "valid-verifier", r.FormValue("code_verifier"))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "token-123", "token_type": "Bearer"}`))
	}))
	defer ts.Close()

	cfg := Config{
		ClientID:         "client-id",
		RedirectURL:      "http://localhost/callback",
		AuthorizationURL: "http://example.com/auth",
		TokenURL:         ts.URL,
	}

	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)

	token, err := auth.Exchange(context.Background(), "valid-code", "state", "valid-verifier")
	assert.NoError(t, err)
	assert.Equal(t, "token-123", token.AccessToken)
}

func TestAuthorizeRequest(t *testing.T) {
	cfg := Config{
		ClientID:         "id",
		RedirectURL:      "url",
		AuthorizationURL: "a",
		TokenURL:         "t",
	}
	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)

	token := &oauth2.Token{AccessToken: "secret-token"}
	req, _ := http.NewRequest(http.MethodGet, "http://api.example.com", nil)

	auth.AuthorizeRequest(token, req)

	assert.Equal(t, "Bearer secret-token", req.Header.Get("Authorization"))
}

func TestAuthenticator_WithLogger(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Custom logger that tracks entries
	type trackingHandler struct {
		slog.Handler
		messages []string
	}
	th := &trackingHandler{
		Handler: slog.Default().Handler(),
	}
	th.Handler = th // This is a bit recursive, better just implement Handle

	logger := slog.New(roundTripperFunc2(func(ctx context.Context, record slog.Record) error {
		th.messages = append(th.messages, record.Message)
		return nil
	}))

	auth, err := NewAuthenticator(Config{
		BaseURL:     ts.URL,
		ClientID:    "id",
		RedirectURL: "url",
	}, WithLogger(logger))
	require.NoError(t, err)

	_, err = auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.NotEmpty(t, th.messages)
	assert.Contains(t, th.messages, "starting discovery")
}

type roundTripperFunc2 func(context.Context, slog.Record) error

func (f roundTripperFunc2) Handle(ctx context.Context, record slog.Record) error {
	return f(ctx, record)
}
func (f roundTripperFunc2) Enabled(context.Context, slog.Level) bool { return true }
func (f roundTripperFunc2) WithAttrs(attrs []slog.Attr) slog.Handler { return f }
func (f roundTripperFunc2) WithGroup(name string) slog.Handler       { return f }

func TestAuthenticator_WithHTTPClient(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_endpoint":"http://example.com/auth","token_endpoint":"http://example.com/token"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Custom client that tracks requests
	type trackingClient struct {
		*http.Client
		requestedURLs []string
	}
	tc := &trackingClient{
		Client: http.DefaultClient,
	}

	// We wrap the Transport to track
	originalTransport := http.DefaultTransport.(*http.Transport).Clone()
	tc.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		tc.requestedURLs = append(tc.requestedURLs, req.URL.String())
		return originalTransport.RoundTrip(req)
	})

	auth, err := NewAuthenticator(Config{
		BaseURL:     ts.URL,
		ClientID:    "id",
		RedirectURL: "url",
	}, WithHTTPClient(tc.Client))
	require.NoError(t, err)

	_, err = auth.Discover(context.Background())
	assert.NoError(t, err)
	assert.NotEmpty(t, tc.requestedURLs)
	assert.Contains(t, tc.requestedURLs[0], ts.URL)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAuthenticator_RefreshToken(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "new-token", "token_type": "Bearer"}`))
	}))
	defer ts.Close()

	cfg := Config{
		ClientID:         "id",
		RedirectURL:      "url",
		AuthorizationURL: "a",
		TokenURL:         ts.URL,
	}
	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)

	oldToken := &oauth2.Token{
		AccessToken:  "old-token",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-time.Hour),
	}

	newToken, err := auth.RefreshToken(context.Background(), oldToken)
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "new-token", newToken.AccessToken)
}

func TestAuthenticator_CanUseClientCredentials(t *testing.T) {
	// 1. Opt-in false
	auth, err := NewAuthenticator(Config{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
	})
	require.NoError(t, err)
	assert.False(t, auth.CanUseClientCredentials())

	// 2. Opt-in true, but no ClientSecret
	auth, err = NewAuthenticator(Config{
		ClientID:               "client-id",
		RedirectURL:            "http://localhost/callback",
		AllowClientCredentials: true,
	})
	require.NoError(t, err)
	assert.False(t, auth.CanUseClientCredentials())

	// 3. Opt-in true, ClientSecret set, but metadata nil
	auth, err = NewAuthenticator(Config{
		ClientID:               "client-id",
		ClientSecret:           "secret",
		RedirectURL:            "http://localhost/callback",
		AllowClientCredentials: true,
	})
	require.NoError(t, err)
	assert.False(t, auth.CanUseClientCredentials())

	// 4. Opt-in true, ClientSecret set, metadata has client_credentials
	auth.metadata = &Metadata{
		GrantTypes: []string{"authorization_code", "client_credentials"},
	}
	assert.True(t, auth.CanUseClientCredentials())

	// 5. Opt-in true, ClientSecret set, metadata does NOT have client_credentials
	auth.metadata = &Metadata{
		GrantTypes: []string{"authorization_code"},
	}
	assert.False(t, auth.CanUseClientCredentials())

	// 6. Opt-in true, ClientSecret set, manual endpoints configured (empty metadata GrantTypes)
	authManual, err := NewAuthenticator(Config{
		ClientID:               "client-id",
		ClientSecret:           "secret",
		AllowClientCredentials: true,
		AuthorizationURL:       "https://example.com/auth",
		TokenURL:               "https://example.com/token",
	})
	require.NoError(t, err)
	// NewAuthenticator sets metadata automatically for manual endpoints
	assert.True(t, authManual.CanUseClientCredentials())
}

func TestAuthenticator_ClientCredentialsToken_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		// oauth2 client credentials flow standard client authentication
		username, password, ok := r.BasicAuth()
		if ok {
			assert.Equal(t, "client-id", username)
			assert.Equal(t, "secret", password)
		} else {
			assert.Equal(t, "client-id", r.FormValue("client_id"))
			assert.Equal(t, "secret", r.FormValue("client_secret"))
		}

		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "cc-token-999", "token_type": "Bearer", "expires_in": 3600}`))
	}))
	defer ts.Close()

	auth, err := NewAuthenticator(Config{
		ClientID:               "client-id",
		ClientSecret:           "secret",
		AllowClientCredentials: true,
		TokenURL:               ts.URL,
		AuthorizationURL:       "http://unused",
	})
	require.NoError(t, err)

	token, err := auth.ClientCredentialsToken(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "cc-token-999", token.AccessToken)
}

func TestRefreshToken_ClientCredentialsFallback(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "cc-token-refreshed", "token_type": "Bearer", "expires_in": 3600}`))
	}))
	defer ts.Close()

	auth, err := NewAuthenticator(Config{
		ClientID:               "client-id",
		ClientSecret:           "secret",
		AllowClientCredentials: true,
		TokenURL:               ts.URL,
		AuthorizationURL:       "http://unused",
	})
	require.NoError(t, err)

	expiredToken := &oauth2.Token{
		AccessToken: "old-cc-token",
		Expiry:      time.Now().Add(-time.Hour),
	}

	newToken, err := auth.RefreshToken(context.Background(), expiredToken)
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "cc-token-refreshed", newToken.AccessToken)
}
