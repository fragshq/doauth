package doauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Metadata contains the authorization server's metadata (RFC 8414 / RFC 9728).
type Metadata struct {
	Issuer               string   `json:"issuer,omitempty"`
	AuthorizationURL     string   `json:"authorization_url,omitempty"`
	TokenURL             string   `json:"token_url,omitempty"`
	JWKSURI              string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint string   `json:"registration_endpoint,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	ResponseTypes        []string `json:"response_types_supported,omitempty"`
	GrantTypes           []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethods []string `json:"code_challenge_methods_supported,omitempty"`

	// Protected Resource Metadata (RFC 9728)
	Resource             string   `json:"resource,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
}

// MarshalBinary encodes the Metadata struct into JSON bytes.
func (m *Metadata) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

// UnmarshalBinary decodes JSON bytes back into the Metadata struct.
func (m *Metadata) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, m)
}

// UnmarshalJSON implements custom decoding to handle standard and aliased endpoint names.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	type Alias Metadata
	aux := &struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		AuthURL       string `json:"authorization_url"`
		TokenEndpoint string `json:"token_endpoint"`
		TokenURL      string `json:"token_url"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	m.AuthorizationURL = aux.AuthEndpoint
	if m.AuthorizationURL == "" {
		m.AuthorizationURL = aux.AuthURL
	}

	m.TokenURL = aux.TokenEndpoint
	if m.TokenURL == "" {
		m.TokenURL = aux.TokenURL
	}

	return nil
}

// GetEndpoints returns the resolved authorization and token URLs.
func (m *Metadata) GetEndpoints() (auth, token string) {
	return m.AuthorizationURL, m.TokenURL
}

// DiscoverMetadata attempts to find OAuth2 metadata for a given base URL.
func DiscoverMetadata(ctx context.Context, baseURL string, client *http.Client, logger *slog.Logger) (*Metadata, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &Authenticator{cfg: Config{BaseURL: baseURL}, client: client, logger: logger}
	return a.greedyDiscover(ctx, baseURL, roleResource, make(map[string]bool))
}

// discoveryRole tells greedyDiscover what kind of URL it is looking at.
type discoveryRole int

const (
	// roleResource is a protected resource (e.g. an MCP server): look for its PRM first.
	roleResource discoveryRole = iota
	// roleAuthServer is an authorization server issuer: look for AS metadata only.
	roleAuthServer
	// roleExact is a URL expected to be the metadata document itself (e.g. a header pointer).
	roleExact
)

// greedyDiscover performs a recursive search for metadata.
// A document without endpoints (e.g. a PRM whose chain cannot be resolved) does not stop the
// search; it is only returned if nothing better is found.
func (a *Authenticator) greedyDiscover(ctx context.Context, baseURL string, role discoveryRole, visited map[string]bool) (*Metadata, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if visited[baseURL] {
		return nil, fmt.Errorf("discovery recursion detected: %s", baseURL)
	}
	visited[baseURL] = true

	var candidates []string
	isWellKnown := strings.Contains(baseURL, "/.well-known/")
	if role != roleExact && !isWellKnown {
		candidates = append(candidates, a.getWellKnownURLs(baseURL, role)...)
	}
	candidates = append(candidates, baseURL)
	if role == roleExact && !isWellKnown {
		candidates = append(candidates, baseURL+PathOpenIDConfig)
	}

	var partial *Metadata
	for _, u := range candidates {
		a.logger.Debug("trying discovery", "url", u)
		m, err := a.fetchMetadata(ctx, u)
		if err != nil {
			continue
		}
		resolved, err := a.resolveMetadataChain(ctx, m, visited)
		if err != nil {
			continue
		}
		if resolved.AuthorizationURL != "" && resolved.TokenURL != "" {
			a.logger.Debug("discovery successful", "url", u)
			return resolved, nil
		}
		a.logger.Debug("metadata found but without endpoints, continuing", "url", u)
		if partial == nil {
			partial = resolved
		}
	}

	if partial != nil {
		return partial, nil
	}
	return nil, fmt.Errorf("no metadata found at %s", baseURL)
}

// getWellKnownURLs generates potential discovery URLs, most authoritative first.
// For a resource: its Protected Resource Metadata (RFC 9728), then AS metadata in case the
// resource is its own authorization server. For an authorization server: RFC 8414 order.
// Path-specific locations always come before host-root ones.
func (a *Authenticator) getWellKnownURLs(baseURL string, role discoveryRole) []string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	host := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")

	var urls []string
	if role == roleResource {
		if path != "" {
			urls = append(urls, host+PathOAuthProtectedRoute+path) // RFC 9728
			urls = append(urls, baseURL+PathOAuthProtectedRoute)   // not standard but often used
		}
		urls = append(urls, host+PathOAuthProtectedRoute) // MCP root fallback
	}

	if path != "" {
		urls = append(urls, host+PathOAuthAuthServer+path) // RFC 8414
		urls = append(urls, host+PathOpenIDConfig+path)    // RFC 8414 §5 OIDC compatibility
		urls = append(urls, baseURL+PathOpenIDConfig)      // OIDC Discovery
		urls = append(urls, baseURL+PathOAuthAuthServer)   // not standard but often used
	}
	urls = append(urls, host+PathOAuthAuthServer)
	urls = append(urls, host+PathOpenIDConfig)
	return urls
}

// fetchMetadata retrieves and decodes metadata from a URL.
func (a *Authenticator) fetchMetadata(ctx context.Context, url string) (*Metadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var m Metadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// resolveMetadataChain follows RFC 9728 pointer chains.
func (a *Authenticator) resolveMetadataChain(ctx context.Context, m *Metadata, visited map[string]bool) (*Metadata, error) {
	if m.AuthorizationURL != "" && m.TokenURL != "" {
		return m, nil
	}

	if len(m.AuthorizationServers) > 0 {
		a.logger.Debug("following authorization_servers chain", "next", m.AuthorizationServers[0])
		next, err := a.greedyDiscover(ctx, m.AuthorizationServers[0], roleAuthServer, visited)
		if err == nil {
			if len(next.ScopesSupported) == 0 {
				next.ScopesSupported = m.ScopesSupported
			}
			return next, nil
		}
	}

	return m, nil
}

// ProbeMetadata checks if a resource is protected and attempts discovery via headers.
func ProbeMetadata(ctx context.Context, baseURL string, client *http.Client, logger *slog.Logger) (*Metadata, bool, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &Authenticator{cfg: Config{BaseURL: baseURL}, client: client, logger: logger}

	a.logger.Debug("probing resource for auth requirements", "url", baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		a.logger.Debug("resource is not protected")
		return nil, false, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		a.logger.Debug("resource returned 401 Unauthorized, checking for discovery pointers")
		discoveryURL := ""
		fallbackRole := roleResource
		if url := resp.Header.Get(HeaderXDiscoveryURL); url != "" {
			discoveryURL = url
		} else if wwwAuth := resp.Header.Get(HeaderWWWAuthenticate); wwwAuth != "" {
			var isIssuer bool
			discoveryURL, isIssuer = parseWWWAuth(wwwAuth)
			if isIssuer {
				fallbackRole = roleAuthServer
			}
		}

		if discoveryURL != "" {
			a.logger.Debug("found discovery pointer in headers", "discovery_url", discoveryURL)
			// The pointer is usually the exact document: fetch it before guessing well-known paths,
			// which could otherwise land on unrelated host-root metadata.
			m, err := a.greedyDiscover(ctx, discoveryURL, roleExact, make(map[string]bool))
			if err != nil || m.AuthorizationURL == "" || m.TokenURL == "" {
				m, err = a.greedyDiscover(ctx, discoveryURL, fallbackRole, make(map[string]bool))
			}
			if err == nil {
				return m, true, nil
			}
		}
		return nil, true, nil
	}

	return nil, false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

// parseWWWAuth extracts discovery URLs from the WWW-Authenticate header.
// It also reports whether the URL is an issuer (an authorization server) rather than resource metadata.
func parseWWWAuth(h string) (string, bool) {
	// Look for resource_metadata="..." or issuer="..."
	prefixes := []string{`resource_metadata="`, `issuer="`}
	for _, p := range prefixes {
		if start := strings.Index(h, p); start != -1 {
			s := h[start+len(p):]
			if end := strings.Index(s, `"`); end != -1 {
				return s[:end], p == `issuer="`
			}
		}
	}
	return "", false
}
