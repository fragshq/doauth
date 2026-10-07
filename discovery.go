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
	return a.greedyDiscover(ctx, baseURL, true, make(map[string]bool))
}

// greedyDiscover performs a recursive search for metadata.
func (a *Authenticator) greedyDiscover(ctx context.Context, baseURL string, tryWellKnown bool, visited map[string]bool) (*Metadata, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if visited[baseURL] {
		return nil, fmt.Errorf("discovery recursion detected: %s", baseURL)
	}
	visited[baseURL] = true

	// 1. Try well-known paths
	if tryWellKnown && !strings.Contains(baseURL, "/.well-known/") {
		for _, u := range a.getWellKnownURLs(baseURL) {
			a.logger.Debug("trying well-known discovery", "url", u)
			if m, err := a.fetchMetadata(ctx, u); err == nil {
				a.logger.Debug("well-known discovery successful", "url", u)
				return a.resolveMetadataChain(ctx, m, visited)
			}
		}
	}

	// 2. Try the URL directly
	a.logger.Debug("trying direct discovery", "url", baseURL)
	if m, err := a.fetchMetadata(ctx, baseURL); err == nil {
		a.logger.Debug("direct discovery successful", "url", baseURL)
		return a.resolveMetadataChain(ctx, m, visited)
	}

	// 3. Last resort fallback
	if !strings.Contains(baseURL, "/.well-known/") {
		u := baseURL + PathOpenIDConfig
		a.logger.Debug("trying fallback discovery", "url", u)
		if m, err := a.fetchMetadata(ctx, u); err == nil {
			a.logger.Debug("fallback discovery successful", "url", u)
			return a.resolveMetadataChain(ctx, m, visited)
		}
	}

	return nil, fmt.Errorf("no metadata found at %s", baseURL)
}

// getWellKnownURLs generates potential discovery URLs based on standard specifications.
func (a *Authenticator) getWellKnownURLs(baseURL string) []string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	host := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")

	var urls []string
	if path != "" {
		// RFC 8414/9728 style
		urls = append(urls, host+PathOpenIDConfig+path)
		urls = append(urls, host+PathOAuthAuthServer+path)
		urls = append(urls, host+PathOAuthProtectedRoute+path)
	}

	// Standard relative paths
	urls = append(urls, baseURL+PathOpenIDConfig)
	urls = append(urls, baseURL+PathOAuthAuthServer)
	urls = append(urls, baseURL+PathOAuthProtectedRoute)

	// Not standard but often used
	urls = append(urls, host+PathOpenIDConfig)
	urls = append(urls, host+PathOAuthAuthServer)
	urls = append(urls, host+PathOAuthProtectedRoute)
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
		next, err := a.greedyDiscover(ctx, m.AuthorizationServers[0], true, visited)
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
		if url := resp.Header.Get(HeaderXDiscoveryURL); url != "" {
			discoveryURL = url
		} else if wwwAuth := resp.Header.Get(HeaderWWWAuthenticate); wwwAuth != "" {
			discoveryURL = parseWWWAuth(wwwAuth)
		}

		if discoveryURL != "" {
			a.logger.Debug("found discovery pointer in headers", "discovery_url", discoveryURL)
			// The pointer is usually the exact document: fetch it before guessing well-known paths,
			// which could otherwise land on unrelated host-root metadata.
			m, err := a.greedyDiscover(ctx, discoveryURL, false, make(map[string]bool))
			if err != nil {
				m, err = a.greedyDiscover(ctx, discoveryURL, true, make(map[string]bool))
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
func parseWWWAuth(h string) string {
	// Look for resource_metadata="..." or issuer="..."
	prefixes := []string{`resource_metadata="`, `issuer="`}
	for _, p := range prefixes {
		if start := strings.Index(h, p); start != -1 {
			s := h[start+len(p):]
			if end := strings.Index(s, `"`); end != -1 {
				return s[:end]
			}
		}
	}
	return ""
}
