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

	// ChallengeScopes are the scopes the resource asked for in its WWW-Authenticate challenge.
	// Not part of any metadata document; set by ProbeMetadata.
	ChallengeScopes []string `json:"challenge_scopes,omitempty"`
	// ResourceScopes are the scopes_supported of the Protected Resource Metadata that led to
	// this authorization server. Not part of any metadata document; set when following the chain.
	ResourceScopes []string `json:"resource_scopes,omitempty"`
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

// DefaultScopes returns the scopes to request when none are configured: those the resource's
// challenge asked for, otherwise those its Protected Resource Metadata lists. The AS's
// scopes_supported is never used: it describes the whole server, not this resource. A nil
// result means no scope should be requested, letting the AS apply its default (RFC 6749 §3.3).
func (m *Metadata) DefaultScopes() []string {
	if m == nil {
		return nil
	}
	if len(m.ChallengeScopes) > 0 {
		return m.ChallengeScopes
	}
	if len(m.ResourceScopes) > 0 {
		return m.ResourceScopes
	}
	return nil
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
			// Keep the resource's scopes apart from the AS's: they describe what this resource needs.
			next.ResourceScopes = m.ScopesSupported
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
		var challenge wwwAuthChallenge
		if wwwAuth := resp.Header.Get(HeaderWWWAuthenticate); wwwAuth != "" {
			challenge = parseWWWAuth(wwwAuth)
		}

		discoveryURL := resp.Header.Get(HeaderXDiscoveryURL)
		fallbackRole := roleResource
		if discoveryURL == "" {
			if challenge.ResourceMetadata != "" {
				discoveryURL = challenge.ResourceMetadata
			} else if challenge.Issuer != "" {
				discoveryURL = challenge.Issuer
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
				if len(challenge.Scopes) > 0 {
					a.logger.Debug("resource challenge requires scopes", "scopes", challenge.Scopes)
					m.ChallengeScopes = challenge.Scopes
				}
				return m, true, nil
			}
		}
		return nil, true, nil
	}

	return nil, false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

// wwwAuthChallenge holds the WWW-Authenticate parameters relevant to discovery.
type wwwAuthChallenge struct {
	// ResourceMetadata points at the Protected Resource Metadata document (RFC 9728).
	ResourceMetadata string
	// Issuer points at an authorization server (non-standard but seen in the wild).
	Issuer string
	// Scopes are the scopes the resource requires (RFC 6750 §3).
	Scopes []string
}

// parseWWWAuth extracts discovery pointers and required scopes from the WWW-Authenticate header.
// Parameters are read from the Bearer challenge if there is one, otherwise from the first challenge.
func parseWWWAuth(h string) wwwAuthChallenge {
	challenges := parseAuthChallenges(h)
	if len(challenges) == 0 {
		return wwwAuthChallenge{}
	}
	params := challenges[0].params
	for _, c := range challenges {
		if strings.EqualFold(c.scheme, "Bearer") {
			params = c.params
			break
		}
	}
	c := wwwAuthChallenge{
		ResourceMetadata: params["resource_metadata"],
		Issuer:           params["issuer"],
	}
	if scopes := strings.Fields(params["scope"]); len(scopes) > 0 {
		c.Scopes = scopes
	}
	return c
}

// authChallenge is a single challenge of a WWW-Authenticate header.
type authChallenge struct {
	scheme string
	params map[string]string
}

// parseAuthChallenges splits a WWW-Authenticate header into challenges (RFC 9110 §11.6.1).
// Parameter names are lowercased; the first occurrence of a parameter wins. It is lenient:
// parameters without a preceding scheme are accepted, and unquoted values run until the next
// comma or whitespace so that bare URLs survive.
func parseAuthChallenges(h string) []authChallenge {
	var out []authChallenge
	i := 0
	for {
		for i < len(h) && (h[i] == ',' || isAuthSpace(h[i])) {
			i++
		}
		if i >= len(h) {
			return out
		}

		name := readAuthToken(h, &i)
		if name == "" {
			i++ // unexpected character, skip it
			continue
		}

		j := i
		for j < len(h) && isAuthSpace(h[j]) {
			j++
		}
		if j >= len(h) || h[j] != '=' {
			out = append(out, authChallenge{scheme: name, params: map[string]string{}})
			continue
		}

		// auth-param: name=token or name="quoted string"
		i = j + 1
		for i < len(h) && isAuthSpace(h[i]) {
			i++
		}
		var value string
		if i < len(h) && h[i] == '"' {
			value = readAuthQuoted(h, &i)
		} else {
			start := i
			for i < len(h) && h[i] != ',' && !isAuthSpace(h[i]) {
				i++
			}
			value = h[start:i]
		}

		if len(out) == 0 {
			out = append(out, authChallenge{params: map[string]string{}})
		}
		params := out[len(out)-1].params
		key := strings.ToLower(name)
		if _, ok := params[key]; !ok {
			params[key] = value
		}
	}
}

// readAuthToken reads an RFC 9110 token starting at *i.
func readAuthToken(h string, i *int) string {
	start := *i
	for *i < len(h) && isAuthTokenChar(h[*i]) {
		*i++
	}
	return h[start:*i]
}

// readAuthQuoted reads a quoted string starting at the opening quote at *i, unescaping quoted pairs.
// An unterminated string runs to the end of the header.
func readAuthQuoted(h string, i *int) string {
	var b strings.Builder
	*i++ // opening quote
	for *i < len(h) {
		c := h[*i]
		switch {
		case c == '\\' && *i+1 < len(h):
			b.WriteByte(h[*i+1])
			*i += 2
		case c == '"':
			*i++
			return b.String()
		default:
			b.WriteByte(c)
			*i++
		}
	}
	return b.String()
}

func isAuthSpace(c byte) bool {
	return c == ' ' || c == '\t'
}

func isAuthTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) != -1
}
