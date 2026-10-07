# doauth

`doauth` is a robust Go library designed to simplify OAuth2 authentication by automating the discovery of authorization server metadata. It is built to handle modern, complex environments where endpoints might not be known upfront, or where resources point to their authorization servers via standard discovery protocols.

## Key Features

- **Greedy Discovery**: Automatically searches for metadata using OIDC (OpenID Connect), RFC 8414 (OAuth 2.0 Authorization Server Metadata), and RFC 9728 (Discovery of Protected Resource Metadata).
- **Resource Probing**: Can probe a protected resource URL to find its authorization server via `WWW-Authenticate` headers or `X-Discovery-URL`.
- **PKCE by Default**: Securely handles Proof Key for Code Exchange (S256) to protect against code injection attacks.
- **Local Flow for CLIs**: Includes a built-in local web server to automatically capture authorization callbacks in CLI applications.
- **Flexible Configuration**: Supports both automatic discovery and manual endpoint overrides.
- **Customizable**: Allows passing a custom `http.Client` for all network operations (discovery, exchange, refresh).
- **Stateless Exchange**: Designed to work across different application instances or process boundaries.

## Installation

```bash
go get github.com/fragshq/doauth
```

## Quick Start (Standard Discovery)

```go
package main

import (
    "context"
    "fmt"
    "github.com/fragshq/doauth"
)

func main() {
    ctx := context.Background()

    // 1. Initialize the Authenticator
    auth, _ := doauth.NewAuthenticator(doauth.Config{
        BaseURL:      "https://api.example.com",
        ClientID:     "your-client-id",
        RedirectURL:  "http://localhost:8080/callback",
    })

    // 2. Discover endpoints (OIDC, RFC 8414, RFC 9728)
    needed, _ := auth.Discover(ctx)
    if !needed {
        fmt.Println("No authentication required for this resource")
        return
    }

    // 3. Generate the Authorization URL (PKCE is enabled by default)
    url, state, verifier, _ := auth.GetAuthURL()
    fmt.Printf("Visit this URL to authorize: %s\n", url)

    // ... after getting the 'code' from your redirect handler ...
    code := "received-auth-code"

    // 4. Exchange the code for a token
    token, _ := auth.Exchange(ctx, code, state, verifier)
    fmt.Printf("Access Token: %s\n", token.AccessToken)
}
```

## Advanced Discovery Logic

`doauth` uses a "greedy" approach to find authorization metadata. When you call `Discover()`, it performs the following steps:

1.  **Probing**: It requests the `BaseURL`. If it returns `401 Unauthorized`, `doauth` follows the `X-Discovery-URL` header or the `resource_metadata` (RFC 9728) / `issuer` parameter of `WWW-Authenticate`, fetching the pointed document directly first. A server's own pointer always wins over guessed locations.
2.  **Standard Well-Known Paths**: Otherwise it checks, most specific first:
    -   Protected Resource Metadata: `/.well-known/oauth-protected-resource` inserted before the path, appended to it, then at the host root.
    -   Authorization Server Metadata, in case the resource is its own authorization server: `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` inserted before the path, appended to it, then at the host root.
3.  **Greedy Fetch**: It attempts to fetch the `BaseURL` directly, as some servers serve metadata at the root of the API path.
4.  **Chain Resolution**: If the discovery points to a "Protected Resource Metadata" (RFC 9728), it follows the chain to the actual Authorization Server, which is looked up in RFC 8414 order. If the chain can't be resolved, the search moves on to the next location.

## Local Flow for CLI Applications

If you are building a CLI tool, you can use the `LocalFlow` helper to automate the browser opening and callback capture:

```go
flow := doauth.NewLocalFlow(doauth.WithPort(8080))

// Open the system browser
_ = flow.OpenBrowser(authURL)

// Block until the code is received at http://localhost:8080/callback
result, _ := flow.WaitForCode(ctx)
token, _ := auth.Exchange(ctx, result.Code, state, verifier)
```

## Client Credentials Flow (Opt-in)

If the server supports the `client_credentials` grant type, you can opt-in to use it. The library allows you to check if the server supports it, retrieve a token directly, and handle automatic refresh if needed:

```go
// 1. Initialize with AllowClientCredentials set to true
auth, _ := doauth.NewAuthenticator(doauth.Config{
    BaseURL:                "https://api.example.com",
    ClientID:               "your-client-id",
    ClientSecret:           "your-client-secret",
    AllowClientCredentials: true,
})

// 2. Discover metadata capabilities
_, _ = auth.Discover(ctx)

// 3. Conditionally use the Client Credentials flow if available
var token *oauth2.Token
var err error
if auth.CanUseClientCredentials() {
    // Dynamic opt-in: obtain token directly without browser interaction
    token, err = auth.ClientCredentialsToken(ctx)
} else {
    // Fall back to the 3-legged authorization code flow
    authURL, state, verifier, _ := auth.GetAuthURL()
    // Open browser, wait for callback code, and exchange
}
```

If the token is expired and has no refresh token (as is typical for client credentials tokens), calling `auth.RefreshToken(ctx, token)` will automatically request a new token via client credentials if the capability is available.

## Manual Configuration

If your environment doesn't support discovery, or you want to bypass it, you can provide endpoints manually:

```go
auth, _ := doauth.NewAuthenticator(doauth.Config{
    ClientID:         "my-client",
    RedirectURL:      "http://localhost/callback",
    AuthorizationURL: "https://auth.example.com/authorize",
    TokenURL:         "https://auth.example.com/token",
})

// Discover() will return immediately without network calls
_, _ = auth.Discover(ctx)
```

## Custom HTTP Client

Use the Options pattern to provide a custom client (e.g., for proxying, custom timeouts, or logging):

```go
myClient := &http.Client{Timeout: 30 * time.Second}
auth, _ := doauth.NewAuthenticator(cfg, doauth.WithHTTPClient(myClient))
```

## PKCE Support

PKCE is enabled by default for all generated URLs. You can toggle it or provide a custom state:

```go
url, state, verifier, _ := auth.GetAuthURL(
    doauth.WithPKCE(true),
    doauth.WithState("custom-secure-state"),
)
```

## RFC Compliance

- **OIDC Discovery**: Fully supported.
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata.
- **RFC 9728**: Discovery of Protected Resource Metadata.
- **RFC 7636**: PKCE (Proof Key for Code Exchange).
- **RFC 6750**: Bearer Token usage via `AuthorizeRequest`.
- **RFC 6749 Section 4.4**: Client Credentials Grant.

## License

MIT
