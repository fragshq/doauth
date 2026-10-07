package doauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWWWAuth(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   wwwAuthChallenge
	}{
		{
			name:   "resource metadata",
			header: `Bearer realm="example", resource_metadata="https://h/.well-known/oauth-protected-resource"`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/.well-known/oauth-protected-resource"},
		},
		{
			name:   "issuer",
			header: `Bearer realm="example", issuer="https://as.example.com"`,
			want:   wwwAuthChallenge{Issuer: "https://as.example.com"},
		},
		{
			name:   "scopes",
			header: `Bearer resource_metadata="https://h/prm", scope="files:read  files:write"`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/prm", Scopes: []string{"files:read", "files:write"}},
		},
		{
			name:   "unquoted values",
			header: `Bearer scope=read, resource_metadata=https://h/prm`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/prm", Scopes: []string{"read"}},
		},
		{
			name:   "case insensitive names",
			header: `bearer Resource_Metadata="https://h/prm", SCOPE="read"`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/prm", Scopes: []string{"read"}},
		},
		{
			name:   "escaped quotes",
			header: `Bearer error_description="bad \"token\"", scope="read"`,
			want:   wwwAuthChallenge{Scopes: []string{"read"}},
		},
		{
			name:   "parameter names inside values are not matched",
			header: `Bearer error_description="see issuer=\"https://evil\"", resource_metadata="https://h/prm"`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/prm"},
		},
		{
			name:   "bearer challenge preferred",
			header: `Basic realm="x", scope="basic", Bearer scope="read write", resource_metadata="https://h/prm"`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/prm", Scopes: []string{"read", "write"}},
		},
		{
			name:   "token68 challenge before bearer",
			header: `Negotiate dG9rZW4=, Bearer scope="read"`,
			want:   wwwAuthChallenge{Scopes: []string{"read"}},
		},
		{
			name:   "params without scheme",
			header: `resource_metadata="https://h/prm"`,
			want:   wwwAuthChallenge{ResourceMetadata: "https://h/prm"},
		},
		{
			name:   "unterminated quote",
			header: `Bearer scope="read write`,
			want:   wwwAuthChallenge{Scopes: []string{"read", "write"}},
		},
		{
			name:   "no params",
			header: `Bearer`,
			want:   wwwAuthChallenge{},
		},
		{
			name:   "empty",
			header: ``,
			want:   wwwAuthChallenge{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseWWWAuth(tt.header))
		})
	}
}
