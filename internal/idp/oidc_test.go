package idp

import (
	"sort"
	"testing"
)

// Role extraction is the one thing a generic OIDC deployment must configure, and the shapes
// differ per provider. These tests pin every shape the verifier claims to support, because
// getting it wrong yields an empty role list — which means no rule matches and every
// connection is refused.

func TestRolesFromClaimShapes(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		path string
		want []string
	}{
		{
			name: "flat array (Keycloak realm_access, Entra roles)",
			raw: map[string]any{
				"realm_access": map[string]any{
					"roles": []any{"admin", "user"},
				},
			},
			path: "realm_access.roles",
			want: []string{"admin", "user"},
		},
		{
			name: "top-level array",
			raw:  map[string]any{"roles": []any{"a", "b"}},
			path: "roles",
			want: []string{"a", "b"},
		},
		{
			name: "space-separated string",
			raw:  map[string]any{"scope": "read write"},
			path: "scope",
			want: []string{"read", "write"},
		},
		{
			name: "comma-separated string",
			raw:  map[string]any{"roles": "a,b,c"},
			path: "roles",
			want: []string{"a", "b", "c"},
		},
		{
			name: "object keyed by role name (Zitadel-style)",
			raw: map[string]any{
				"urn:custom:roles": map[string]any{
					"admin": map[string]any{"org": "example"},
					"user":  map[string]any{"org": "example"},
				},
			},
			path: "urn:custom:roles",
			want: []string{"admin", "user"},
		},
		{
			name: "missing claim yields no roles",
			raw:  map[string]any{"other": "value"},
			path: "roles",
			want: nil,
		},
		{
			name: "unsupported shape yields no roles",
			raw:  map[string]any{"roles": 42.0},
			path: "roles",
			want: nil,
		},
		{
			name: "path into a non-object yields no roles",
			raw:  map[string]any{"roles": "flat"},
			path: "roles.nested",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rolesFromClaim(&Claims{Raw: tc.raw}, tc.path)
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("expected %v, got %v", want, got)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("expected %v, got %v", want, got)
				}
			}
		})
	}
}

// TestClaimStringScalars covers the placeholder value reader. Only scalars are usable, because
// a placeholder becomes a single NATS subject token.
func TestClaimStringScalars(t *testing.T) {
	claims := &Claims{Raw: map[string]any{
		"tenant":   "acme",
		"empty":    "",
		"count":    42.0,
		"fraction": 1.5,
		"enabled":  true,
		"nested":   map[string]any{"region": "eu"},
		"list":     []any{"a"},
		"object":   map[string]any{"k": "v"},
	}}

	tests := []struct {
		path   string
		want   string
		wantOk bool
	}{
		{"tenant", "acme", true},
		{"nested.region", "eu", true},
		// An integer arriving as a JSON number is common for tenant/org ids.
		{"count", "42", true},
		{"fraction", "1.5", true},
		{"enabled", "true", true},
		// An empty string is not a usable subject token.
		{"empty", "", false},
		{"missing", "", false},
		// Composites cannot be subject tokens.
		{"list", "", false},
		{"object", "", false},
	}

	for _, tc := range tests {
		got, ok := claims.ClaimString(tc.path)
		if ok != tc.wantOk || got != tc.want {
			t.Errorf("ClaimString(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.want, tc.wantOk)
		}
	}
}

// TestNewOIDCRequiresRolesClaim pins the deliberate refusal to default the roles claim.
func TestNewOIDCRequiresRolesClaim(t *testing.T) {
	if _, err := NewOIDC(t.Context(), "https://id.example.test", ""); err == nil {
		t.Fatal("an empty roles claim should be refused rather than defaulted")
	}
}

// TestMockExtraClaims covers the mock's optional claims field, which is what lets the
// configurable-grammar path be exercised without a real IdP.
func TestMockExtraClaims(t *testing.T) {
	claims, err := NewMock().VerifyToken(t.Context(), "mock:u-1:ana:role-a,role-b:tenant_id=acme,region=eu")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.Subject != "u-1" || claims.Username != "ana" {
		t.Fatalf("unexpected identity: %+v", claims)
	}
	if len(claims.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %v", claims.Roles)
	}
	if tenant, ok := claims.ClaimString("tenant_id"); !ok || tenant != "acme" {
		t.Fatalf("expected tenant acme, got %q (ok=%v)", tenant, ok)
	}
	if region, ok := claims.ClaimString("region"); !ok || region != "eu" {
		t.Fatalf("expected region eu, got %q (ok=%v)", region, ok)
	}
}

// TestMockBackwardCompatible pins that three-field tokens — every one in the README and the
// scripts — keep working after the format gained a fourth field.
func TestMockBackwardCompatible(t *testing.T) {
	claims, err := NewMock().VerifyToken(t.Context(), "mock:zit-ana:ana@example.com:poc-user")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "zit-ana" || claims.Username != "ana@example.com" {
		t.Fatalf("unexpected identity: %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "poc-user" {
		t.Fatalf("expected [poc-user], got %v", claims.Roles)
	}
}
