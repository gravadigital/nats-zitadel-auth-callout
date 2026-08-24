package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// OIDC verifies access tokens against any standards-compliant OIDC provider.
//
// It exists so the service is not tied to one identity provider. Everything it does is in the
// OIDC/JWT standards — discovery, JWKS, signature, issuer, expiry — with ONE thing left to
// configuration: where the roles live. There is no cross-provider convention for that claim
// (Keycloak nests them under `realm_access.roles`, Auth0 and Okta usually use a namespaced
// claim, Entra uses `roles`), so it is declared rather than guessed.
//
// Zitadel has its own type in this package because its roles claim is not just a path but a
// SHAPE — a nested object keyed by role name — and because it supports narrowing by project.
type OIDC struct {
	issuer   string
	audience string
	// rolesClaim is the dot-separated path the roles are read from.
	rolesClaim string
	// usernameClaim is the claim carrying the human-readable name.
	usernameClaim string
	// enrich says how much to ask userinfo for when the token does not carry it. It defaults to
	// EnrichNone here: a generic provider is not known to withhold anything, so nothing is
	// requested unless the deployment asks.
	enrich EnrichMode
	// userinfo reads the discovered userinfo endpoint, with a per-subject cache.
	userinfo *userinfoFetcher

	cache      *jwk.Cache
	jwksURL    string
	httpClient *http.Client

	now func() time.Time

	mu          sync.Mutex
	lastRefetch time.Time
}

// OIDCOption configures an OIDC verifier.
type OIDCOption func(*OIDC)

// WithOIDCAudience additionally requires the token's `aud` to contain the given value.
//
// Worth setting: without it any token the provider issued for ANY of its clients verifies
// here, which is rarely the intent.
func WithOIDCAudience(audience string) OIDCOption {
	return func(o *OIDC) { o.audience = audience }
}

// WithOIDCUsernameClaim sets the claim the human-readable name is read from.
func WithOIDCUsernameClaim(claim string) OIDCOption {
	return func(o *OIDC) {
		if claim != "" {
			o.usernameClaim = claim
		}
	}
}

// WithOIDCEnrichment selects how much userinfo is consulted for what the token does not carry.
//
// It exists because the problem is not Zitadel-specific: an access token is not an ID token, and
// plenty of providers keep `name` and `email` out of it. A deployment publishing authentication
// events turns this on; one that does not, pays nothing.
func WithOIDCEnrichment(mode EnrichMode) OIDCOption {
	return func(o *OIDC) {
		if mode.IsValid() {
			o.enrich = mode
		}
	}
}

// WithOIDCHTTPClient replaces the HTTP client.
func WithOIDCHTTPClient(client *http.Client) OIDCOption {
	return func(o *OIDC) {
		if client != nil {
			o.httpClient = client
		}
	}
}

// NewOIDC builds a verifier against the provider at issuerURL, reading roles from rolesClaim.
func NewOIDC(ctx context.Context, issuerURL, rolesClaim string, opts ...OIDCOption) (*OIDC, error) {
	if issuerURL == "" {
		return nil, errors.New("idp: missing the OIDC issuer URL")
	}
	if rolesClaim == "" {
		// Defaulting this would be worse than refusing: an unreadable roles claim yields an
		// empty role list, no rule matches, and every connection is refused with an error that
		// points at the rules rather than at the claim.
		return nil, errors.New("idp: missing the roles claim (there is no cross-provider default for where roles live)")
	}

	o := &OIDC{
		issuer:        strings.TrimSuffix(issuerURL, "/"),
		rolesClaim:    rolesClaim,
		usernameClaim: "preferred_username",
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		enrich:        EnrichNone,
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}

	endpoints, err := discoverEndpoints(ctx, o.httpClient, o.issuer, &o.issuer)
	if err != nil {
		return nil, err
	}
	o.jwksURL = endpoints.JWKS
	o.userinfo = newUserinfoFetcher(endpoints.Userinfo, o.httpClient, userinfoTimeout)

	cache := jwk.NewCache(ctx)
	if err := cache.Register(o.jwksURL,
		jwk.WithMinRefreshInterval(jwksRefreshInterval),
		jwk.WithHTTPClient(o.httpClient),
	); err != nil {
		return nil, fmt.Errorf("idp: register JWKS %q: %w", o.jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, o.jwksURL); err != nil {
		return nil, fmt.Errorf("idp: read JWKS %q: %w", o.jwksURL, err)
	}
	o.cache = cache

	return o, nil
}

// VerifyToken validates the token and extracts its normalized claims. Key rotation is handled
// the same way as for Zitadel: an unknown `kid` forces one rate-limited JWKS refetch.
func (o *OIDC) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	set, err := o.cache.Get(ctx, o.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("idp: get JWKS: %w", err)
	}

	parsed, err := o.parse(token, set)
	if err != nil && isUnknownKeyID(err) {
		if fresh, ok := o.refreshForUnknownKey(ctx); ok {
			parsed, err = o.parse(token, fresh)
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), `"exp" not satisfied`) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	subject := parsed.Subject()
	if subject == "" {
		return nil, ErrNoSubject
	}

	claims := &Claims{
		Subject:   subject,
		ExpiresAt: parsed.Expiration(),
		Raw:       parsed.PrivateClaims(),
	}
	claims.Roles = rolesFromClaim(claims, o.rolesClaim)
	if username, ok := claims.ClaimString(o.usernameClaim); ok {
		claims.Username = username
	}
	// The OIDC standard names, read from the token when it carries them.
	if name, ok := claims.ClaimString(claimName); ok {
		claims.Name = name
	}
	if email, ok := claims.ClaimString(claimEmail); ok {
		claims.Email = email
	}

	o.enrichClaims(ctx, claims, token)

	return claims, nil
}

// enrichClaims fills from userinfo what the token did not carry. See Zitadel.enrichClaims: the
// modes and the best-effort contract are identical, deliberately.
func (o *OIDC) enrichClaims(ctx context.Context, claims *Claims, token string) {
	switch o.enrich {
	case EnrichUsername:
		if claims.Username != "" {
			return
		}
		if fetched, ok := o.userinfo.fetch(ctx, claims.Subject, token); ok {
			claims.Username = fetched.PreferredUsername
			if claims.Username == "" {
				claims.Username = fetched.Name
			}
		}
	case EnrichProfile:
		if !needsEnrichment(claims) {
			return
		}
		if fetched, ok := o.userinfo.fetch(ctx, claims.Subject, token); ok {
			fetched.applyTo(claims)
		}
	}
}

// parse validates the token against a specific JWKS.
func (o *OIDC) parse(token string, set jwk.Set) (jwt.Token, error) {
	opts := []jwt.ParseOption{
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(o.issuer),
		jwt.WithValidate(true),
	}
	if o.audience != "" {
		opts = append(opts, jwt.WithAudience(o.audience))
	}
	return jwt.ParseString(token, opts...)
}

// refreshForUnknownKey forces one rate-limited JWKS refetch. See the Zitadel equivalent for
// why the cooldown is marked before the fetch rather than after.
func (o *OIDC) refreshForUnknownKey(ctx context.Context) (jwk.Set, bool) {
	o.mu.Lock()
	now := o.now()
	if !o.lastRefetch.IsZero() && now.Sub(o.lastRefetch) < jwksRefetchCooldown {
		o.mu.Unlock()
		return nil, false
	}
	o.lastRefetch = now
	o.mu.Unlock()

	set, err := o.cache.Refresh(ctx, o.jwksURL)
	if err != nil {
		return nil, false
	}
	return set, true
}

// rolesFromClaim reads roles from a claim path, accepting the shapes providers actually emit.
//
// Three are supported because there is no standard:
//
//	["a","b"]                 a flat array (Keycloak realm_access.roles, Entra roles)
//	"a b" / "a,b"             a space- or comma-separated string
//	{"a":{...},"b":{...}}     an object keyed by role name (Zitadel-style)
//
// Anything else yields no roles, which means no rule matches and the connection is refused —
// the safe direction for an unreadable claim.
func rolesFromClaim(claims *Claims, path string) []string {
	raw, ok := lookupClaim(claims.Raw, path)
	if !ok {
		return nil
	}

	switch value := raw.(type) {
	case []any:
		roles := make([]string, 0, len(value))
		for _, item := range value {
			if role, ok := item.(string); ok {
				if role = strings.TrimSpace(role); role != "" {
					roles = append(roles, role)
				}
			}
		}
		return roles

	case []string:
		return value

	case string:
		// Split on commas or whitespace: both conventions are in the wild (`scope` is
		// space-separated, custom claims are often comma-separated).
		fields := strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		roles := make([]string, 0, len(fields))
		for _, role := range fields {
			if role = strings.TrimSpace(role); role != "" {
				roles = append(roles, role)
			}
		}
		return roles

	case map[string]any:
		roles := make([]string, 0, len(value))
		for role := range value {
			roles = append(roles, role)
		}
		return roles

	default:
		return nil
	}
}

// lookupClaim walks a dot-separated path into a claim map.
func lookupClaim(raw map[string]any, path string) (any, bool) {
	if len(raw) == 0 || path == "" {
		return nil, false
	}
	var current any = raw
	for _, segment := range strings.Split(path, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = obj[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// Compile-time check.
var _ Verifier = (*OIDC)(nil)
