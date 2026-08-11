package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// These tests cover Zitadel key rotation: the case where the IdP starts signing with a `kid`
// the cache does not have yet.
//
// Without the on-demand refetch, that window lasts until the next periodic refresh (15 min)
// and perfectly valid tokens are rejected. In production the failure shows up as a generic
// `Authorization Violation` on the client side, so it is worth pinning down here rather than
// relying on reproducing it against real Zitadel.

// jwksServer is a fake JWKS that mimics Zitadel: it serves a key set that can be swapped at
// runtime and counts how many times it was requested.
type jwksServer struct {
	*httptest.Server
	mu   sync.Mutex
	keys []jwk.Key
	hits atomic.Int32
}

func newJWKSServer(t *testing.T, keys ...jwk.Key) *jwksServer {
	t.Helper()
	js := &jwksServer{keys: keys}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, js.URL, js.URL+"/oauth/v2/keys")
	})
	mux.HandleFunc("/oauth/v2/keys", func(w http.ResponseWriter, _ *http.Request) {
		js.hits.Add(1)
		// The same headers Zitadel responds with: with no `max-age` to latch onto, httprc falls
		// back to the WithMinRefreshInterval floor. They are here so the test exercises the same
		// path as production.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		w.Write(js.publicSet(t))
	})

	js.Server = httptest.NewServer(mux)
	t.Cleanup(js.Close)
	return js
}

// serve swaps the keys the JWKS publishes. Zitadel ACCUMULATES during a rotation (the old and
// the new coexist), and the tests reproduce that by passing both.
func (js *jwksServer) serve(keys ...jwk.Key) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.keys = keys
}

func (js *jwksServer) publicSet(t *testing.T) []byte {
	t.Helper()
	js.mu.Lock()
	defer js.mu.Unlock()

	set := jwk.NewSet()
	for _, k := range js.keys {
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatalf("derive the public key: %v", err)
		}
		if err := set.AddKey(pub); err != nil {
			t.Fatalf("add the key to the set: %v", err)
		}
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("serialize the JWKS: %v", err)
	}
	return body
}

// newSigningKey generates an RSA signing key with the given `kid`.
func newSigningKey(t *testing.T, kid string) jwk.Key {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	return key
}

// signToken issues a valid access token signed with key.
func signToken(t *testing.T, key jwk.Key, issuer string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject("100000000000000001").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("build the token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("sign the token: %v", err)
	}
	return string(signed)
}

// The reported case: Zitadel starts signing with a new key and the cache does not have it.
// Before the fix this failed until the next refresh; now the on-demand refetch resolves it
// within the same attempt.
func TestVerifyTokenRefetchesOnKeyRotation(t *testing.T) {
	keyOld := newSigningKey(t, "kid-old")
	keyNew := newSigningKey(t, "kid-new")

	js := newJWKSServer(t, keyOld)
	ctx := context.Background()

	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	// Normal state: the current key verifies.
	if _, err := z.VerifyToken(ctx, signToken(t, keyOld, js.URL)); err != nil {
		t.Fatalf("the token signed with the current key should verify: %v", err)
	}

	// Zitadel rotates: it now publishes both and signs with the new one.
	js.serve(keyOld, keyNew)

	before := js.hits.Load()
	claims, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL))
	if err != nil {
		t.Fatalf("after the rotation the token should verify without waiting for the refresh: %v", err)
	}
	if claims.Subject != "100000000000000001" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
	if js.hits.Load() <= before {
		t.Fatal("expected a JWKS refetch for the unknown kid, there was none")
	}
}

// The old key has to keep verifying after the rotation: Zitadel accumulates, and
// already-issued tokens remain valid until their `exp`.
func TestVerifyTokenAcceptsOldKeyAfterRotation(t *testing.T) {
	keyOld := newSigningKey(t, "kid-old")
	keyNew := newSigningKey(t, "kid-new")

	js := newJWKSServer(t, keyOld, keyNew)
	ctx := context.Background()

	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	for name, key := range map[string]jwk.Key{"old": keyOld, "new": keyNew} {
		if _, err := z.VerifyToken(ctx, signToken(t, key, js.URL)); err != nil {
			t.Fatalf("the token signed with the %s key should verify: %v", name, err)
		}
	}
}

// The rate limit: tokens with a made-up `kid` must not trigger a fetch against Zitadel's JWKS
// on every attempt. Without this brake, anyone — without authenticating — turns the callout
// into a traffic amplifier against the IdP.
func TestVerifyTokenRateLimitsRefetch(t *testing.T) {
	keyGood := newSigningKey(t, "kid-good")
	keyBogus := newSigningKey(t, "kid-made-up") // never published in the JWKS

	js := newJWKSServer(t, keyGood)

	// Frozen clock: the cooldown never elapses within the test.
	frozen := time.Now()
	ctx := context.Background()
	z, err := NewZitadel(ctx, js.URL,
		WithUsernameEnrichment(false),
		withClock(func() time.Time { return frozen }),
	)
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	before := js.hits.Load()
	const attempts = 20
	for range attempts {
		if _, err := z.VerifyToken(ctx, signToken(t, keyBogus, js.URL)); err == nil {
			t.Fatal("a token with an unknown kid must not verify")
		}
	}

	if got := js.hits.Load() - before; got != 1 {
		t.Fatalf("expected exactly 1 refetch for %d attempts, there were %d", attempts, got)
	}
}

// Once the cooldown has elapsed a refetch is allowed again: the rate limit must not leave the
// callout stuck on a stale JWKS if the rotation happens right after a failed attempt.
func TestVerifyTokenRefetchesAgainAfterCooldown(t *testing.T) {
	keyOld := newSigningKey(t, "kid-old")
	keyNew := newSigningKey(t, "kid-new")

	js := newJWKSServer(t, keyOld)

	now := time.Now()
	clock := func() time.Time { return now }

	ctx := context.Background()
	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false), withClock(clock))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	// First attempt with a kid that does not exist: it consumes the cooldown's refetch.
	if _, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL)); err == nil {
		t.Fatal("the new key has not been published yet: it should not verify")
	}

	// Now Zitadel does rotate, but the cooldown is still in effect.
	js.serve(keyOld, keyNew)
	if _, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL)); err == nil {
		t.Fatal("within the cooldown it should not refetch, so it still cannot verify")
	}

	// With the cooldown elapsed, the refetch is allowed again and the new key comes in.
	now = now.Add(jwksRefetchCooldown + time.Second)
	if _, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL)); err != nil {
		t.Fatalf("once the cooldown has elapsed the token should verify: %v", err)
	}
}

// An expired token has to keep being reported as ErrExpiredToken and must NOT trigger a
// refetch: its `kid` is in the JWKS, the problem is a different one.
func TestVerifyTokenExpiredDoesNotRefetch(t *testing.T) {
	key := newSigningKey(t, "kid-good")
	js := newJWKSServer(t, key)
	ctx := context.Background()

	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	expired, err := jwt.NewBuilder().
		Issuer(js.URL).Subject("u-1").
		IssuedAt(time.Now().Add(-2 * time.Hour)).
		Expiration(time.Now().Add(-time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("build the token: %v", err)
	}
	signed, err := jwt.Sign(expired, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	before := js.hits.Load()
	_, err = z.VerifyToken(ctx, string(signed))
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
	if js.hits.Load() != before {
		t.Fatal("an expired token must not trigger a JWKS refetch")
	}
}

// isUnknownKeyID detects the case by TEXT because jwx v2 exposes no typed error. This test is
// the one that warns if a jwx update changes the message: without it, the refetch would stop
// firing and the rejection window would come back, silently and without failing any test.
func TestUnknownKeyIDFragmentStillMatches(t *testing.T) {
	keyPublished := newSigningKey(t, "kid-published")
	keyAbsent := newSigningKey(t, "kid-absent")

	js := newJWKSServer(t, keyPublished)
	ctx := context.Background()

	set, err := jwk.Fetch(ctx, js.URL+"/oauth/v2/keys")
	if err != nil {
		t.Fatalf("fetch the JWKS: %v", err)
	}

	z := &Zitadel{issuer: js.URL, now: time.Now}
	_, err = z.parse(signToken(t, keyAbsent, js.URL), set)
	if err == nil {
		t.Fatal("a kid absent from the JWKS should not verify")
	}
	if !isUnknownKeyID(err) {
		t.Fatalf("jwx changed its 'unknown kid' message: the on-demand refetch no longer fires "+
			"and the rejection window on rotations is back.\n"+
			"Update errUnknownKeyIDFragment (%q) so that it matches: %v",
			errUnknownKeyIDFragment, err)
	}
}
