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

// Estos tests cubren la rotación de claves de Zitadel: el caso en que el IdP empieza a
// firmar con una `kid` que el cache todavía no tiene.
//
// Sin refetch on-demand, esa ventana dura hasta el refresco periódico siguiente (15 min) y
// se rechazan tokens perfectamente válidos. Es un fallo que en producción se ve como
// `Authorization Violation` genérico del lado del cliente, así que conviene tenerlo fijado
// acá y no depender de reproducirlo contra Zitadel real.

// jwksServer es un JWKS de mentira que imita a Zitadel: sirve un set de claves que se puede
// cambiar en caliente y cuenta cuántas veces se lo pidieron.
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
		// Los mismos headers que responde Zitadel: sin `max-age` del que agarrarse, httprc
		// cae al piso de WithMinRefreshInterval. Están acá para que el test ejercite el
		// mismo camino que producción.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		w.Write(js.publicSet(t))
	})

	js.Server = httptest.NewServer(mux)
	t.Cleanup(js.Close)
	return js
}

// serve cambia las claves que publica el JWKS. Zitadel ACUMULA durante una rotación (la
// vieja y la nueva conviven), y los tests lo reproducen pasando ambas.
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
			t.Fatalf("derivar la clave pública: %v", err)
		}
		if err := set.AddKey(pub); err != nil {
			t.Fatalf("agregar la clave al set: %v", err)
		}
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("serializar el JWKS: %v", err)
	}
	return body
}

// newSigningKey genera una clave RSA de firma con el `kid` dado.
func newSigningKey(t *testing.T, kid string) jwk.Key {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generar RSA: %v", err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("fijar kid: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("fijar alg: %v", err)
	}
	return key
}

// signToken emite un access token válido firmado con key.
func signToken(t *testing.T, key jwk.Key, issuer string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject("385270818583609346").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("armar el token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("firmar el token: %v", err)
	}
	return string(signed)
}

// El caso del reporte: Zitadel empieza a firmar con una clave nueva y el cache no la tiene.
// Antes del arreglo esto fallaba hasta el refresco siguiente; ahora el refetch on-demand lo
// resuelve en el mismo intento.
func TestVerifyTokenRefetchesOnKeyRotation(t *testing.T) {
	keyOld := newSigningKey(t, "kid-vieja")
	keyNew := newSigningKey(t, "kid-nueva")

	js := newJWKSServer(t, keyOld)
	ctx := context.Background()

	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	// Estado normal: la clave vigente verifica.
	if _, err := z.VerifyToken(ctx, signToken(t, keyOld, js.URL)); err != nil {
		t.Fatalf("el token con la clave vigente debería verificar: %v", err)
	}

	// Zitadel rota: ahora publica las dos y firma con la nueva.
	js.serve(keyOld, keyNew)

	before := js.hits.Load()
	claims, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL))
	if err != nil {
		t.Fatalf("tras la rotación el token debería verificar sin esperar el refresco: %v", err)
	}
	if claims.Subject != "385270818583609346" {
		t.Fatalf("subject inesperado: %q", claims.Subject)
	}
	if js.hits.Load() <= before {
		t.Fatal("se esperaba un refetch del JWKS ante la kid desconocida, no hubo ninguno")
	}
}

// La clave vieja tiene que seguir verificando después de la rotación: Zitadel acumula, y los
// tokens ya emitidos siguen vigentes hasta su `exp`.
func TestVerifyTokenAcceptsOldKeyAfterRotation(t *testing.T) {
	keyOld := newSigningKey(t, "kid-vieja")
	keyNew := newSigningKey(t, "kid-nueva")

	js := newJWKSServer(t, keyOld, keyNew)
	ctx := context.Background()

	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	for name, key := range map[string]jwk.Key{"vieja": keyOld, "nueva": keyNew} {
		if _, err := z.VerifyToken(ctx, signToken(t, key, js.URL)); err != nil {
			t.Fatalf("el token firmado con la clave %s debería verificar: %v", name, err)
		}
	}
}

// El rate limit: tokens con una `kid` inventada no pueden disparar un fetch al JWKS de
// Zitadel por intento. Sin este freno, cualquiera —sin autenticarse— convierte al callout en
// un amplificador de tráfico contra el IdP.
func TestVerifyTokenRateLimitsRefetch(t *testing.T) {
	keyGood := newSigningKey(t, "kid-buena")
	keyBogus := newSigningKey(t, "kid-inventada") // nunca se publica en el JWKS

	js := newJWKSServer(t, keyGood)

	// Reloj fijo: el cooldown nunca vence dentro del test.
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
	const intentos = 20
	for range intentos {
		if _, err := z.VerifyToken(ctx, signToken(t, keyBogus, js.URL)); err == nil {
			t.Fatal("un token con kid desconocida no debe verificar")
		}
	}

	if got := js.hits.Load() - before; got != 1 {
		t.Fatalf("se esperaba exactamente 1 refetch para %d intentos, hubo %d", intentos, got)
	}
}

// Pasado el cooldown vuelve a permitirse un refetch: el rate limit no puede dejar al callout
// clavado en un JWKS viejo si la rotación ocurre justo después de un intento fallido.
func TestVerifyTokenRefetchesAgainAfterCooldown(t *testing.T) {
	keyOld := newSigningKey(t, "kid-vieja")
	keyNew := newSigningKey(t, "kid-nueva")

	js := newJWKSServer(t, keyOld)

	now := time.Now()
	clock := func() time.Time { return now }

	ctx := context.Background()
	z, err := NewZitadel(ctx, js.URL, WithUsernameEnrichment(false), withClock(clock))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	// Primer intento con una kid que no existe: consume el refetch del cooldown.
	if _, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL)); err == nil {
		t.Fatal("todavía no se publicó la clave nueva: no debería verificar")
	}

	// Ahora sí rota Zitadel, pero el cooldown sigue vigente.
	js.serve(keyOld, keyNew)
	if _, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL)); err == nil {
		t.Fatal("dentro del cooldown no debería refetchear, así que aún no puede verificar")
	}

	// Vencido el cooldown, el refetch se vuelve a permitir y la clave nueva entra.
	now = now.Add(jwksRefetchCooldown + time.Second)
	if _, err := z.VerifyToken(ctx, signToken(t, keyNew, js.URL)); err != nil {
		t.Fatalf("pasado el cooldown el token debería verificar: %v", err)
	}
}

// Un token vencido tiene que seguir reportándose como ErrExpiredToken y NO disparar un
// refetch: su `kid` está en el JWKS, el problema es otro.
func TestVerifyTokenExpiredDoesNotRefetch(t *testing.T) {
	key := newSigningKey(t, "kid-buena")
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
		t.Fatalf("armar el token: %v", err)
	}
	signed, err := jwt.Sign(expired, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("firmar: %v", err)
	}

	before := js.hits.Load()
	_, err = z.VerifyToken(ctx, string(signed))
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("esperaba ErrExpiredToken, obtuve %v", err)
	}
	if js.hits.Load() != before {
		t.Fatal("un token vencido no debe disparar un refetch del JWKS")
	}
}

// isUnknownKeyID detecta el caso por TEXTO porque jwx v2 no expone un error tipado. Este
// test es el que avisa si una actualización de jwx cambia el mensaje: sin él, el refetch
// dejaría de dispararse y volvería la ventana de rechazo, en silencio y sin fallar ningún
// test.
func TestUnknownKeyIDFragmentSigueVigente(t *testing.T) {
	keyPublicada := newSigningKey(t, "kid-publicada")
	keyAusente := newSigningKey(t, "kid-ausente")

	js := newJWKSServer(t, keyPublicada)
	ctx := context.Background()

	set, err := jwk.Fetch(ctx, js.URL+"/oauth/v2/keys")
	if err != nil {
		t.Fatalf("traer el JWKS: %v", err)
	}

	z := &Zitadel{issuer: js.URL, now: time.Now}
	_, err = z.parse(signToken(t, keyAusente, js.URL), set)
	if err == nil {
		t.Fatal("una kid ausente del JWKS no debería verificar")
	}
	if !isUnknownKeyID(err) {
		t.Fatalf("jwx cambió el mensaje de 'kid desconocida': el refetch on-demand ya no se "+
			"dispara y volvió la ventana de rechazo ante rotaciones.\n"+
			"Actualizá errUnknownKeyIDFragment (%q) para que matchee: %v",
			errUnknownKeyIDFragment, err)
	}
}
