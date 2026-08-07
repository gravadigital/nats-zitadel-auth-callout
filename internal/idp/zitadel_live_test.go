//go:build live

// Tests contra una instancia REAL de Zitadel. Quedan detrás del build tag `live` porque
// necesitan red y una instancia accesible: no corren en `go test ./...`.
//
//	GESTION_ZITADEL_ISSUER_URL=https://id.grava.io go test -tags live -v ./internal/idp/
//
// Con un token a mano, además se verifica el camino completo de validación:
//
//	GESTION_ZITADEL_ISSUER_URL=https://id.grava.io \
//	GESTION_TEST_TOKEN="$(./scripts/zitadel-token.sh secrets/poc-service.json)" \
//	  go test -tags live -v ./internal/idp/
package idp

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// issuerFromEnv devuelve el issuer a probar, o saltea el test si no está configurado.
func issuerFromEnv(t *testing.T) string {
	t.Helper()
	issuer := os.Getenv("GESTION_ZITADEL_ISSUER_URL")
	if issuer == "" {
		t.Skip("falta GESTION_ZITADEL_ISSUER_URL")
	}
	return issuer
}

// Verifica lo que rompía en el POC: que el JWKS se resuelva por OIDC discovery. Una
// instancia self-hosted lo sirve en /oauth/v2/keys, no en /.well-known/jwks.json.
func TestLiveDiscoveryResolvesJWKS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verifier, err := NewZitadel(ctx, issuerFromEnv(t))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}
	t.Logf("discovery OK — issuer=%s jwks=%s", verifier.issuer, verifier.jwksURL)

	// Un token mal formado tiene que dar ErrInvalidToken y no un error de infraestructura:
	// así se distingue "el cliente mandó cualquier cosa" de "Zitadel no responde".
	if _, err := verifier.VerifyToken(ctx, "no.es.un.jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("esperaba ErrInvalidToken, obtuve %v", err)
	}
}

// Con un token real, verifica el camino completo: firma, issuer, vigencia, y que salgan el
// sub y los roles. Si esto pasa, el callout va a poder autenticar ese token.
func TestLiveVerifyToken(t *testing.T) {
	token := os.Getenv("GESTION_TEST_TOKEN")
	if token == "" {
		t.Skip("falta GESTION_TEST_TOKEN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verifier, err := NewZitadel(ctx, issuerFromEnv(t),
		WithProjectID(os.Getenv("GESTION_ZITADEL_PROJECT_ID")),
	)
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	claims, err := verifier.VerifyToken(ctx, token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	t.Logf("sub=%s username=%q roles=%v expira=%s",
		claims.Subject, claims.Username, claims.Roles, claims.ExpiresAt.Format(time.RFC3339))

	if claims.Subject == "" {
		t.Fatal("el token no trae sub")
	}
	// Sin roles el callout no puede matchear ninguna regla, así que este es el fallo que
	// más conviene detectar acá y no en el handshake de NATS.
	if len(claims.Roles) == 0 {
		t.Fatal("el token no trae roles: falta el scope urn:zitadel:iam:org:projects:roles, " +
			"o el rol no está concedido al usuario en el proyecto")
	}
}
