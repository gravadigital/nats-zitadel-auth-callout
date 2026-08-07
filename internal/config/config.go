// Package config lee la configuración del callout del entorno.
//
// Se parte en dos fuentes a propósito:
//
//   - lo que decide una persona (URL de NATS, issuer de Zitadel, instancia) va en .env;
//   - lo que genera el bootstrap (seeds, pubkeys, creds) se expone por nats/out/callout-env.sh,
//     que el script de arranque hace `source`. Así las claves nunca se escriben a mano
//     y regenerar la identidad NATS no obliga a editar configuración.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Modos de identidad.
const (
	// IDPModeZitadel valida los tokens contra una instancia real de Zitadel.
	IDPModeZitadel = "zitadel"
	// IDPModeMock valida contra un IdP de mentira, en proceso. Es el modo de CI y de
	// desarrollo local: no necesita secretos ni red.
	IDPModeMock = "mock"
)

// Config es la configuración completa del callout.
type Config struct {
	// NATSURL es la URL del servidor NATS.
	NATSURL string
	// HandlerCreds son las creds del sentinel-handler de la cuenta AUTH: la conexión del
	// propio servicio. Tiene que estar declarado en `--auth-user`, para que el servidor
	// lo autorice directo y el callout no se dispare sobre sí mismo.
	HandlerCreds string

	// AppAccountSigningKeySeed es la seed de la signing key de la cuenta APP. Firma los
	// User JWT: es lo que hace que el usuario aterrice en esa cuenta.
	AppAccountSigningKeySeed string
	// AppAccountPubKey es la pubkey de la cuenta APP (claim IssuerAccount).
	AppAccountPubKey string
	// AuthAccountSigningKeySeed es la seed de la signing key de la cuenta AUTH. Firma el
	// authorization_response, y es la que el servidor tiene configurada como issuer.
	AuthAccountSigningKeySeed string
	// XKeySeed es la seed curve25519 del callout (encriptación de los requests). Vacía
	// desactiva la encriptación; solo tiene sentido si el server tampoco tiene --curve.
	XKeySeed string

	// RulesPath es el path a rules.yaml. Las plantillas se resuelven relativas a su directorio.
	RulesPath string
	// Instance es el primer token de todo subject: aísla despliegues que comparten NATS.
	Instance string

	// IDPMode es zitadel o mock.
	IDPMode string
	// ZitadelIssuerURL es la URL de la instancia de Zitadel (modo zitadel).
	ZitadelIssuerURL string
	// ZitadelProjectID acota la lectura de roles a un proyecto. Vacío lee los roles de
	// todos los proyectos del token.
	ZitadelProjectID string

	// LogLevel es el nivel de log (debug, info, warn, error).
	LogLevel string
}

// Load arma la Config desde el entorno y la valida.
func Load() (*Config, error) {
	cfg := &Config{
		NATSURL:                   env("GESTION_NATS_URL", "nats://127.0.0.1:4222"),
		HandlerCreds:              os.Getenv("GESTION_HANDLER_CREDS"),
		AppAccountSigningKeySeed:  os.Getenv("GESTION_APP_ACCOUNT_SK_SEED"),
		AppAccountPubKey:          os.Getenv("GESTION_APP_ACCOUNT_PUB"),
		AuthAccountSigningKeySeed: os.Getenv("GESTION_AUTH_ACCOUNT_SK_SEED"),
		XKeySeed:                  os.Getenv("GESTION_XKEY_SEED"),
		RulesPath:                 env("GESTION_RULES_PATH", "config/rules.yaml"),
		Instance:                  env("GESTION_INSTANCE", "dev"),
		IDPMode:                   env("GESTION_IDP_MODE", IDPModeMock),
		ZitadelIssuerURL:          os.Getenv("GESTION_ZITADEL_ISSUER_URL"),
		ZitadelProjectID:          os.Getenv("GESTION_ZITADEL_PROJECT_ID"),
		LogLevel:                  env("GESTION_LOG_LEVEL", "info"),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate chequea que no falte nada indispensable. Se hace todo junto para que un
// deploy mal configurado muestre en un solo arranque todo lo que le falta.
func (c *Config) validate() error {
	var missing []string
	require := func(name, value string) {
		if value == "" {
			missing = append(missing, name)
		}
	}

	require("GESTION_HANDLER_CREDS", c.HandlerCreds)
	require("GESTION_APP_ACCOUNT_SK_SEED", c.AppAccountSigningKeySeed)
	require("GESTION_APP_ACCOUNT_PUB", c.AppAccountPubKey)
	require("GESTION_AUTH_ACCOUNT_SK_SEED", c.AuthAccountSigningKeySeed)
	require("GESTION_RULES_PATH", c.RulesPath)
	require("GESTION_INSTANCE", c.Instance)

	switch c.IDPMode {
	case IDPModeZitadel:
		require("GESTION_ZITADEL_ISSUER_URL", c.ZitadelIssuerURL)
	case IDPModeMock:
	default:
		return fmt.Errorf("config: GESTION_IDP_MODE %q inválido (esperaba %s o %s)",
			c.IDPMode, IDPModeZitadel, IDPModeMock)
	}

	if len(missing) > 0 {
		return fmt.Errorf("config: faltan variables de entorno: %s", strings.Join(missing, ", "))
	}

	// La instancia es el primer token de todo subject: un punto o un wildcard la
	// romperían de forma difícil de diagnosticar (los permisos quedarían corridos
	// un segmento).
	if strings.ContainsAny(c.Instance, ".*> ") {
		return errors.New("config: GESTION_INSTANCE no puede contener `.`, `*`, `>` ni espacios")
	}

	return nil
}

// env lee una variable con default.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
