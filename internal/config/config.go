// Package config reads the callout's configuration from the environment.
//
// It is split into two sources on purpose:
//
//   - what a person decides (NATS URL, Zitadel issuer, instance) goes in .env;
//   - what the bootstrap generates (seeds, pubkeys, creds) is exposed through
//     nats/out/callout-env.sh, which the startup script sources. That way the keys are never
//     written by hand and regenerating the NATS identity does not force editing any
//     configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Identity modes.
const (
	// IDPModeZitadel validates tokens against a real Zitadel instance.
	IDPModeZitadel = "zitadel"
	// IDPModeMock validates against a fake, in-process IdP. It is the CI and local
	// development mode: it needs no secrets and no network.
	IDPModeMock = "mock"
)

// Config is the callout's full configuration.
type Config struct {
	// NATSURL is the NATS server URL.
	NATSURL string
	// HandlerCreds are the creds of the AUTH account's sentinel-handler: the service's own
	// connection. It has to be declared in `--auth-user`, so that the server authorizes it
	// directly and the callout is not triggered against itself.
	HandlerCreds string

	// AppAccountSigningKeySeed is the seed of the APP account's signing key. It signs the
	// User JWTs: it is what makes the user land in that account.
	AppAccountSigningKeySeed string
	// AppAccountPubKey is the APP account's public key (the IssuerAccount claim).
	AppAccountPubKey string
	// AuthAccountSigningKeySeed is the seed of the AUTH account's signing key. It signs the
	// authorization_response, and it is the one the server has configured as the issuer.
	AuthAccountSigningKeySeed string
	// XKeySeed is the callout's curve25519 seed (request encryption). Leaving it empty
	// disables encryption; that only makes sense if the server has no --curve either.
	XKeySeed string

	// RulesPath is the path to rules.yaml. Templates are resolved relative to its directory.
	RulesPath string
	// Instance is the first token of every subject: it isolates deployments sharing a NATS.
	Instance string

	// IDPMode is zitadel or mock.
	IDPMode string
	// ZitadelIssuerURL is the Zitadel instance's URL (zitadel mode).
	ZitadelIssuerURL string
	// ZitadelProjectID narrows role reading to a single project. Empty reads the roles of
	// every project in the token.
	ZitadelProjectID string

	// LogLevel is the log level (debug, info, warn, error).
	LogLevel string
}

// Load assembles the Config from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		NATSURL:                   env("CALLOUT_NATS_URL", "nats://127.0.0.1:4222"),
		HandlerCreds:              os.Getenv("CALLOUT_HANDLER_CREDS"),
		AppAccountSigningKeySeed:  os.Getenv("CALLOUT_APP_ACCOUNT_SK_SEED"),
		AppAccountPubKey:          os.Getenv("CALLOUT_APP_ACCOUNT_PUB"),
		AuthAccountSigningKeySeed: os.Getenv("CALLOUT_AUTH_ACCOUNT_SK_SEED"),
		XKeySeed:                  os.Getenv("CALLOUT_XKEY_SEED"),
		RulesPath:                 env("CALLOUT_RULES_PATH", "config/rules.yaml"),
		Instance:                  env("CALLOUT_INSTANCE", "dev"),
		IDPMode:                   env("CALLOUT_IDP_MODE", IDPModeMock),
		ZitadelIssuerURL:          os.Getenv("CALLOUT_ZITADEL_ISSUER_URL"),
		ZitadelProjectID:          os.Getenv("CALLOUT_ZITADEL_PROJECT_ID"),
		LogLevel:                  env("CALLOUT_LOG_LEVEL", "info"),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate checks that nothing essential is missing. It is all done at once so that a
// misconfigured deploy shows everything it lacks in a single startup.
func (c *Config) validate() error {
	var missing []string
	require := func(name, value string) {
		if value == "" {
			missing = append(missing, name)
		}
	}

	require("CALLOUT_HANDLER_CREDS", c.HandlerCreds)
	require("CALLOUT_APP_ACCOUNT_SK_SEED", c.AppAccountSigningKeySeed)
	require("CALLOUT_APP_ACCOUNT_PUB", c.AppAccountPubKey)
	require("CALLOUT_AUTH_ACCOUNT_SK_SEED", c.AuthAccountSigningKeySeed)
	require("CALLOUT_RULES_PATH", c.RulesPath)
	require("CALLOUT_INSTANCE", c.Instance)

	switch c.IDPMode {
	case IDPModeZitadel:
		require("CALLOUT_ZITADEL_ISSUER_URL", c.ZitadelIssuerURL)
	case IDPModeMock:
	default:
		return fmt.Errorf("config: invalid CALLOUT_IDP_MODE %q (expected %s or %s)",
			c.IDPMode, IDPModeZitadel, IDPModeMock)
	}

	if len(missing) > 0 {
		return fmt.Errorf("config: missing environment variables: %s", strings.Join(missing, ", "))
	}

	// The instance is the first token of every subject: a dot or a wildcard would break it in
	// a way that is hard to diagnose (the permissions would be shifted by one segment).
	if strings.ContainsAny(c.Instance, ".*> ") {
		return errors.New("config: CALLOUT_INSTANCE cannot contain `.`, `*`, `>` or spaces")
	}

	return nil
}

// env reads a variable with a fallback.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
