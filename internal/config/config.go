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
	// IDPModeOIDC validates against any standards-compliant OIDC provider, with the role and
	// username claims declared in configuration. It is what makes the service usable against
	// Keycloak, Auth0, Okta or Entra without code changes.
	IDPModeOIDC = "oidc"
	// IDPModeMock validates against a fake, in-process IdP. It is the CI and local
	// development mode: it needs no secrets and no network.
	IDPModeMock = "mock"
)

// Server authorization modes. They mirror callout.Mode; config carries strings so this package
// keeps depending on nothing.
const (
	// ServerModeOperator is a NATS whose authorization comes from operator-signed account JWTs.
	ServerModeOperator = "operator"
	// ServerModeConfig is a NATS whose authorization lives in nats-server.conf.
	ServerModeConfig = "config"
)

// Inbox derivation modes.
const (
	// InboxModeHashed scopes each client to `_INBOX.<hash(user-id)>`. It isolates replies
	// between users, at the cost of every client having to set that prefix when connecting.
	InboxModeHashed = "hashed"
	// InboxModePassthrough leaves the inbox alone, for adopting an existing NATS whose clients
	// cannot be changed. Templates then have to grant a broader inbox (typically `_INBOX.>`),
	// which means any client in the account can subscribe to another's replies. It is a
	// deliberate trade-off and the reason this is not the default.
	InboxModePassthrough = "passthrough"
)

// Handler credential kinds: how the callout authenticates its OWN connection.
const (
	// HandlerAuthCreds is a .creds file (an operator-mode format).
	HandlerAuthCreds = "creds"
	// HandlerAuthUserPass is user/password, the usual config-mode form.
	HandlerAuthUserPass = "userpass"
	// HandlerAuthNKey is an nkey seed plus its pubkey declared in the server config.
	HandlerAuthNKey = "nkey"
)

// Config is the callout's full configuration.
type Config struct {
	// NATSURL is the NATS server URL.
	NATSURL string

	// ServerMode is the authorization mode of the NATS being served: operator or config.
	//
	// It is declared, never inferred. Inferring it from which variables happen to be present
	// would turn a typo into a silently different authorization model, which is the last thing
	// worth guessing in an authorization component.
	ServerMode string

	// HandlerCreds are the creds of the AUTH account's sentinel-handler: the service's own
	// connection. It has to be declared in `--auth-user` (operator) or `auth_users` (config),
	// so that the server authorizes it directly and the callout is not triggered against
	// itself.
	HandlerCreds string
	// HandlerUser and HandlerPassword are the user/password form of the handler's own
	// connection. It is the usual form in config mode, where .creds files do not exist.
	HandlerUser     string
	HandlerPassword string
	// HandlerNKeySeed is the nkey form of the handler's own connection. Its public half has to
	// be declared in the server's config.
	HandlerNKeySeed string

	// AppAccountSigningKeySeed is the seed of the key that signs User JWTs.
	//
	// In operator mode it is an APP account signing key: it is what makes the user land in that
	// account. In config mode it is the key whose pubkey the server declares in
	// `auth_callout.issuer`.
	AppAccountSigningKeySeed string
	// AppAccountPubKey is the APP account's public key (the IssuerAccount claim). Operator
	// mode only: a config-mode server rejects a User JWT carrying issuer_account.
	AppAccountPubKey string
	// TargetAccount is the NAME of the account connections land in. Config mode only, where it
	// travels in the User JWT's audience. It must be an account NAME, not a pubkey: the server
	// resolves the placement by name.
	TargetAccount string
	// AuthAccountSigningKeySeed is the seed of the AUTH account's signing key. It signs the
	// authorization_response. Operator mode only; in config mode a single key signs both.
	AuthAccountSigningKeySeed string
	// XKeySeed is the callout's curve25519 seed (request encryption). Leaving it empty
	// disables encryption; that only makes sense if the server has no XKey either.
	XKeySeed string

	// RulesPath is the path to rules.yaml. Templates are resolved relative to its directory.
	RulesPath string
	// Instance is the value of the {{instance}} placeholder: it isolates deployments sharing a
	// NATS.
	//
	// It is OPTIONAL. A deployment adopting an existing subject grammar usually has nowhere to
	// put an extra leading token, and templates that never reference {{instance}} have no use
	// for it. When empty, a template using {{instance}} fails at startup rather than expanding
	// to an empty subject segment.
	Instance string

	// InboxMode selects how the private inbox prefix is derived: hashed or passthrough.
	InboxMode string

	// IDPMode is zitadel, oidc or mock.
	IDPMode string
	// ZitadelIssuerURL is the Zitadel instance's URL (zitadel mode).
	ZitadelIssuerURL string
	// ZitadelProjectID narrows role reading to a single project. Empty reads the roles of
	// every project in the token.
	ZitadelProjectID string

	// OIDCIssuerURL is the provider's issuer URL (oidc mode). JWKS is found by discovery.
	OIDCIssuerURL string
	// OIDCRolesClaim is the claim path the roles are read from, dot-separated for nesting
	// (e.g. `realm_access.roles` for Keycloak, `roles` for a flat array). Required in oidc
	// mode: there is no cross-provider standard for where roles live.
	OIDCRolesClaim string
	// OIDCUsernameClaim is the claim carrying the human-readable name.
	OIDCUsernameClaim string
	// OIDCAudience, when set, additionally requires the token's `aud` to contain it. Without
	// it any token the provider issued for ANY of its clients verifies here, which is usually
	// not what a deployment wants.
	OIDCAudience string

	// LogLevel is the log level (debug, info, warn, error).
	LogLevel string
}

// Load assembles the Config from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		NATSURL: env("CALLOUT_NATS_URL", "nats://127.0.0.1:4222"),
		// Defaulting to operator keeps every existing deployment working with no new variable.
		ServerMode:                env("CALLOUT_SERVER_MODE", ServerModeOperator),
		HandlerCreds:              os.Getenv("CALLOUT_HANDLER_CREDS"),
		HandlerUser:               os.Getenv("CALLOUT_HANDLER_USER"),
		HandlerPassword:           os.Getenv("CALLOUT_HANDLER_PASSWORD"),
		HandlerNKeySeed:           os.Getenv("CALLOUT_HANDLER_NKEY_SEED"),
		AppAccountSigningKeySeed:  os.Getenv("CALLOUT_APP_ACCOUNT_SK_SEED"),
		AppAccountPubKey:          os.Getenv("CALLOUT_APP_ACCOUNT_PUB"),
		TargetAccount:             os.Getenv("CALLOUT_TARGET_ACCOUNT"),
		AuthAccountSigningKeySeed: os.Getenv("CALLOUT_AUTH_ACCOUNT_SK_SEED"),
		XKeySeed:                  os.Getenv("CALLOUT_XKEY_SEED"),
		RulesPath:                 env("CALLOUT_RULES_PATH", "config/rules.yaml"),
		Instance:                  os.Getenv("CALLOUT_INSTANCE"),
		IDPMode:                   env("CALLOUT_IDP_MODE", IDPModeMock),
		ZitadelIssuerURL:          os.Getenv("CALLOUT_ZITADEL_ISSUER_URL"),
		ZitadelProjectID:          os.Getenv("CALLOUT_ZITADEL_PROJECT_ID"),
		OIDCIssuerURL:             os.Getenv("CALLOUT_OIDC_ISSUER_URL"),
		OIDCRolesClaim:            os.Getenv("CALLOUT_OIDC_ROLES_CLAIM"),
		OIDCUsernameClaim:         env("CALLOUT_OIDC_USERNAME_CLAIM", "preferred_username"),
		OIDCAudience:              os.Getenv("CALLOUT_OIDC_AUDIENCE"),
		InboxMode:                 env("CALLOUT_INBOX_MODE", InboxModeHashed),
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

	// unexpected flags a variable that has no meaning in the selected mode. Ignoring it would
	// let a deploy believe it had configured something the service never reads.
	var unexpected []string
	reject := func(name, value, why string) {
		if value != "" {
			unexpected = append(unexpected, fmt.Sprintf("%s (%s)", name, why))
		}
	}

	require("CALLOUT_APP_ACCOUNT_SK_SEED", c.AppAccountSigningKeySeed)
	require("CALLOUT_RULES_PATH", c.RulesPath)

	// The signing key is the only key both modes share; everything else is per-mode.
	switch c.ServerMode {
	case ServerModeOperator:
		require("CALLOUT_APP_ACCOUNT_PUB", c.AppAccountPubKey)
		require("CALLOUT_AUTH_ACCOUNT_SK_SEED", c.AuthAccountSigningKeySeed)
		reject("CALLOUT_TARGET_ACCOUNT", c.TargetAccount,
			"operator mode places users by issuer-account pubkey, not by account name")
	case ServerModeConfig:
		require("CALLOUT_TARGET_ACCOUNT", c.TargetAccount)
		reject("CALLOUT_APP_ACCOUNT_PUB", c.AppAccountPubKey,
			"a config-mode server rejects a User JWT carrying issuer_account")
		reject("CALLOUT_AUTH_ACCOUNT_SK_SEED", c.AuthAccountSigningKeySeed,
			"config mode signs both the User JWT and the response with CALLOUT_APP_ACCOUNT_SK_SEED")
	default:
		return fmt.Errorf("config: invalid CALLOUT_SERVER_MODE %q (expected %s or %s)",
			c.ServerMode, ServerModeOperator, ServerModeConfig)
	}

	// The handler's own connection. Exactly one form has to be given: accepting several and
	// picking one silently would make it unclear which credential is actually in use.
	forms := 0
	if c.HandlerCreds != "" {
		forms++
	}
	if c.HandlerUser != "" || c.HandlerPassword != "" {
		forms++
	}
	if c.HandlerNKeySeed != "" {
		forms++
	}
	switch {
	case forms == 0:
		missing = append(missing, "one of CALLOUT_HANDLER_CREDS, CALLOUT_HANDLER_USER+CALLOUT_HANDLER_PASSWORD or CALLOUT_HANDLER_NKEY_SEED")
	case forms > 1:
		return errors.New("config: more than one handler credential form is set; keep exactly one of CALLOUT_HANDLER_CREDS, CALLOUT_HANDLER_USER+CALLOUT_HANDLER_PASSWORD or CALLOUT_HANDLER_NKEY_SEED")
	case c.HandlerUser != "" && c.HandlerPassword == "":
		missing = append(missing, "CALLOUT_HANDLER_PASSWORD")
	case c.HandlerPassword != "" && c.HandlerUser == "":
		missing = append(missing, "CALLOUT_HANDLER_USER")
	}

	switch c.IDPMode {
	case IDPModeZitadel:
		require("CALLOUT_ZITADEL_ISSUER_URL", c.ZitadelIssuerURL)
	case IDPModeOIDC:
		require("CALLOUT_OIDC_ISSUER_URL", c.OIDCIssuerURL)
		// There is no cross-provider convention for where roles live, so this cannot be
		// defaulted: guessing would silently authorize with an empty role list, and an empty
		// role list means no rule matches and every connection is refused.
		require("CALLOUT_OIDC_ROLES_CLAIM", c.OIDCRolesClaim)
	case IDPModeMock:
	default:
		return fmt.Errorf("config: invalid CALLOUT_IDP_MODE %q (expected %s, %s or %s)",
			c.IDPMode, IDPModeZitadel, IDPModeOIDC, IDPModeMock)
	}

	switch c.InboxMode {
	case InboxModeHashed, InboxModePassthrough:
	default:
		return fmt.Errorf("config: invalid CALLOUT_INBOX_MODE %q (expected %s or %s)",
			c.InboxMode, InboxModeHashed, InboxModePassthrough)
	}

	if len(unexpected) > 0 {
		return fmt.Errorf("config: variables that do not apply to CALLOUT_SERVER_MODE=%s: %s",
			c.ServerMode, strings.Join(unexpected, ", "))
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: missing environment variables: %s", strings.Join(missing, ", "))
	}

	// The instance is a subject token: a dot or a wildcard would break it in a way that is hard
	// to diagnose (the permissions would be shifted by one segment). Empty is allowed — it just
	// means templates must not reference {{instance}}.
	if strings.ContainsAny(c.Instance, ".*> ") {
		return errors.New("config: CALLOUT_INSTANCE cannot contain `.`, `*`, `>` or spaces")
	}

	// The target account is a NAME the server looks up. An account pubkey is the single most
	// likely mistake here (ADR-26's wording invites it) and it fails at connection time with an
	// error that does not mention the cause, so it is caught at startup.
	if c.ServerMode == ServerModeConfig && looksLikeAccountPubKey(c.TargetAccount) {
		return fmt.Errorf("config: CALLOUT_TARGET_ACCOUNT must be the account NAME, not its public key (%q looks like a pubkey; the server resolves the placement by name)", c.TargetAccount)
	}

	return nil
}

// looksLikeAccountPubKey reports whether value has the shape of an account nkey (`A` + 55
// base32 chars).
func looksLikeAccountPubKey(value string) bool {
	return len(value) == 56 && strings.HasPrefix(value, "A") && !strings.ContainsAny(value, ".*> /\\")
}

// ServerModeIsConfig reports whether the callout serves a config-mode NATS.
func (c *Config) ServerModeIsConfig() bool { return c.ServerMode == ServerModeConfig }

// env reads a variable with a fallback.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
