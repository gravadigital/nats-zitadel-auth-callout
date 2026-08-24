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

// Userinfo enrichment levels. They mirror idp.EnrichMode; config carries strings so this
// package keeps depending on nothing.
const (
	// IDPEnrichNone never calls userinfo: everything comes from the token.
	IDPEnrichNone = "none"
	// IDPEnrichUsername calls it only for a token with no username, and takes only that.
	IDPEnrichUsername = "username"
	// IDPEnrichProfile additionally fills the name and the email. It is what an authentication
	// event needs from a provider that keeps them out of access tokens.
	IDPEnrichProfile = "profile"
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

	// IDPEnrich says how much the verifier may ask the provider's userinfo endpoint for, when
	// the token itself does not carry it: `none`, `username` or `profile`.
	//
	// It is a cost, which is why it is a setting: userinfo is an HTTP call on the path that
	// authenticates a connection. It is cached per subject, so the cost is one call per user per
	// cache window rather than one per connection.
	//
	// The default depends on the IdP mode, to keep every existing deployment behaving exactly as
	// it did: `username` for zitadel (machine user tokens carry no username, and a readable name
	// in `nats server report connections` is worth one rare call), `none` for oidc and mock.
	//
	// `profile` is what a deployment publishing authentication events sets: an access token is
	// not an ID token, and Zitadel — among others — keeps `name` and `email` out of it, so
	// userinfo is the only standards-compliant place to get them.
	IDPEnrich string

	// EventsSubject is the subject an authentication event is published to. It is a PATTERN,
	// expanded per event with the same {{placeholders}} permission templates use.
	//
	// It has no default, and empty DISABLES the whole feature. Both halves of that are
	// deliberate: an existing deployment must not start announcing who logs in — with their
	// name and email in the payload — to a subject nobody chose, and a default subject is
	// exactly how that would happen.
	EventsSubject string
	// EventsStream is the JetStream stream that must capture EventsSubject.
	//
	// It is OPTIONAL, and it selects how events are delivered. Set, the publisher publishes to
	// JetStream and waits for the ack: confirmed delivery, and a consumer that was down can read
	// what it missed. Empty, events are ordinary core NATS messages: at most once, to whoever is
	// subscribed at that instant, with nothing to read afterwards.
	EventsStream string
	// EventsNATSURL is the URL the events connection uses. It defaults to NATSURL: the usual
	// case is the same server, a different account.
	EventsNATSURL string
	// The events connection's own credentials. It is a SECOND connection, in the account where
	// the consumers live — the callout's handler connects in the AUTH account, whose subject
	// namespace application clients cannot see. Exactly one form, like the handler's.
	EventsCreds    string
	EventsUser     string
	EventsPassword string
	EventsNKeySeed string
	// EventsNameClaim and EventsEmailClaim are the claim paths the event's name and email are
	// read from. Empty means the OIDC standard names (`name`, `email`).
	EventsNameClaim  string
	EventsEmailClaim string

	// LogLevel is the log level (debug, info, warn, error).
	LogLevel string
}

// Load assembles the Config and validates it.
//
// Three layers, each overriding the one before it:
//
//	built-in defaults  <-  the file at CALLOUT_CONFIG_FILE (optional)  <-  the environment
//
// The environment always wins, with no per-key exceptions. Secrets come from the environment
// only; a file that sets one is refused (see ErrSecretInFile).
func Load() (*Config, error) {
	cfg, _, err := load()
	return cfg, err
}

// LoadWithSource behaves like Load and additionally reports which file was read and which of its
// keys the environment overrode, for the service to log at startup.
func LoadWithSource() (cfg *Config, file string, overridden []string, err error) {
	c, src, err := load()
	if err != nil {
		return nil, "", nil, err
	}
	return c, src.path, src.overridden, nil
}

// source records where the configuration came from, for reporting.
type source struct {
	path       string
	overridden []string
}

func load() (*Config, source, error) {
	// Layer 1: the defaults. Operator mode keeps existing deployments working with no new
	// variable; mock IdP is the one that cannot silently be mistaken for a real one, because the
	// service warns loudly about it on every startup.
	cfg := &Config{
		NATSURL:           "nats://127.0.0.1:4222",
		ServerMode:        ServerModeOperator,
		IDPMode:           IDPModeMock,
		OIDCUsernameClaim: "preferred_username",
		InboxMode:         InboxModeHashed,
		LogLevel:          "info",
		// RulesPath has NO default on purpose: defaulting to the bundled example means a
		// deployment that forgets to mount its own configuration starts and serves example roles
		// instead of failing. Requiring it turns that into a startup error naming the setting.
	}

	var src source

	// Layer 2: the file, when one is configured.
	if path := os.Getenv(FileEnvVar); path != "" {
		file, err := LoadFile(path)
		if err != nil {
			return nil, src, err
		}
		file.applyTo(cfg)
		src.path = path
		src.overridden = file.overriddenBy(envIsSet)
	}

	// Layer 3: the environment.
	envOverride(&cfg.NATSURL, "CALLOUT_NATS_URL")
	envOverride(&cfg.ServerMode, "CALLOUT_SERVER_MODE")
	envOverride(&cfg.HandlerCreds, "CALLOUT_HANDLER_CREDS")
	envOverride(&cfg.HandlerUser, "CALLOUT_HANDLER_USER")
	envOverride(&cfg.HandlerPassword, "CALLOUT_HANDLER_PASSWORD")
	envOverride(&cfg.HandlerNKeySeed, "CALLOUT_HANDLER_NKEY_SEED")
	envOverride(&cfg.AppAccountSigningKeySeed, "CALLOUT_APP_ACCOUNT_SK_SEED")
	envOverride(&cfg.AppAccountPubKey, "CALLOUT_APP_ACCOUNT_PUB")
	envOverride(&cfg.TargetAccount, "CALLOUT_TARGET_ACCOUNT")
	envOverride(&cfg.AuthAccountSigningKeySeed, "CALLOUT_AUTH_ACCOUNT_SK_SEED")
	envOverride(&cfg.XKeySeed, "CALLOUT_XKEY_SEED")
	envOverride(&cfg.RulesPath, "CALLOUT_RULES_PATH")
	envOverride(&cfg.Instance, "CALLOUT_INSTANCE")
	envOverride(&cfg.IDPMode, "CALLOUT_IDP_MODE")
	envOverride(&cfg.ZitadelIssuerURL, "CALLOUT_ZITADEL_ISSUER_URL")
	envOverride(&cfg.ZitadelProjectID, "CALLOUT_ZITADEL_PROJECT_ID")
	envOverride(&cfg.OIDCIssuerURL, "CALLOUT_OIDC_ISSUER_URL")
	envOverride(&cfg.OIDCRolesClaim, "CALLOUT_OIDC_ROLES_CLAIM")
	envOverride(&cfg.OIDCUsernameClaim, "CALLOUT_OIDC_USERNAME_CLAIM")
	envOverride(&cfg.OIDCAudience, "CALLOUT_OIDC_AUDIENCE")
	envOverride(&cfg.IDPEnrich, "CALLOUT_IDP_ENRICH")
	envOverride(&cfg.InboxMode, "CALLOUT_INBOX_MODE")
	envOverride(&cfg.EventsSubject, "CALLOUT_EVENTS_SUBJECT")
	envOverride(&cfg.EventsStream, "CALLOUT_EVENTS_STREAM")
	envOverride(&cfg.EventsNATSURL, "CALLOUT_EVENTS_URL")
	envOverride(&cfg.EventsCreds, "CALLOUT_EVENTS_CREDS")
	envOverride(&cfg.EventsUser, "CALLOUT_EVENTS_USER")
	envOverride(&cfg.EventsPassword, "CALLOUT_EVENTS_PASSWORD")
	envOverride(&cfg.EventsNKeySeed, "CALLOUT_EVENTS_NKEY_SEED")
	envOverride(&cfg.EventsNameClaim, "CALLOUT_EVENTS_NAME_CLAIM")
	envOverride(&cfg.EventsEmailClaim, "CALLOUT_EVENTS_EMAIL_CLAIM")
	envOverride(&cfg.LogLevel, "CALLOUT_LOG_LEVEL")

	// The enrichment default depends on the IdP mode, so it can only be decided once every source
	// has been read. Both values reproduce exactly what the service did before the setting
	// existed, so no deployment changes behaviour by upgrading.
	if cfg.IDPEnrich == "" {
		if cfg.IDPMode == IDPModeZitadel {
			cfg.IDPEnrich = IDPEnrichUsername
		} else {
			cfg.IDPEnrich = IDPEnrichNone
		}
	}

	// The events connection almost always goes to the same server as the callout's own, just
	// into a different account. Defaulting it keeps the common case to one setting, and an
	// explicit value still wins for the deployment whose accounts live on separate clusters.
	if cfg.EventsSubject != "" && cfg.EventsNATSURL == "" {
		cfg.EventsNATSURL = cfg.NATSURL
	}

	if err := cfg.validate(); err != nil {
		return nil, src, err
	}
	return cfg, src, nil
}

// envOverride replaces dst when the variable is SET, even to an empty string.
//
// Honouring an explicit empty value matters once a file is in play: it is how a deployment turns
// off something the file enables — `CALLOUT_ZITADEL_PROJECT_ID=` to widen role reading, say —
// and treating that as "unset" would make the setting impossible to clear without editing the
// file the deployment may not own.
func envOverride(dst *string, name string) {
	if value, ok := os.LookupEnv(name); ok {
		*dst = value
	}
}

// envIsSet reports whether a variable is present, empty or not.
func envIsSet(name string) bool {
	_, ok := os.LookupEnv(name)
	return ok
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

	// This one is a secret, so it has no file key: naming one would invite writing it there.
	require("CALLOUT_APP_ACCOUNT_SK_SEED", c.AppAccountSigningKeySeed)
	require(setting("CALLOUT_RULES_PATH", "permissions.rules_path"), c.RulesPath)

	// The signing key is the only key both modes share; everything else is per-mode.
	switch c.ServerMode {
	case ServerModeOperator:
		require(setting("CALLOUT_APP_ACCOUNT_PUB", "server.app_account_pub"), c.AppAccountPubKey)
		require("CALLOUT_AUTH_ACCOUNT_SK_SEED", c.AuthAccountSigningKeySeed)
		reject(setting("CALLOUT_TARGET_ACCOUNT", "server.target_account"), c.TargetAccount,
			"operator mode places users by issuer-account pubkey, not by account name")
	case ServerModeConfig:
		require(setting("CALLOUT_TARGET_ACCOUNT", "server.target_account"), c.TargetAccount)
		reject(setting("CALLOUT_APP_ACCOUNT_PUB", "server.app_account_pub"), c.AppAccountPubKey,
			"a config-mode server rejects a User JWT carrying issuer_account")
		reject("CALLOUT_AUTH_ACCOUNT_SK_SEED", c.AuthAccountSigningKeySeed,
			"config mode signs both the User JWT and the response with CALLOUT_APP_ACCOUNT_SK_SEED")
	default:
		return fmt.Errorf("config: invalid server mode %q from %s (expected %s or %s)",
			c.ServerMode, setting("CALLOUT_SERVER_MODE", "server.mode"), ServerModeOperator, ServerModeConfig)
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
		require(setting("CALLOUT_ZITADEL_ISSUER_URL", "idp.issuer_url"), c.ZitadelIssuerURL)
	case IDPModeOIDC:
		require(setting("CALLOUT_OIDC_ISSUER_URL", "idp.issuer_url"), c.OIDCIssuerURL)
		// There is no cross-provider convention for where roles live, so this cannot be
		// defaulted: guessing would silently authorize with an empty role list, and an empty
		// role list means no rule matches and every connection is refused.
		require(setting("CALLOUT_OIDC_ROLES_CLAIM", "idp.roles_claim"), c.OIDCRolesClaim)
	case IDPModeMock:
	default:
		return fmt.Errorf("config: invalid IdP mode %q from %s (expected %s, %s or %s)",
			c.IDPMode, setting("CALLOUT_IDP_MODE", "idp.mode"), IDPModeZitadel, IDPModeOIDC, IDPModeMock)
	}

	switch c.IDPEnrich {
	case IDPEnrichNone, IDPEnrichUsername, IDPEnrichProfile:
	default:
		return fmt.Errorf("config: invalid userinfo enrichment %q from %s (expected %s, %s or %s)",
			c.IDPEnrich, setting("CALLOUT_IDP_ENRICH", "idp.enrich"),
			IDPEnrichNone, IDPEnrichUsername, IDPEnrichProfile)
	}

	switch c.InboxMode {
	case InboxModeHashed, InboxModePassthrough:
	default:
		return fmt.Errorf("config: invalid inbox mode %q from %s (expected %s or %s)",
			c.InboxMode, setting("CALLOUT_INBOX_MODE", "permissions.inbox_mode"), InboxModeHashed, InboxModePassthrough)
	}

	// --- Authentication events -------------------------------------------------------------
	//
	// The whole feature hangs off ONE setting, the subject. Everything else here is meaningless
	// without it, so a value set while the subject is not is REFUSED rather than ignored: a
	// deployment that configured a stream and a credential and then saw no events would have
	// nothing to go on.
	var eventsOff []string
	offender := func(name, value string) {
		if value != "" {
			eventsOff = append(eventsOff, name)
		}
	}
	if c.EventsSubject == "" {
		offender(setting("CALLOUT_EVENTS_STREAM", "events.stream"), c.EventsStream)
		offender(setting("CALLOUT_EVENTS_URL", "events.url"), c.EventsNATSURL)
		offender(setting("CALLOUT_EVENTS_USER", "events.user"), c.EventsUser)
		offender("CALLOUT_EVENTS_PASSWORD", c.EventsPassword)
		offender("CALLOUT_EVENTS_CREDS", c.EventsCreds)
		offender("CALLOUT_EVENTS_NKEY_SEED", c.EventsNKeySeed)
		offender(setting("CALLOUT_EVENTS_NAME_CLAIM", "events.name_claim"), c.EventsNameClaim)
		offender(setting("CALLOUT_EVENTS_EMAIL_CLAIM", "events.email_claim"), c.EventsEmailClaim)
	} else {
		// The stream is deliberately NOT required. It selects the delivery mode: with one, each
		// event is acked by JetStream and readable later; without one, the event is an ordinary
		// core NATS message that only whoever is subscribed at that instant receives. Both are
		// legitimate, so neither is imposed — and the service says which one it is running on its
		// startup line, because that difference is invisible from the outside.

		// The events connection is a SECOND connection, in the account where the consumers are.
		// Its credential is separate from the handler's on purpose: the handler's account cannot
		// see the application's subject namespace, and this one only ever needs to publish.
		eventForms := 0
		if c.EventsCreds != "" {
			eventForms++
		}
		if c.EventsUser != "" || c.EventsPassword != "" {
			eventForms++
		}
		if c.EventsNKeySeed != "" {
			eventForms++
		}
		switch {
		case eventForms == 0:
			missing = append(missing, "one of CALLOUT_EVENTS_CREDS, CALLOUT_EVENTS_USER+CALLOUT_EVENTS_PASSWORD or CALLOUT_EVENTS_NKEY_SEED")
		case eventForms > 1:
			return errors.New("config: more than one events credential form is set; keep exactly one of CALLOUT_EVENTS_CREDS, CALLOUT_EVENTS_USER+CALLOUT_EVENTS_PASSWORD or CALLOUT_EVENTS_NKEY_SEED")
		case c.EventsUser != "" && c.EventsPassword == "":
			missing = append(missing, "CALLOUT_EVENTS_PASSWORD")
		case c.EventsPassword != "" && c.EventsUser == "":
			missing = append(missing, "CALLOUT_EVENTS_USER")
		}
	}

	if len(eventsOff) > 0 {
		return fmt.Errorf("config: the authentication event publisher is OFF (%s is not set) but these are configured, so nothing would read them: %s",
			setting("CALLOUT_EVENTS_SUBJECT", "events.subject"), strings.Join(eventsOff, ", "))
	}

	if len(unexpected) > 0 {
		return fmt.Errorf("config: settings that do not apply to server mode %q: %s",
			c.ServerMode, strings.Join(unexpected, ", "))
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: missing settings: %s", strings.Join(missing, ", "))
	}

	// The instance is a subject token: a dot or a wildcard would break it in a way that is hard
	// to diagnose (the permissions would be shifted by one segment). Empty is allowed — it just
	// means templates must not reference {{instance}}.
	if strings.ContainsAny(c.Instance, ".*> ") {
		return fmt.Errorf("config: the instance cannot contain `.`, `*`, `>` or spaces (%s)",
			setting("CALLOUT_INSTANCE", "permissions.instance"))
	}

	// The target account is a NAME the server looks up. An account pubkey is the single most
	// likely mistake here (ADR-26's wording invites it) and it fails at connection time with an
	// error that does not mention the cause, so it is caught at startup.
	if c.ServerMode == ServerModeConfig && looksLikeAccountPubKey(c.TargetAccount) {
		return fmt.Errorf("config: the target account must be the account NAME, not its public key (%q looks like a pubkey; the server resolves the placement by name) — %s",
			c.TargetAccount, setting("CALLOUT_TARGET_ACCOUNT", "server.target_account"))
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
// setting names a configuration value in BOTH forms, because a deployment may be using either
// and an error that names only one sends the reader to a file they do not have.
func setting(envVar, fileKey string) string {
	return fmt.Sprintf("%s (or %s in the configuration file)", envVar, fileKey)
}
