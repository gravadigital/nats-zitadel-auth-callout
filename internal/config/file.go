package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file adds an optional configuration FILE alongside the environment.
//
// Why a file at all, when environment variables already work: eleven of the service's
// validations are per-mode, so which settings apply depends on `server.mode` and `idp.mode`. A
// flat list of variables cannot express that — CALLOUT_TARGET_ACCOUNT gives no hint that it is
// config-mode only — whereas nesting them under the mode that owns them makes the structure
// itself the documentation. Put the operator-mode and config-mode files side by side and the
// difference between the two topologies is visible at a glance.
//
// Two rules keep it from becoming another thing to reason about:
//
//   - The environment ALWAYS wins. No exceptions, no per-key special cases: one rule nobody has
//     to memorise, and the one every deployment tool assumes.
//   - Secrets NEVER go in the file. A seed or a password in a YAML file is a seed in version
//     control eventually, so finding one is a startup error rather than a warning.

// FileEnvVar names the configuration file. It is itself an environment variable because
// something has to bootstrap the file's own location.
const FileEnvVar = "CALLOUT_CONFIG_FILE"

// ErrSecretInFile flags a secret written into the configuration file.
//
// It is refused rather than accepted-with-a-warning because the failure mode is not a
// misconfiguration, it is a leak: the file gets committed, and the seeds that sign every User
// JWT this deployment mints go with it.
var ErrSecretInFile = errors.New("config: secrets must not appear in the configuration file")

// File is the shape of the configuration file.
//
// The grouping mirrors the decisions a deployment actually makes — what NATS looks like, who
// issues identity, what permissions to apply — rather than the flat variable list, so that
// reading the file tells you which settings belong to which mode.
type File struct {
	Server      FileServer      `yaml:"server"`
	IDP         FileIDP         `yaml:"idp"`
	Permissions FilePermissions `yaml:"permissions"`
	Events      FileEvents      `yaml:"events"`
	Log         FileLog         `yaml:"log"`
}

// FileServer describes the NATS being served.
type FileServer struct {
	// Mode is operator or config. Everything else in this section depends on it.
	Mode string `yaml:"mode"`
	// URL is the NATS URL.
	URL string `yaml:"url"`
	// AppAccountPub is the target account's PUBLIC KEY. Operator mode only.
	AppAccountPub string `yaml:"app_account_pub"`
	// TargetAccount is the target account's NAME. Config mode only.
	TargetAccount string `yaml:"target_account"`
	// Handler is the non-secret half of the callout's own credentials.
	Handler FileHandler `yaml:"handler"`
}

// FileHandler carries what is safe to write down about the handler's connection.
//
// The user name belongs here; the password and the seeds do not, and a file that sets them is
// rejected. That split is why this is a struct rather than a single string.
type FileHandler struct {
	// User is the handler's user name (config mode, user/password form).
	User string `yaml:"user"`

	// The remaining fields exist ONLY so that writing a secret here is caught and named. They
	// are never read into the Config.
	Password string `yaml:"password"`
	Creds    string `yaml:"creds"`
	NKeySeed string `yaml:"nkey_seed"`
}

// FileIDP describes the identity provider.
type FileIDP struct {
	// Mode is zitadel, oidc or mock.
	Mode string `yaml:"mode"`
	// IssuerURL is the provider's URL. It is ONE key for both zitadel and oidc modes: the mode
	// already says which verifier reads it, so two separate keys would only invite setting the
	// wrong one.
	IssuerURL string `yaml:"issuer_url"`
	// ProjectID narrows role reading to one project (zitadel mode).
	ProjectID string `yaml:"project_id"`
	// RolesClaim is the claim path roles are read from (oidc mode).
	RolesClaim string `yaml:"roles_claim"`
	// UsernameClaim is the claim carrying the human-readable name (oidc mode).
	UsernameClaim string `yaml:"username_claim"`
	// Audience additionally requires the token's `aud` to contain this value (oidc mode).
	Audience string `yaml:"audience"`
}

// FilePermissions describes how permissions are derived.
type FilePermissions struct {
	// RulesPath is the path to rules.yaml. Templates resolve relative to its directory.
	RulesPath string `yaml:"rules_path"`
	// Instance is the {{instance}} placeholder's value. Optional.
	Instance string `yaml:"instance"`
	// InboxMode is hashed or passthrough.
	InboxMode string `yaml:"inbox_mode"`
}

// FileEvents describes the authentication event publisher.
//
// The whole section is optional and the subject is what turns it on. It gets its own section
// rather than living under `server` because it describes a SECOND connection, to a different
// account, with its own credential: nesting it under the server that is being served would
// suggest they are the same connection, which is the one misunderstanding that costs a
// deployment an afternoon here.
type FileEvents struct {
	// Subject is the subject pattern events are published to. Empty (or absent) means the
	// publisher is off.
	Subject string `yaml:"subject"`
	// Stream is the JetStream stream that has to capture Subject.
	Stream string `yaml:"stream"`
	// URL is the NATS URL for the events connection. Defaults to server.url.
	URL string `yaml:"url"`
	// User is the events connection's user name (user/password form).
	User string `yaml:"user"`
	// NameClaim and EmailClaim are the claim paths the name and the email are read from.
	// Default to the OIDC standard `name` and `email`.
	NameClaim  string `yaml:"name_claim"`
	EmailClaim string `yaml:"email_claim"`

	// As in FileHandler, these exist ONLY so that writing a secret here is caught and named.
	// They are never read into the Config.
	Password string `yaml:"password"`
	Creds    string `yaml:"creds"`
	NKeySeed string `yaml:"nkey_seed"`
}

// FileLog holds logging settings.
type FileLog struct {
	Level string `yaml:"level"`
}

// secretFields lists every place in the file that must stay empty, with the variable to use
// instead. Keeping it as data means the error can name all of them at once instead of stopping
// at the first.
func (f *File) secretFields() []struct{ where, useInstead, value string } {
	return []struct{ where, useInstead, value string }{
		{"server.handler.password", "CALLOUT_HANDLER_PASSWORD", f.Server.Handler.Password},
		{"server.handler.creds", "CALLOUT_HANDLER_CREDS", f.Server.Handler.Creds},
		{"server.handler.nkey_seed", "CALLOUT_HANDLER_NKEY_SEED", f.Server.Handler.NKeySeed},
		{"events.password", "CALLOUT_EVENTS_PASSWORD", f.Events.Password},
		{"events.creds", "CALLOUT_EVENTS_CREDS", f.Events.Creds},
		{"events.nkey_seed", "CALLOUT_EVENTS_NKEY_SEED", f.Events.NKeySeed},
	}
}

// LoadFile reads and parses a configuration file.
//
// Unknown keys are rejected: a typo in an authorization component's configuration would
// otherwise be silently ignored, leaving the deployment running with a default nobody chose.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	var file File
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		// An empty file is valid: it means "configure everything through the environment".
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config: parse %q: %w", path, err)
		}
	}

	var found []string
	for _, field := range file.secretFields() {
		if field.value != "" {
			found = append(found, fmt.Sprintf("%s (use %s instead)", field.where, field.useInstead))
		}
	}
	if len(found) > 0 {
		return nil, fmt.Errorf("%w: %q sets %s", ErrSecretInFile, path, strings.Join(found, ", "))
	}

	return &file, nil
}

// applyTo copies the file's values into cfg, and reports which of them the environment
// subsequently overrides.
//
// It runs BEFORE the environment is read, so every value here is a default that the environment
// is free to replace. The returned list is only for logging: a deployment setting the same thing
// in both places is not an error, but it is worth being able to see which one won.
func (f *File) applyTo(cfg *Config) {
	set := func(dst *string, value string) {
		if value != "" {
			*dst = value
		}
	}

	set(&cfg.ServerMode, f.Server.Mode)
	set(&cfg.NATSURL, f.Server.URL)
	set(&cfg.AppAccountPubKey, f.Server.AppAccountPub)
	set(&cfg.TargetAccount, f.Server.TargetAccount)
	set(&cfg.HandlerUser, f.Server.Handler.User)

	set(&cfg.IDPMode, f.IDP.Mode)
	// One key feeds both verifiers; validate() then requires whichever the selected mode needs.
	set(&cfg.ZitadelIssuerURL, f.IDP.IssuerURL)
	set(&cfg.OIDCIssuerURL, f.IDP.IssuerURL)
	set(&cfg.ZitadelProjectID, f.IDP.ProjectID)
	set(&cfg.OIDCRolesClaim, f.IDP.RolesClaim)
	set(&cfg.OIDCUsernameClaim, f.IDP.UsernameClaim)
	set(&cfg.OIDCAudience, f.IDP.Audience)

	set(&cfg.RulesPath, f.Permissions.RulesPath)
	set(&cfg.Instance, f.Permissions.Instance)
	set(&cfg.InboxMode, f.Permissions.InboxMode)

	set(&cfg.EventsSubject, f.Events.Subject)
	set(&cfg.EventsStream, f.Events.Stream)
	set(&cfg.EventsNATSURL, f.Events.URL)
	set(&cfg.EventsUser, f.Events.User)
	set(&cfg.EventsNameClaim, f.Events.NameClaim)
	set(&cfg.EventsEmailClaim, f.Events.EmailClaim)

	set(&cfg.LogLevel, f.Log.Level)
}

// overriddenBy lists the file keys the environment replaced, so startup can report them.
//
// Worth surfacing because "I changed the file and nothing happened" is otherwise a genuinely
// confusing afternoon: the value is there, it is just losing to a variable somebody set months
// ago in a deployment manifest.
func (f *File) overriddenBy(envSet func(string) bool) []string {
	pairs := []struct{ key, envVar, value string }{
		{"server.mode", "CALLOUT_SERVER_MODE", f.Server.Mode},
		{"server.url", "CALLOUT_NATS_URL", f.Server.URL},
		{"server.app_account_pub", "CALLOUT_APP_ACCOUNT_PUB", f.Server.AppAccountPub},
		{"server.target_account", "CALLOUT_TARGET_ACCOUNT", f.Server.TargetAccount},
		{"server.handler.user", "CALLOUT_HANDLER_USER", f.Server.Handler.User},
		{"idp.mode", "CALLOUT_IDP_MODE", f.IDP.Mode},
		{"idp.issuer_url", "CALLOUT_ZITADEL_ISSUER_URL", f.IDP.IssuerURL},
		{"idp.issuer_url", "CALLOUT_OIDC_ISSUER_URL", f.IDP.IssuerURL},
		{"idp.project_id", "CALLOUT_ZITADEL_PROJECT_ID", f.IDP.ProjectID},
		{"idp.roles_claim", "CALLOUT_OIDC_ROLES_CLAIM", f.IDP.RolesClaim},
		{"idp.username_claim", "CALLOUT_OIDC_USERNAME_CLAIM", f.IDP.UsernameClaim},
		{"idp.audience", "CALLOUT_OIDC_AUDIENCE", f.IDP.Audience},
		{"permissions.rules_path", "CALLOUT_RULES_PATH", f.Permissions.RulesPath},
		{"permissions.instance", "CALLOUT_INSTANCE", f.Permissions.Instance},
		{"permissions.inbox_mode", "CALLOUT_INBOX_MODE", f.Permissions.InboxMode},
		{"events.subject", "CALLOUT_EVENTS_SUBJECT", f.Events.Subject},
		{"events.stream", "CALLOUT_EVENTS_STREAM", f.Events.Stream},
		{"events.url", "CALLOUT_EVENTS_URL", f.Events.URL},
		{"events.user", "CALLOUT_EVENTS_USER", f.Events.User},
		{"events.name_claim", "CALLOUT_EVENTS_NAME_CLAIM", f.Events.NameClaim},
		{"events.email_claim", "CALLOUT_EVENTS_EMAIL_CLAIM", f.Events.EmailClaim},
		{"log.level", "CALLOUT_LOG_LEVEL", f.Log.Level},
	}

	var out []string
	for _, p := range pairs {
		if p.value != "" && envSet(p.envVar) {
			out = append(out, fmt.Sprintf("%s (overridden by %s)", p.key, p.envVar))
		}
	}
	return out
}
