package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The configuration file is optional and layered under the environment. What these tests pin is
// the part that would be expensive to get wrong: which source wins, and that secrets cannot be
// written into a file that will end up in version control.

// writeFile writes a configuration file and returns its path.
func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "callout.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

// loadWithFile runs Load with a configuration file plus the given environment.
func loadWithFile(t *testing.T, body string, env map[string]string) (*Config, error) {
	t.Helper()
	withFile := map[string]string{FileEnvVar: writeFile(t, body)}
	for k, v := range env {
		withFile[k] = v
	}
	return loadWith(t, withFile)
}

// operatorFile is a complete operator-mode file. Only the secrets are missing, because they can
// only come from the environment.
const operatorFile = `
server:
  mode: operator
  url: nats://nats.internal:4222
  app_account_pub: ABACLEQRISCUB7DI5MZRJWCA4CHNULUFGW234IKWX3JCWDHUIUPALEQU
idp:
  mode: zitadel
  issuer_url: https://id.example.com
  project_id: "200000000000000002"
permissions:
  rules_path: /etc/auth-callout/rules.yaml
  instance: prod
  inbox_mode: hashed
log:
  level: debug
`

// TestFileConfiguresEverythingButSecrets is the shape the documentation promises: a complete
// deployment described in a file, with only the secrets in the environment.
func TestFileConfiguresEverythingButSecrets(t *testing.T) {
	cfg, err := loadWithFile(t, operatorFile, map[string]string{
		"CALLOUT_HANDLER_CREDS":        "/run/secrets/handler.creds",
		"CALLOUT_APP_ACCOUNT_SK_SEED":  "/run/secrets/app.seed",
		"CALLOUT_AUTH_ACCOUNT_SK_SEED": "/run/secrets/auth.seed",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, c := range []struct{ name, got, want string }{
		{"server mode", cfg.ServerMode, ServerModeOperator},
		{"url", cfg.NATSURL, "nats://nats.internal:4222"},
		{"app account pub", cfg.AppAccountPubKey, "ABACLEQRISCUB7DI5MZRJWCA4CHNULUFGW234IKWX3JCWDHUIUPALEQU"},
		{"idp mode", cfg.IDPMode, IDPModeZitadel},
		{"issuer", cfg.ZitadelIssuerURL, "https://id.example.com"},
		{"project", cfg.ZitadelProjectID, "200000000000000002"},
		{"rules path", cfg.RulesPath, "/etc/auth-callout/rules.yaml"},
		{"instance", cfg.Instance, "prod"},
		{"inbox mode", cfg.InboxMode, InboxModeHashed},
		{"log level", cfg.LogLevel, "debug"},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestEnvironmentOverridesFile pins the precedence rule. It is the single most important
// behaviour here, because a deployment that believes the file wins would be running with
// settings it cannot see in the file it is reading.
func TestEnvironmentOverridesFile(t *testing.T) {
	cfg, err := loadWithFile(t, operatorFile, map[string]string{
		"CALLOUT_HANDLER_CREDS":        "/run/secrets/handler.creds",
		"CALLOUT_APP_ACCOUNT_SK_SEED":  "SAAAA",
		"CALLOUT_AUTH_ACCOUNT_SK_SEED": "SBBBB",
		"CALLOUT_NATS_URL":             "nats://override:4222",
		"CALLOUT_INSTANCE":             "staging",
		"CALLOUT_LOG_LEVEL":            "warn",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.NATSURL != "nats://override:4222" {
		t.Errorf("the environment must win: got %q", cfg.NATSURL)
	}
	if cfg.Instance != "staging" {
		t.Errorf("the environment must win: got %q", cfg.Instance)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("the environment must win: got %q", cfg.LogLevel)
	}
	// Everything it did not mention still comes from the file.
	if cfg.RulesPath != "/etc/auth-callout/rules.yaml" {
		t.Errorf("unset variables must leave the file's value: got %q", cfg.RulesPath)
	}
}

// TestEmptyEnvironmentVariableClearsFileValue covers the case that makes "the environment always
// wins" a real rule rather than an approximation: setting a variable to empty has to CLEAR what
// the file set. Otherwise a deployment cannot turn off a setting in a file it does not own.
func TestEmptyEnvironmentVariableClearsFileValue(t *testing.T) {
	cfg, err := loadWithFile(t, operatorFile, map[string]string{
		"CALLOUT_HANDLER_CREDS":        "/run/secrets/handler.creds",
		"CALLOUT_APP_ACCOUNT_SK_SEED":  "SAAAA",
		"CALLOUT_AUTH_ACCOUNT_SK_SEED": "SBBBB",
		// Widen role reading to every project in the token, despite the file naming one.
		"CALLOUT_ZITADEL_PROJECT_ID": "",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ZitadelProjectID != "" {
		t.Fatalf("an empty variable must clear the file's value, got %q", cfg.ZitadelProjectID)
	}
}

// TestSecretsInFileAreRejected is the other rule worth pinning. A seed in a YAML file is a seed
// in version control eventually, so this fails rather than warns.
func TestSecretsInFileAreRejected(t *testing.T) {
	for name, body := range map[string]string{
		"password":  "server:\n  handler:\n    password: hunter2\n",
		"creds":     "server:\n  handler:\n    creds: /etc/handler.creds\n",
		"nkey seed": "server:\n  handler:\n    nkey_seed: SUAAAAA\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadWithFile(t, body, nil)
			if !errors.Is(err, ErrSecretInFile) {
				t.Fatalf("expected ErrSecretInFile, got: %v", err)
			}
			// The error has to say where to put it instead, or it only says "no".
			if !strings.Contains(err.Error(), "CALLOUT_") {
				t.Fatalf("the error should name the variable to use instead, got: %v", err)
			}
		})
	}
}

// TestHandlerUserIsNotASecret: the user name is safe to write down, and the password is not.
// Splitting them is what lets a file describe the deployment fully without holding a secret.
func TestHandlerUserIsNotASecret(t *testing.T) {
	body := `
server:
  mode: config
  target_account: APP
  handler:
    user: callout-handler
idp:
  mode: mock
permissions:
  rules_path: /etc/auth-callout/rules.yaml
`
	cfg, err := loadWithFile(t, body, map[string]string{
		"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
		"CALLOUT_HANDLER_PASSWORD":    "hunter2",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HandlerUser != "callout-handler" || cfg.HandlerPassword != "hunter2" {
		t.Fatalf("got user=%q password set=%v", cfg.HandlerUser, cfg.HandlerPassword != "")
	}
}

// TestUnknownKeyInFileIsRejected: an ignored typo would leave the deployment running with a
// default nobody chose, which is the same failure the rules and template loaders already refuse.
func TestUnknownKeyInFileIsRejected(t *testing.T) {
	_, err := loadWithFile(t, "server:\n  moed: operator\n", nil)
	if err == nil {
		t.Fatal("an unknown key should fail")
	}
	if !strings.Contains(err.Error(), "moed") {
		t.Fatalf("the error should name the unknown key, got: %v", err)
	}
}

// TestPerModeValidationStillAppliesToFileValues: the file is a different SOURCE, not a different
// set of rules. A setting the mode does not read is still an error when it comes from the file.
func TestPerModeValidationStillAppliesToFileValues(t *testing.T) {
	body := `
server:
  mode: config
  target_account: APP
  app_account_pub: ABACLEQRISCUB7DI5MZRJWCA4CHNULUFGW234IKWX3JCWDHUIUPALEQU
idp:
  mode: mock
permissions:
  rules_path: /etc/auth-callout/rules.yaml
`
	_, err := loadWithFile(t, body, map[string]string{
		"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
		"CALLOUT_HANDLER_USER":        "h",
		"CALLOUT_HANDLER_PASSWORD":    "p",
	})
	if err == nil {
		t.Fatal("app_account_pub does not apply to config mode and should be rejected")
	}
	// The message has to name the file key, since that is where the reader will look.
	if !strings.Contains(err.Error(), "server.app_account_pub") {
		t.Fatalf("the error should name the file key, got: %v", err)
	}
}

// TestMissingFileIsAnError: a deployment that points at a file it cannot read is misconfigured.
// Carrying on with the environment alone would start it with defaults nobody intended.
func TestMissingFileIsAnError(t *testing.T) {
	_, err := loadWith(t, map[string]string{FileEnvVar: "/nonexistent/callout.yaml"})
	if err == nil {
		t.Fatal("an unreadable configuration file should fail")
	}
	if !strings.Contains(err.Error(), "/nonexistent/callout.yaml") {
		t.Fatalf("the error should name the file, got: %v", err)
	}
}

// TestNoFileStillWorks: the file is optional, and every existing deployment configures
// everything through the environment.
func TestNoFileStillWorks(t *testing.T) {
	if _, err := loadWith(t, baseEnv()); err != nil {
		t.Fatalf("the environment alone must still work: %v", err)
	}
}

// TestOverriddenKeysAreReported: "I changed the file and nothing happened" is a confusing
// afternoon, so startup can say which keys lost to a variable.
func TestOverriddenKeysAreReported(t *testing.T) {
	path := writeFile(t, operatorFile)
	_, file, overridden, err := loadWithSourceIn(t, map[string]string{
		FileEnvVar:                     path,
		"CALLOUT_HANDLER_CREDS":        "/run/secrets/handler.creds",
		"CALLOUT_APP_ACCOUNT_SK_SEED":  "SAAAA",
		"CALLOUT_AUTH_ACCOUNT_SK_SEED": "SBBBB",
		"CALLOUT_NATS_URL":             "nats://override:4222",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if file != path {
		t.Errorf("the source file should be reported, got %q", file)
	}
	if len(overridden) != 1 || !strings.Contains(overridden[0], "server.url") {
		t.Fatalf("expected server.url to be reported as overridden, got %v", overridden)
	}
}
