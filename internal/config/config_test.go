package config

import (
	"os"
	"strings"
	"testing"
)

// Config validation is where a reusable service either helps or hinders: the whole point of
// per-mode validation is that a deployment is told, at startup, which variables its mode
// actually reads. These tests pin that behavior.

// baseEnv is a minimal valid operator-mode environment.
func baseEnv() map[string]string {
	return map[string]string{
		"CALLOUT_SERVER_MODE":          ServerModeOperator,
		"CALLOUT_HANDLER_CREDS":        "/tmp/handler.creds",
		"CALLOUT_APP_ACCOUNT_SK_SEED":  "SAAAA",
		"CALLOUT_APP_ACCOUNT_PUB":      "AAAAA",
		"CALLOUT_AUTH_ACCOUNT_SK_SEED": "SBBBB",
		"CALLOUT_RULES_PATH":           "examples/rules.yaml",
	}
}

// loadWith runs Load with exactly the given environment.
func loadWith(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	// Clear every variable this package reads, so a test never inherits the developer's shell.
	for _, name := range []string{
		"CALLOUT_NATS_URL", "CALLOUT_SERVER_MODE", "CALLOUT_HANDLER_CREDS",
		"CALLOUT_HANDLER_USER", "CALLOUT_HANDLER_PASSWORD", "CALLOUT_HANDLER_NKEY_SEED",
		"CALLOUT_APP_ACCOUNT_SK_SEED", "CALLOUT_APP_ACCOUNT_PUB", "CALLOUT_TARGET_ACCOUNT",
		"CALLOUT_AUTH_ACCOUNT_SK_SEED", "CALLOUT_XKEY_SEED", "CALLOUT_RULES_PATH",
		"CALLOUT_INSTANCE", "CALLOUT_IDP_MODE", "CALLOUT_ZITADEL_ISSUER_URL",
		"CALLOUT_ZITADEL_PROJECT_ID", "CALLOUT_OIDC_ISSUER_URL", "CALLOUT_OIDC_ROLES_CLAIM",
		"CALLOUT_OIDC_USERNAME_CLAIM", "CALLOUT_OIDC_AUDIENCE", "CALLOUT_INBOX_MODE",
		"CALLOUT_IDP_ENRICH",
		"CALLOUT_EVENTS_SUBJECT", "CALLOUT_EVENTS_STREAM", "CALLOUT_EVENTS_URL",
		"CALLOUT_EVENTS_USER", "CALLOUT_EVENTS_PASSWORD", "CALLOUT_EVENTS_CREDS",
		"CALLOUT_EVENTS_NKEY_SEED", "CALLOUT_EVENTS_NAME_CLAIM", "CALLOUT_EVENTS_EMAIL_CLAIM",
		"CALLOUT_LOG_LEVEL",
	} {
		// UNSET rather than set-to-empty. The two are different: an explicitly empty variable is
		// how a deployment clears a value the configuration file set, so it overrides the
		// built-in default instead of falling back to it.
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	// The configuration file is opt-in; no test here should pick up a developer's own.
	t.Setenv(FileEnvVar, "")
	os.Unsetenv(FileEnvVar)
	for name, value := range env {
		t.Setenv(name, value)
	}
	return Load()
}

// loadWithSourceIn is loadWith for the tests that need to see where each value came from.
func loadWithSourceIn(t *testing.T, env map[string]string) (*Config, string, []string, error) {
	t.Helper()
	if _, err := loadWith(t, env); err != nil {
		return nil, "", nil, err
	}
	// loadWith has already put the environment in place, so this reads the same one.
	return LoadWithSource()
}

// TestOperatorModeIsTheDefault pins backward compatibility: an environment written before the
// mode existed must keep working.
func TestOperatorModeIsTheDefault(t *testing.T) {
	env := baseEnv()
	delete(env, "CALLOUT_SERVER_MODE")

	cfg, err := loadWith(t, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ServerMode != ServerModeOperator {
		t.Fatalf("expected default mode %q, got %q", ServerModeOperator, cfg.ServerMode)
	}
}

// TestConfigModeRequiresTargetAccount covers the variable the original proposal missed.
func TestConfigModeRequiresTargetAccount(t *testing.T) {
	env := map[string]string{
		"CALLOUT_SERVER_MODE":         ServerModeConfig,
		"CALLOUT_HANDLER_USER":        "handler",
		"CALLOUT_HANDLER_PASSWORD":    "pass",
		"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
		"CALLOUT_RULES_PATH":          "examples/rules.yaml",
	}

	_, err := loadWith(t, env)
	if err == nil {
		t.Fatal("config mode with no target account should fail")
	}
	if !strings.Contains(err.Error(), "CALLOUT_TARGET_ACCOUNT") {
		t.Fatalf("error should name CALLOUT_TARGET_ACCOUNT, got: %v", err)
	}
}

// TestConfigModeRejectsOperatorOnlyVariables is the "no useless options" guarantee: a variable
// the selected mode never reads is an error, not something silently ignored.
func TestConfigModeRejectsOperatorOnlyVariables(t *testing.T) {
	for _, name := range []string{"CALLOUT_APP_ACCOUNT_PUB", "CALLOUT_AUTH_ACCOUNT_SK_SEED"} {
		t.Run(name, func(t *testing.T) {
			env := map[string]string{
				"CALLOUT_SERVER_MODE":         ServerModeConfig,
				"CALLOUT_HANDLER_USER":        "handler",
				"CALLOUT_HANDLER_PASSWORD":    "pass",
				"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
				"CALLOUT_TARGET_ACCOUNT":      "APP",
				"CALLOUT_RULES_PATH":          "examples/rules.yaml",
				name:                          "something",
			}

			_, err := loadWith(t, env)
			if err == nil {
				t.Fatalf("%s should be rejected in config mode", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("error should name %s, got: %v", name, err)
			}
		})
	}
}

// TestOperatorModeRejectsTargetAccount is the mirror guard.
func TestOperatorModeRejectsTargetAccount(t *testing.T) {
	env := baseEnv()
	env["CALLOUT_TARGET_ACCOUNT"] = "APP"

	_, err := loadWith(t, env)
	if err == nil {
		t.Fatal("CALLOUT_TARGET_ACCOUNT should be rejected in operator mode")
	}
	if !strings.Contains(err.Error(), "CALLOUT_TARGET_ACCOUNT") {
		t.Fatalf("error should name CALLOUT_TARGET_ACCOUNT, got: %v", err)
	}
}

// TestTargetAccountMustBeNameNotPubkey pins issue #4313 at the configuration layer, where the
// mistake is cheap to catch. The alternative is a connection-time failure whose message does
// not mention the cause.
func TestTargetAccountMustBeNameNotPubkey(t *testing.T) {
	// A syntactically plausible account pubkey: `A` + 55 chars.
	pubkey := "A" + strings.Repeat("B", 55)

	env := map[string]string{
		"CALLOUT_SERVER_MODE":         ServerModeConfig,
		"CALLOUT_HANDLER_USER":        "handler",
		"CALLOUT_HANDLER_PASSWORD":    "pass",
		"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
		"CALLOUT_TARGET_ACCOUNT":      pubkey,
		"CALLOUT_RULES_PATH":          "examples/rules.yaml",
	}

	_, err := loadWith(t, env)
	if err == nil {
		t.Fatal("an account pubkey as the target account should be rejected")
	}
	if !strings.Contains(err.Error(), "NAME") {
		t.Fatalf("error should explain that a NAME is required, got: %v", err)
	}
}

// TestHandlerCredentialForms covers the three connection forms and the ambiguity guard.
func TestHandlerCredentialForms(t *testing.T) {
	t.Run("userpass", func(t *testing.T) {
		env := map[string]string{
			"CALLOUT_SERVER_MODE":         ServerModeConfig,
			"CALLOUT_HANDLER_USER":        "handler",
			"CALLOUT_HANDLER_PASSWORD":    "pass",
			"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
			"CALLOUT_TARGET_ACCOUNT":      "APP",
			"CALLOUT_RULES_PATH":          "examples/rules.yaml",
		}
		if _, err := loadWith(t, env); err != nil {
			t.Fatalf("user/password should be accepted: %v", err)
		}
	})

	t.Run("nkey", func(t *testing.T) {
		env := map[string]string{
			"CALLOUT_SERVER_MODE":         ServerModeConfig,
			"CALLOUT_HANDLER_NKEY_SEED":   "SUAAA",
			"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
			"CALLOUT_TARGET_ACCOUNT":      "APP",
			"CALLOUT_RULES_PATH":          "examples/rules.yaml",
		}
		if _, err := loadWith(t, env); err != nil {
			t.Fatalf("nkey should be accepted: %v", err)
		}
	})

	t.Run("none", func(t *testing.T) {
		env := baseEnv()
		delete(env, "CALLOUT_HANDLER_CREDS")

		_, err := loadWith(t, env)
		if err == nil {
			t.Fatal("no handler credentials should fail")
		}
	})

	t.Run("ambiguous", func(t *testing.T) {
		// Two forms set: picking one silently would leave it unclear which credential is in use.
		env := baseEnv()
		env["CALLOUT_HANDLER_USER"] = "handler"
		env["CALLOUT_HANDLER_PASSWORD"] = "pass"

		_, err := loadWith(t, env)
		if err == nil {
			t.Fatal("two handler credential forms should fail")
		}
		if !strings.Contains(err.Error(), "more than one") {
			t.Fatalf("error should flag the ambiguity, got: %v", err)
		}
	})

	t.Run("user without password", func(t *testing.T) {
		env := map[string]string{
			"CALLOUT_SERVER_MODE":         ServerModeConfig,
			"CALLOUT_HANDLER_USER":        "handler",
			"CALLOUT_APP_ACCOUNT_SK_SEED": "SAAAA",
			"CALLOUT_TARGET_ACCOUNT":      "APP",
			"CALLOUT_RULES_PATH":          "examples/rules.yaml",
		}
		_, err := loadWith(t, env)
		if err == nil {
			t.Fatal("a user with no password should fail")
		}
		if !strings.Contains(err.Error(), "CALLOUT_HANDLER_PASSWORD") {
			t.Fatalf("error should name the missing password, got: %v", err)
		}
	})
}

// TestOIDCModeRequiresRolesClaim covers the one thing a generic OIDC deployment cannot default.
func TestOIDCModeRequiresRolesClaim(t *testing.T) {
	env := baseEnv()
	env["CALLOUT_IDP_MODE"] = IDPModeOIDC
	env["CALLOUT_OIDC_ISSUER_URL"] = "https://id.example.test"

	_, err := loadWith(t, env)
	if err == nil {
		t.Fatal("oidc mode with no roles claim should fail")
	}
	if !strings.Contains(err.Error(), "CALLOUT_OIDC_ROLES_CLAIM") {
		t.Fatalf("error should name the roles claim, got: %v", err)
	}
}

// TestInstanceIsOptional pins the change that lets a deployment adopt an existing grammar.
func TestInstanceIsOptional(t *testing.T) {
	env := baseEnv()
	delete(env, "CALLOUT_INSTANCE")

	cfg, err := loadWith(t, env)
	if err != nil {
		t.Fatalf("an empty instance should be allowed: %v", err)
	}
	if cfg.Instance != "" {
		t.Fatalf("expected an empty instance, got %q", cfg.Instance)
	}
}

// TestInstanceRejectsSubjectMetacharacters keeps the existing guard.
func TestInstanceRejectsSubjectMetacharacters(t *testing.T) {
	for _, bad := range []string{"a.b", "a*", "a>", "a b"} {
		env := baseEnv()
		env["CALLOUT_INSTANCE"] = bad

		if _, err := loadWith(t, env); err == nil {
			t.Fatalf("instance %q should be rejected", bad)
		}
	}
}

// TestInvalidModesRejected covers the enum-style fields.
func TestInvalidModesRejected(t *testing.T) {
	t.Run("server mode", func(t *testing.T) {
		env := baseEnv()
		env["CALLOUT_SERVER_MODE"] = "bogus"
		if _, err := loadWith(t, env); err == nil {
			t.Fatal("an invalid server mode should fail")
		}
	})

	t.Run("inbox mode", func(t *testing.T) {
		env := baseEnv()
		env["CALLOUT_INBOX_MODE"] = "bogus"
		if _, err := loadWith(t, env); err == nil {
			t.Fatal("an invalid inbox mode should fail")
		}
	})

	t.Run("idp mode", func(t *testing.T) {
		env := baseEnv()
		env["CALLOUT_IDP_MODE"] = "bogus"
		if _, err := loadWith(t, env); err == nil {
			t.Fatal("an invalid idp mode should fail")
		}
	})
}

// --- authentication events ---------------------------------------------------------------

func TestEventsAreOffUnlessASubjectIsSet(t *testing.T) {
	cfg, err := loadWith(t, baseEnv())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The feature has to be opt-in: an existing deployment must not start announcing who logs
	// in, with their name and email, because it upgraded.
	if cfg.EventsSubject != "" {
		t.Errorf("EventsSubject = %q with nothing configured, want empty", cfg.EventsSubject)
	}
}

func TestEventsSettingsWithoutASubjectAreRefused(t *testing.T) {
	// Ignoring these would leave a deployment believing it had configured events while nothing
	// reads any of it.
	for _, name := range []string{
		"CALLOUT_EVENTS_STREAM", "CALLOUT_EVENTS_URL", "CALLOUT_EVENTS_USER",
		"CALLOUT_EVENTS_PASSWORD", "CALLOUT_EVENTS_CREDS", "CALLOUT_EVENTS_NKEY_SEED",
		"CALLOUT_EVENTS_NAME_CLAIM", "CALLOUT_EVENTS_EMAIL_CLAIM",
	} {
		t.Run(name, func(t *testing.T) {
			env := baseEnv()
			env[name] = "something"
			_, err := loadWith(t, env)
			if err == nil {
				t.Fatalf("load succeeded with %s set and no events subject", name)
			}
			if !strings.Contains(err.Error(), "CALLOUT_EVENTS_SUBJECT") {
				t.Errorf("error %q does not point at the subject setting", err)
			}
		})
	}
}

func TestEventsStreamIsOptionalAndSelectsTheDeliveryMode(t *testing.T) {
	// No stream is a legitimate configuration, not an omission: the events are then ordinary core
	// NATS messages. Requiring one would force JetStream on a deployment that only wants to tell
	// a live consumer that somebody signed in.
	env := baseEnv()
	env["CALLOUT_EVENTS_SUBJECT"] = "dev.events.auth"
	env["CALLOUT_EVENTS_CREDS"] = "/tmp/events.creds"

	cfg, err := loadWith(t, env)
	if err != nil {
		t.Fatalf("load with no events stream: %v", err)
	}
	if cfg.EventsStream != "" {
		t.Errorf("EventsStream = %q, want empty", cfg.EventsStream)
	}

	// And with one, it is carried through untouched.
	env["CALLOUT_EVENTS_STREAM"] = "AUTH_EVENTS"
	cfg, err = loadWith(t, env)
	if err != nil {
		t.Fatalf("load with an events stream: %v", err)
	}
	if cfg.EventsStream != "AUTH_EVENTS" {
		t.Errorf("EventsStream = %q, want AUTH_EVENTS", cfg.EventsStream)
	}
}

func TestEventsCredentialForms(t *testing.T) {
	// The events connection lands in a DIFFERENT account from the handler's, so it has its own
	// credential — with the same "exactly one form" rule, for the same reason: picking one
	// silently would leave it unclear which credential is in use.
	base := func() map[string]string {
		env := baseEnv()
		env["CALLOUT_EVENTS_SUBJECT"] = "dev.events.auth"
		env["CALLOUT_EVENTS_STREAM"] = "AUTH_EVENTS"
		return env
	}

	t.Run("none", func(t *testing.T) {
		_, err := loadWith(t, base())
		if err == nil || !strings.Contains(err.Error(), "CALLOUT_EVENTS_CREDS") {
			t.Fatalf("err = %v, want a complaint naming the credential forms", err)
		}
	})

	t.Run("two", func(t *testing.T) {
		env := base()
		env["CALLOUT_EVENTS_CREDS"] = "/tmp/events.creds"
		env["CALLOUT_EVENTS_USER"] = "callout-events"
		env["CALLOUT_EVENTS_PASSWORD"] = "secret"
		_, err := loadWith(t, env)
		if err == nil || !strings.Contains(err.Error(), "more than one events credential") {
			t.Fatalf("err = %v, want the two-forms error", err)
		}
	})

	t.Run("user with no password", func(t *testing.T) {
		env := base()
		env["CALLOUT_EVENTS_USER"] = "callout-events"
		_, err := loadWith(t, env)
		if err == nil || !strings.Contains(err.Error(), "CALLOUT_EVENTS_PASSWORD") {
			t.Fatalf("err = %v, want the missing password", err)
		}
	})

	t.Run("creds alone is enough", func(t *testing.T) {
		env := base()
		env["CALLOUT_EVENTS_CREDS"] = "/tmp/events.creds"
		if _, err := loadWith(t, env); err != nil {
			t.Fatalf("load: %v", err)
		}
	})
}

func TestEventsURLDefaultsToTheServerURL(t *testing.T) {
	env := baseEnv()
	env["CALLOUT_NATS_URL"] = "nats://nats.internal:4222"
	env["CALLOUT_EVENTS_SUBJECT"] = "dev.events.auth"
	env["CALLOUT_EVENTS_STREAM"] = "AUTH_EVENTS"
	env["CALLOUT_EVENTS_CREDS"] = "/tmp/events.creds"

	cfg, err := loadWith(t, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Same server, different account is the usual shape; a separate URL stays possible.
	if cfg.EventsNATSURL != "nats://nats.internal:4222" {
		t.Errorf("EventsNATSURL = %q, want the server URL", cfg.EventsNATSURL)
	}
}

func TestEventsURLCanDifferFromTheServerURL(t *testing.T) {
	env := baseEnv()
	env["CALLOUT_NATS_URL"] = "nats://nats.internal:4222"
	env["CALLOUT_EVENTS_SUBJECT"] = "dev.events.auth"
	env["CALLOUT_EVENTS_STREAM"] = "AUTH_EVENTS"
	env["CALLOUT_EVENTS_CREDS"] = "/tmp/events.creds"
	env["CALLOUT_EVENTS_URL"] = "nats://events.internal:4222"

	cfg, err := loadWith(t, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.EventsNATSURL != "nats://events.internal:4222" {
		t.Errorf("EventsNATSURL = %q, want the explicit events URL", cfg.EventsNATSURL)
	}
}

// --- userinfo enrichment -----------------------------------------------------------------

func TestEnrichmentDefaultsPerIdPMode(t *testing.T) {
	// The defaults exist to keep every deployment behaving exactly as it did before the setting
	// existed: zitadel already asked userinfo for a missing username, and nothing else asked at
	// all. A different default would change authentication behaviour on upgrade.
	cases := map[string]string{
		IDPModeZitadel: IDPEnrichUsername,
		IDPModeOIDC:    IDPEnrichNone,
		IDPModeMock:    IDPEnrichNone,
	}
	for mode, want := range cases {
		t.Run(mode, func(t *testing.T) {
			env := baseEnv()
			env["CALLOUT_IDP_MODE"] = mode
			switch mode {
			case IDPModeZitadel:
				env["CALLOUT_ZITADEL_ISSUER_URL"] = "https://id.example.com"
			case IDPModeOIDC:
				env["CALLOUT_OIDC_ISSUER_URL"] = "https://id.example.com"
				env["CALLOUT_OIDC_ROLES_CLAIM"] = "roles"
			}
			cfg, err := loadWith(t, env)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.IDPEnrich != want {
				t.Errorf("IDPEnrich = %q, want %q", cfg.IDPEnrich, want)
			}
		})
	}
}

func TestEnrichmentIsValidated(t *testing.T) {
	env := baseEnv()
	env["CALLOUT_IDP_ENRICH"] = "everything"

	_, err := loadWith(t, env)
	if err == nil {
		t.Fatal("load succeeded with an unknown enrichment level")
	}
	// Silently treating an unknown value as "none" would leave a deployment wondering why its
	// events have no names.
	if !strings.Contains(err.Error(), "CALLOUT_IDP_ENRICH") {
		t.Errorf("error %q does not name the setting", err)
	}
}

func TestEnrichmentCanBeSetToProfile(t *testing.T) {
	env := baseEnv()
	env["CALLOUT_IDP_ENRICH"] = IDPEnrichProfile

	cfg, err := loadWith(t, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.IDPEnrich != IDPEnrichProfile {
		t.Errorf("IDPEnrich = %q, want %q", cfg.IDPEnrich, IDPEnrichProfile)
	}
}
