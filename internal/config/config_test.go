package config

import (
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
		"CALLOUT_RULES_PATH":           "config/rules.yaml",
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
		"CALLOUT_LOG_LEVEL",
	} {
		t.Setenv(name, "")
	}
	for name, value := range env {
		t.Setenv(name, value)
	}
	return Load()
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
		"CALLOUT_RULES_PATH":          "config/rules.yaml",
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
				"CALLOUT_RULES_PATH":          "config/rules.yaml",
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
		"CALLOUT_RULES_PATH":          "config/rules.yaml",
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
			"CALLOUT_RULES_PATH":          "config/rules.yaml",
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
			"CALLOUT_RULES_PATH":          "config/rules.yaml",
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
			"CALLOUT_RULES_PATH":          "config/rules.yaml",
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
