package callout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

// shippedConfigModeConf is the example an adopting team copies.
const shippedConfigModeConf = "../../nats/nats-server.config-mode.conf"

// TestShippedConfigModeConfIsValid keeps the shipped example honest: it has to parse with the
// real server parser and declare the callout the way the documentation claims.
//
// A broken example is worse than no example — it is copied verbatim into someone else's
// infrastructure, and the failure surfaces as an authorization problem rather than a syntax one.
func TestShippedConfigModeConfIsValid(t *testing.T) {
	if _, err := os.Stat(shippedConfigModeConf); err != nil {
		t.Fatalf("the shipped config-mode example is missing: %v", err)
	}

	opts, err := natsserver.ProcessConfigFile(shippedConfigModeConf)
	if err != nil {
		t.Fatalf("the shipped config-mode example does not parse: %v", err)
	}

	if opts.AuthCallout == nil {
		t.Fatal("the example declares no auth_callout block")
	}

	// The callout must not sit in the global account: every other $G connection could otherwise
	// observe the credential traffic on $SYS.REQ.USER.AUTH.
	if opts.AuthCallout.Account == "" || opts.AuthCallout.Account == "$G" {
		t.Fatalf("the callout account must be a dedicated account, got %q", opts.AuthCallout.Account)
	}

	// Exactly one auth user: anything else in this list bypasses authentication silently.
	if len(opts.AuthCallout.AuthUsers) != 1 {
		t.Fatalf("expected exactly one auth_users entry (the callout's own user), got %v",
			opts.AuthCallout.AuthUsers)
	}

	// The XKey is what keeps clients' access tokens off the wire in the clear.
	if opts.AuthCallout.XKey == "" {
		t.Fatal("the example should configure an xkey: without it access tokens travel in the clear")
	}

	// The target account has to exist and have JetStream enabled, otherwise the KV permissions
	// the templates mint point at an account that cannot serve them — and that failure shows up
	// as a client timeout, not as a permissions error.
	//
	// This is asserted against a RUNNING server: Account.JetStreamEnabled() only reports
	// meaningfully once the server has assigned accounts, so checking the parsed options would
	// pass vacuously.
	var declared bool
	for _, acc := range opts.Accounts {
		if acc.Name == "APP" {
			declared = true
			break
		}
	}
	if !declared {
		t.Fatal("the example should declare the APP target account")
	}

	srv := startShippedExample(t, opts)
	target, err := srv.LookupAccount("APP")
	if err != nil {
		t.Fatalf("look up the APP account: %v", err)
	}
	if !target.JetStreamEnabled() {
		t.Fatal("the APP account should have JetStream enabled: KV permissions otherwise fail as a client timeout")
	}
}

// startShippedExample boots the example config on ephemeral ports so the running server can be
// inspected. The ports are overridden because the example declares the real 4222/8222, which a
// developer's machine may well have in use.
func startShippedExample(t *testing.T, opts *natsserver.Options) *natsserver.Server {
	t.Helper()

	opts.Port = -1
	opts.HTTPPort = 0
	opts.StoreDir = t.TempDir()
	opts.NoLog = true
	opts.NoSigs = true

	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start the shipped example: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(waitFor) {
		t.Fatal("the shipped example did not come up")
	}
	t.Cleanup(srv.Shutdown)

	return srv
}

// TestShippedConfigModeConfWarnsAboutAuthUsers is a documentation test. The auth_users pitfall
// is the highest-consequence, lowest-visibility mistake in config mode — a client listed there
// is never authenticated — so the example must say so in the file itself, where someone editing
// it will actually read it.
func TestShippedConfigModeConfWarnsAboutAuthUsers(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(shippedConfigModeConf))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	text := string(data)

	for _, phrase := range []string{"auth_users", "$G", "jetstream"} {
		if !strings.Contains(text, phrase) {
			t.Errorf("the example should discuss %q", phrase)
		}
	}
}
