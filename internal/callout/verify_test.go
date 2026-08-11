package callout

import (
	"fmt"
	"os"
	"strings"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// These tests run `verify` against real nats-servers, correctly and incorrectly wired, because
// what it claims to detect is a property of the server rather than of our code. A check that
// passes against a broken server is worse than no check: it converts "I am not sure" into false
// confidence.

// findingFor returns the finding for a named check.
func findingFor(t *testing.T, r *Report, check string) Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("no finding for %q; got %+v", check, r.Findings)
	return Finding{}
}

// TestVerifyPassesOnCorrectWiring is the baseline: a properly configured deployment must come
// back clean, or the failures below prove nothing.
func TestVerifyPassesOnCorrectWiring(t *testing.T) {
	fx := startConfigServer(t)

	nc, err := nats.Connect(fx.url, nats.UserInfo(fx.handlerUser, fx.handlerPass))
	if err != nil {
		t.Fatalf("handler connect: %v", err)
	}
	defer nc.Close()

	report := Verify(VerifyInput{
		Conn:           nc,
		Mode:           ModeConfig,
		ClientUser:     fx.clientUser,
		ClientPassword: fx.clientPass,
		NATSURL:        fx.url,
		XKeyConfigured: true,
	})

	if !report.OK() {
		t.Fatalf("a correctly wired deployment should pass:\n%s", report)
	}
	if f := findingFor(t, report, "client bypass"); f.Severity != SeverityPass {
		t.Fatalf("expected the bypass check to pass, got %s: %s", f.Severity, f.Detail)
	}
}

// TestVerifyDetectsClientBypass is the check this command exists for.
//
// A client user listed in auth_users skips the callout entirely and keeps its own permissions.
// It connects fine, so nothing at runtime reveals it — which is exactly why it has to be caught
// before traffic flows.
func TestVerifyDetectsClientBypass(t *testing.T) {
	fx := startBypassedServer(t)

	nc, err := nats.Connect(fx.url, nats.UserInfo(fx.handlerUser, fx.handlerPass))
	if err != nil {
		t.Fatalf("handler connect: %v", err)
	}
	defer nc.Close()

	report := Verify(VerifyInput{
		Conn:           nc,
		Mode:           ModeConfig,
		ClientUser:     fx.clientUser,
		ClientPassword: fx.clientPass,
		NATSURL:        fx.url,
		XKeyConfigured: true,
	})

	f := findingFor(t, report, "client bypass")
	if f.Severity != SeverityFail {
		t.Fatalf("a client in auth_users must FAIL the bypass check, got %s: %s", f.Severity, f.Detail)
	}
	if report.OK() {
		t.Fatal("the report must not be OK when the callout is bypassed")
	}
	// The fix has to name where to look. "Misconfigured" alone sends the reader hunting.
	if !strings.Contains(f.Fix, "auth_users") {
		t.Fatalf("the fix should name auth_users, got: %s", f.Fix)
	}
}

// TestVerifyWithoutClientCredentialsWarns: the bypass check is the valuable one, so its absence
// must be visible rather than looking like a pass.
func TestVerifyWithoutClientCredentialsWarns(t *testing.T) {
	fx := startConfigServer(t)

	nc, err := nats.Connect(fx.url, nats.UserInfo(fx.handlerUser, fx.handlerPass))
	if err != nil {
		t.Fatalf("handler connect: %v", err)
	}
	defer nc.Close()

	report := Verify(VerifyInput{
		Conn:           nc,
		Mode:           ModeConfig,
		NATSURL:        fx.url,
		XKeyConfigured: true,
	})

	if f := findingFor(t, report, "client bypass"); f.Severity != SeverityWarn {
		t.Fatalf("expected a warning when no client credential is given, got %s", f.Severity)
	}
	// A warning must not make the run fail: not checking is not the same as finding a problem.
	if !report.OK() {
		t.Fatal("a missing optional check should not fail the run")
	}
}

// TestVerifyDetectsHandlerCannotServeCalloutSubject: without that subscription the service
// starts, says it is listening, and every connection is refused while its own log stays silent.
func TestVerifyDetectsHandlerCannotServeCalloutSubject(t *testing.T) {
	fx := startDeniedHandlerServer(t)

	nc, err := nats.Connect(fx.url, nats.UserInfo(fx.handlerUser, fx.handlerPass))
	if err != nil {
		t.Fatalf("handler connect: %v", err)
	}
	defer nc.Close()

	report := Verify(VerifyInput{
		Conn:           nc,
		Mode:           ModeConfig,
		NATSURL:        fx.url,
		XKeyConfigured: true,
	})

	if f := findingFor(t, report, "callout subject"); f.Severity != SeverityFail {
		t.Fatalf("a handler denied %s must FAIL, got %s: %s", AuthSubject, f.Severity, f.Detail)
	}
}

// TestVerifyWarnsWithoutXKey: without encryption the clients' access tokens travel in the clear
// on the callout subject. It is a working deployment, so it warns rather than fails.
func TestVerifyWarnsWithoutXKey(t *testing.T) {
	fx := startConfigServer(t)

	nc, err := nats.Connect(fx.url, nats.UserInfo(fx.handlerUser, fx.handlerPass))
	if err != nil {
		t.Fatalf("handler connect: %v", err)
	}
	defer nc.Close()

	report := Verify(VerifyInput{
		Conn:           nc,
		Mode:           ModeConfig,
		NATSURL:        fx.url,
		XKeyConfigured: false,
	})

	f := findingFor(t, report, "request encryption")
	if f.Severity != SeverityWarn {
		t.Fatalf("expected a warning with no XKey, got %s", f.Severity)
	}
	if !strings.Contains(f.Detail, "clear") {
		t.Fatalf("the detail should say the tokens travel in the clear, got: %s", f.Detail)
	}
}

// TestVerifyFailsWhenDisconnected: every other check depends on the handler connection, so a
// dead one has to be reported as the cause rather than as five unrelated failures.
func TestVerifyFailsWhenDisconnected(t *testing.T) {
	report := Verify(VerifyInput{Conn: nil, Mode: ModeConfig})

	if f := findingFor(t, report, "handler connection"); f.Severity != SeverityFail {
		t.Fatalf("expected a failure with no connection, got %s", f.Severity)
	}
	if report.OK() {
		t.Fatal("a report with no connection must not be OK")
	}
}

// TestReportRenderingIncludesFixes keeps the output actionable: a finding with no remedy tells
// the reader something is wrong and leaves them there.
func TestReportRenderingIncludesFixes(t *testing.T) {
	r := &Report{}
	r.fail("a check", "what happened", "what to do")
	out := r.String()

	for _, want := range []string{"FAIL", "a check", "what happened", "fix: what to do", "not ready to serve traffic"} {
		if !strings.Contains(out, want) {
			t.Errorf("the rendered report should contain %q:\n%s", want, out)
		}
	}
}

// --- fixtures for misconfigured servers -------------------------------------------------

// startBypassedServer brings up a server with the CLIENT user also listed in auth_users — the
// open failure. Everything else is wired correctly, so a check that fires here is detecting
// this specific mistake and not some other breakage.
func startBypassedServer(t *testing.T) *configFixture {
	t.Helper()
	return startMisconfiguredServer(t, `auth_users: [ %[1]q, %[2]q ]`, "")
}

// startDeniedHandlerServer brings up a server whose handler cannot subscribe to the callout
// subject.
func startDeniedHandlerServer(t *testing.T) *configFixture {
	t.Helper()
	return startMisconfiguredServer(t, `auth_users: [ %[1]q ]`,
		`, permissions: { subscribe: { deny: "$SYS.>" } }`)
}

// startMisconfiguredServer builds a config-mode server with a deliberate defect.
//
// authUsersLine is a format string receiving the handler and client user names; handlerPerms is
// an optional permissions block applied to the handler.
func startMisconfiguredServer(t *testing.T, authUsersLine, handlerPerms string) *configFixture {
	t.Helper()

	issuerKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create issuer key: %v", err)
	}
	issuerPub, err := issuerKP.PublicKey()
	if err != nil {
		t.Fatalf("issuer pubkey: %v", err)
	}
	xkey, err := nkeys.CreateCurveKeys()
	if err != nil {
		t.Fatalf("create xkey: %v", err)
	}
	xkeyPub, err := xkey.PublicKey()
	if err != nil {
		t.Fatalf("xkey pubkey: %v", err)
	}

	fx := &configFixture{
		issuerKP:    issuerKP,
		xkey:        xkey,
		handlerUser: "callout-handler",
		handlerPass: "handler-pass",
		clientUser:  "callout-client",
		clientPass:  "client-pass",
	}

	dir := t.TempDir()
	conf := fmt.Sprintf(`
port: -1
server_name: verify-test
jetstream { store_dir: %q }
accounts {
  AUTH: {
    users: [
      { user: %q, password: %q %s }
      { user: %q, password: %q }
    ]
  }
  APP: { jetstream: enabled }
}
authorization {
  timeout: 5
  auth_callout {
    issuer: %q
    account: AUTH
    %s
    xkey: %q
  }
}
`, dir,
		fx.handlerUser, fx.handlerPass, handlerPerms,
		fx.clientUser, fx.clientPass,
		issuerPub,
		fmt.Sprintf(authUsersLine, fx.handlerUser, fx.clientUser),
		xkeyPub)

	path := dir + "/nats-server.conf"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	opts, err := natsserver.ProcessConfigFile(path)
	if err != nil {
		t.Fatalf("parse conf: %v", err)
	}
	opts.NoLog, opts.NoSigs = true, true

	srv := natsserver.New(opts)
	go srv.Start()
	if !srv.ReadyForConnections(waitFor) {
		t.Fatal("server did not come up")
	}
	t.Cleanup(srv.Shutdown)

	fx.url = srv.ClientURL()
	return fx
}
