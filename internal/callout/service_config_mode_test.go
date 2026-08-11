package callout

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// These tests exercise the FULL config-mode path against a real nats-server: a client connects
// with a token, the server calls out, this service mints a User JWT, and the server either
// accepts or rejects it. Nothing is stubbed on the server side, so what they verify is the
// server's actual acceptance rules rather than our reading of them.

// testRules writes a minimal rules.yaml + template pair and returns a Router over them. It
// keeps these tests independent of examples/rules.yaml, which is a PoC artifact free to change.
func testRules(t *testing.T, instance string) *authz.Router {
	t.Helper()

	dir := t.TempDir()

	template := `
pub:
  allow:
    - "{{instance}}.{{user_id}}.demo.ping"
sub:
  allow:
    - "_INBOX.{{user_id_hash}}.>"
`
	if err := writeFile(filepath.Join(dir, "person.yaml"), template); err != nil {
		t.Fatalf("write template: %v", err)
	}

	rules := `
version: 1
rules:
  - match: tester
    type: person
    template: person.yaml
`
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := writeFile(rulesPath, rules); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	router, err := authz.NewRouterFromFile(rulesPath, instance)
	if err != nil {
		t.Fatalf("build router: %v", err)
	}
	return router
}

// startConfigService wires the service against a config-mode fixture and starts serving.
// overrides lets a test mutate the Config to exercise a misconfiguration.
func startConfigService(t *testing.T, fx *configFixture, overrides func(*Config)) *Service {
	t.Helper()

	cfg := Config{
		Conn:          fx.connectHandler(t),
		Verifier:      idp.NewMock(),
		Router:        testRules(t, "dev"),
		Mode:          ModeConfig,
		SigningKey:    fx.issuerKP,
		TargetAccount: testAccountName,
		XKey:          fx.xkey,
	}
	if overrides != nil {
		overrides(&cfg)
	}

	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("start service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	return svc
}

// TestConfigModeAcceptsConnection is the core proof of the mode: a client presenting a valid
// token connects, lands in the target account and receives exactly the template's permissions.
func TestConfigModeAcceptsConnection(t *testing.T) {
	fx := startConfigServer(t)
	startConfigService(t, fx, nil)

	nc, err := fx.connectClient("mock:u-ana:ana@example.test:tester")
	if err != nil {
		t.Fatalf("client should have connected: %v", err)
	}
	defer nc.Close()

	if !nc.IsConnected() {
		t.Fatal("client should be connected")
	}

	// The permissions must be the template's, not the config user's. An allowed publish
	// succeeds and a denied one is reported — that is what proves the callout's JWT is what the
	// server is enforcing, rather than the credentials the client presented.
	if err := nc.Publish("dev.u-ana.demo.ping", []byte("hi")); err != nil {
		t.Fatalf("allowed publish failed: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush after allowed publish: %v", err)
	}

	// A publish outside the template must draw a permissions violation. It arrives
	// asynchronously, so it is collected through the error handler.
	violations := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case violations <- err:
		default:
		}
	})

	if err := nc.Publish("dev.someone-else.demo.ping", []byte("nope")); err != nil {
		t.Fatalf("publish call itself failed: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush after denied publish: %v", err)
	}

	// The violation is delivered asynchronously on the connection's error handler, so it has to
	// be waited for rather than polled: flushing only guarantees the server received the
	// publish, not that the error has made it back.
	select {
	case err := <-violations:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got: %v", err)
		}
	case <-time.After(waitFor):
		t.Fatal("publishing outside the template drew no permissions violation: the minted permissions are not being enforced")
	}
}

// TestConfigModeRejectsIssuerAccount pins the rule that makes config mode a real branch rather
// than a cosmetic one: a config-mode server REJECTS a User JWT carrying issuer_account.
//
// The service refuses to be built that way, so this asserts the guard rather than shipping a
// JWT the server would reject. It is the test that would have caught treating IssuerAccount as
// merely "optional" in config mode.
func TestConfigModeRejectsIssuerAccount(t *testing.T) {
	fx := startConfigServer(t)

	appPub, err := publicKeyOf(fx.issuerKP)
	if err != nil {
		t.Fatalf("issuer pubkey: %v", err)
	}

	_, err = New(Config{
		Conn:          fx.connectHandler(t),
		Verifier:      idp.NewMock(),
		Router:        testRules(t, "dev"),
		Mode:          ModeConfig,
		SigningKey:    fx.issuerKP,
		TargetAccount: testAccountName,
		IssuerAccount: appPub,
		XKey:          fx.xkey,
	})
	if err == nil {
		t.Fatal("config mode with an issuer account should fail to build")
	}
	if !strings.Contains(err.Error(), "issuer account") {
		t.Fatalf("error should name the issuer account, got: %v", err)
	}
}

// TestConfigModeRequiresTargetAccount guards the claim the original proposal missed: without
// an Audience the server resolves an empty account name and every connection fails. Catching
// it at startup is the difference between one clear error and a service that rejects
// everything at runtime.
func TestConfigModeRequiresTargetAccount(t *testing.T) {
	fx := startConfigServer(t)

	_, err := New(Config{
		Conn:       fx.connectHandler(t),
		Verifier:   idp.NewMock(),
		Router:     testRules(t, "dev"),
		Mode:       ModeConfig,
		SigningKey: fx.issuerKP,
		XKey:       fx.xkey,
	})
	if err == nil {
		t.Fatal("config mode with no target account should fail to build")
	}
	if !strings.Contains(err.Error(), "target account") {
		t.Fatalf("error should name the target account, got: %v", err)
	}
}

// TestConfigModeWrongTargetAccountIsRejected proves the Audience really is the placement
// account: naming an account that does not exist in the conf must fail the connection.
func TestConfigModeWrongTargetAccountIsRejected(t *testing.T) {
	fx := startConfigServer(t)
	startConfigService(t, fx, func(cfg *Config) {
		cfg.TargetAccount = "NOT_IN_THE_CONF"
	})

	conn, err := fx.connectClient("mock:u-ana:ana@example.test:tester")
	if err == nil {
		conn.Close()
		t.Fatal("a User JWT naming an unknown account should not be accepted")
	}
}

// TestConfigModeUsesAccountNameNotPubkey pins issue #4313: in config mode the placement is
// resolved by account NAME. Passing the account pubkey — which ADR-26's wording suggests — is
// rejected, so the trap is asserted rather than left to a comment.
func TestConfigModeUsesAccountNameNotPubkey(t *testing.T) {
	fx := startConfigServer(t)

	pub, err := publicKeyOf(fx.issuerKP)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}

	startConfigService(t, fx, func(cfg *Config) {
		cfg.TargetAccount = pub
	})

	conn, err := fx.connectClient("mock:u-ana:ana@example.test:tester")
	if err == nil {
		conn.Close()
		t.Fatal("an account PUBKEY as audience should be rejected in config mode; only the NAME resolves")
	}
}

// TestConfigModeRejectsUnknownRole verifies that routing still governs: a token whose role
// matches no rule is refused, and the refusal reaches the client rather than hanging.
func TestConfigModeRejectsUnknownRole(t *testing.T) {
	fx := startConfigServer(t)
	startConfigService(t, fx, nil)

	conn, err := fx.connectClient("mock:u-ana:ana@example.test:no-such-role")
	if err == nil {
		conn.Close()
		t.Fatal("a token whose role matches no rule should not connect")
	}
}

// TestConfigModeRejectsMissingToken covers the connection that presents no token at all.
func TestConfigModeRejectsMissingToken(t *testing.T) {
	fx := startConfigServer(t)
	startConfigService(t, fx, nil)

	conn, err := nats.Connect(fx.url,
		nats.UserInfo(fx.clientUser, fx.clientPass),
		nats.Timeout(waitFor),
	)
	if err == nil {
		conn.Close()
		t.Fatal("a connection with no token should be rejected")
	}
}

// TestModeValidation covers the mode field itself.
func TestModeValidation(t *testing.T) {
	fx := startConfigServer(t)

	_, err := New(Config{
		Conn:       fx.connectHandler(t),
		Verifier:   idp.NewMock(),
		Router:     testRules(t, "dev"),
		Mode:       Mode("bogus"),
		SigningKey: fx.issuerKP,
	})
	if err == nil {
		t.Fatal("an invalid mode should fail to build")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("error should name the invalid mode, got: %v", err)
	}
}

// publicKeyOf is a small helper so tests read cleanly.
func publicKeyOf(kp nkeys.KeyPair) (string, error) {
	if kp == nil {
		return "", errors.New("nil keypair")
	}
	return kp.PublicKey()
}
