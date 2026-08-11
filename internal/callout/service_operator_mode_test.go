package callout

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// Operator-mode coverage. The identity is built in-process with nats-io/jwt rather than by
// shelling out to `nsc`, so the test needs no external tooling and stays hermetic — but the
// resulting topology is the same one nats/bootstrap.sh produces: an operator, an AUTH account
// holding the callout and its two sentinels, and an APP account users land in.

// buildOperatorFixture assembles a full operator-mode server and returns the keys the service
// needs. It mirrors bootstrap.sh: two accounts, two signing keys with different roles, the
// callout declared inside the AUTH account's JWT.
func buildOperatorFixture(t *testing.T) *operatorFixture {
	t.Helper()

	// --- operator -------------------------------------------------------------------------
	opKP, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	opPub, err := opKP.PublicKey()
	if err != nil {
		t.Fatalf("operator pubkey: %v", err)
	}

	// --- APP account: where users land ----------------------------------------------------
	_, appPub := newAccountKey(t)
	appSK, appSKPub := newAccountKey(t)

	appClaims := jwt.NewAccountClaims(appPub)
	appClaims.Name = "APP"
	appClaims.SigningKeys.Add(appSKPub)
	// JetStream so KV permissions point at something that exists.
	appClaims.Limits.JetStreamLimits.MemoryStorage = -1
	appClaims.Limits.JetStreamLimits.DiskStorage = -1
	appClaims.Limits.JetStreamLimits.Streams = -1
	appClaims.Limits.JetStreamLimits.Consumer = -1
	appJWT, err := appClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("encode APP account: %v", err)
	}

	// --- AUTH account: the callout and its sentinels --------------------------------------
	authKP, authPub := newAccountKey(t)
	authSK, authSKPub := newAccountKey(t)

	// The two sentinels. The handler goes in AuthUsers so it bypasses the callout; the client
	// does not, so connecting with it triggers the callout.
	handlerKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create handler user: %v", err)
	}
	handlerPub, err := handlerKP.PublicKey()
	if err != nil {
		t.Fatalf("handler pubkey: %v", err)
	}
	clientKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create client user: %v", err)
	}
	clientPub, err := clientKP.PublicKey()
	if err != nil {
		t.Fatalf("client pubkey: %v", err)
	}

	xkey, err := nkeys.CreateCurveKeys()
	if err != nil {
		t.Fatalf("create xkey: %v", err)
	}
	xkeyPub, err := xkey.PublicKey()
	if err != nil {
		t.Fatalf("xkey pubkey: %v", err)
	}

	authClaims := jwt.NewAccountClaims(authPub)
	authClaims.Name = "AUTH"
	authClaims.SigningKeys.Add(authSKPub)
	authClaims.Authorization.AuthUsers.Add(handlerPub)
	authClaims.Authorization.AllowedAccounts.Add(appPub)
	authClaims.Authorization.XKey = xkeyPub
	authJWT, err := authClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("encode AUTH account: %v", err)
	}

	// --- SYS account ----------------------------------------------------------------------
	_, sysPub := newAccountKey(t)
	sysClaims := jwt.NewAccountClaims(sysPub)
	sysClaims.Name = "SYS"
	sysJWT, err := sysClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("encode SYS account: %v", err)
	}

	// --- user creds -----------------------------------------------------------------------
	handlerCreds := writeUserCreds(t, "sentinel-handler", handlerKP, authKP, authPub)
	// The sentinel-client is deny-all: on its own it authorizes nothing, so every permission a
	// connection gets comes from the User JWT the callout mints.
	clientCreds := writeDenyAllUserCreds(t, "sentinel-client", clientKP, authKP, authPub)
	_ = clientPub

	conf := fmt.Sprintf(`
port: -1
server_name: operator-mode-test

operator: %q
system_account: %s

jetstream { store_dir: %q }

resolver: MEMORY
resolver_preload: {
  %s: %q
  %s: %q
  %s: %q
}

authorization { timeout: 5 }
`,
		mustEncodeOperator(t, opKP, opPub, sysPub),
		sysPub,
		t.TempDir(),
		appPub, appJWT,
		authPub, authJWT,
		sysPub, sysJWT,
	)

	return &operatorFixture{
		appPub:       appPub,
		appSK:        appSK,
		authSK:       authSK,
		xkey:         xkey,
		handlerCreds: handlerCreds,
		clientCreds:  clientCreds,
		url:          startServerFromConf(t, conf),
	}
}

// mustEncodeOperator builds the operator JWT that the server trusts.
func mustEncodeOperator(t *testing.T, opKP nkeys.KeyPair, opPub, sysPub string) string {
	t.Helper()
	claims := jwt.NewOperatorClaims(opPub)
	claims.Name = "test-operator"
	claims.SystemAccount = sysPub
	encoded, err := claims.Encode(opKP)
	if err != nil {
		t.Fatalf("encode operator: %v", err)
	}
	return encoded
}

// newAccountKey creates an account keypair and returns it with its pubkey.
func newAccountKey(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("account pubkey: %v", err)
	}
	return kp, pub
}

// writeUserCreds encodes a user JWT and writes a .creds file for it.
func writeUserCreds(t *testing.T, name string, userKP, signer nkeys.KeyPair, issuerAccount string) string {
	t.Helper()
	return encodeCreds(t, name, userKP, signer, issuerAccount, false)
}

// writeDenyAllUserCreds writes creds for a user denied every publish and subscribe.
func writeDenyAllUserCreds(t *testing.T, name string, userKP, signer nkeys.KeyPair, issuerAccount string) string {
	t.Helper()
	return encodeCreds(t, name, userKP, signer, issuerAccount, true)
}

func encodeCreds(t *testing.T, name string, userKP, signer nkeys.KeyPair, issuerAccount string, denyAll bool) string {
	t.Helper()

	userPub, err := userKP.PublicKey()
	if err != nil {
		t.Fatalf("user pubkey: %v", err)
	}
	claims := jwt.NewUserClaims(userPub)
	claims.Name = name
	// Signed with the ACCOUNT key here (not a signing key), so no IssuerAccount is needed.
	if denyAll {
		claims.Pub.Deny.Add(">")
		claims.Sub.Deny.Add(">")
	}
	userJWT, err := claims.Encode(signer)
	if err != nil {
		t.Fatalf("encode user JWT: %v", err)
	}

	seed, err := userKP.Seed()
	if err != nil {
		t.Fatalf("user seed: %v", err)
	}

	creds, err := jwt.FormatUserConfig(userJWT, seed)
	if err != nil {
		t.Fatalf("format creds: %v", err)
	}

	path := filepath.Join(t.TempDir(), name+".creds")
	if err := writeFile(path, string(creds)); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	return path
}

// startOperatorService wires the service in operator mode against the fixture.
func startOperatorService(t *testing.T, fx *operatorFixture, overrides func(*Config)) *Service {
	t.Helper()

	nc, err := nats.Connect(fx.url, nats.UserCredentials(fx.handlerCreds), nats.Timeout(waitFor))
	if err != nil {
		t.Fatalf("connect handler: %v", err)
	}
	t.Cleanup(nc.Close)

	cfg := Config{
		Conn:           nc,
		Verifier:       idp.NewMock(),
		Router:         testRules(t, "dev"),
		Mode:           ModeOperator,
		SigningKey:     fx.appSK,
		IssuerAccount:  fx.appPub,
		ResponseSigner: fx.authSK,
		XKey:           fx.xkey,
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

// TestOperatorModeAcceptsConnection is the regression guard for the mode split: the existing
// operator path must keep working untouched.
func TestOperatorModeAcceptsConnection(t *testing.T) {
	fx := buildOperatorFixture(t)
	startOperatorService(t, fx, nil)

	nc, err := nats.Connect(fx.url,
		nats.UserCredentials(fx.clientCreds),
		nats.Token("mock:u-ana:ana@example.test:tester"),
		nats.Timeout(waitFor),
	)
	if err != nil {
		t.Fatalf("client should have connected: %v", err)
	}
	defer nc.Close()

	if err := nc.Publish("dev.u-ana.demo.ping", []byte("hi")); err != nil {
		t.Fatalf("allowed publish failed: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// TestOperatorModeRejectsTargetAccount is the mirror of the config-mode guard: a target
// account name is meaningless in operator mode, where placement comes from the issuer account
// pubkey. Accepting it silently would let a deploy think it had changed the target account.
func TestOperatorModeRejectsTargetAccount(t *testing.T) {
	fx := buildOperatorFixture(t)

	nc, err := nats.Connect(fx.url, nats.UserCredentials(fx.handlerCreds), nats.Timeout(waitFor))
	if err != nil {
		t.Fatalf("connect handler: %v", err)
	}
	defer nc.Close()

	_, err = New(Config{
		Conn:           nc,
		Verifier:       idp.NewMock(),
		Router:         testRules(t, "dev"),
		Mode:           ModeOperator,
		SigningKey:     fx.appSK,
		IssuerAccount:  fx.appPub,
		TargetAccount:  "APP",
		ResponseSigner: fx.authSK,
		XKey:           fx.xkey,
	})
	if err == nil {
		t.Fatal("operator mode with a target account should fail to build")
	}
	if !strings.Contains(err.Error(), "target account") {
		t.Fatalf("error should name the target account, got: %v", err)
	}
}

// TestOperatorModeDefaultsWhenModeUnset pins backward compatibility: a Config built the old
// way — with no Mode field at all — must still work as operator mode.
func TestOperatorModeDefaultsWhenModeUnset(t *testing.T) {
	fx := buildOperatorFixture(t)

	nc, err := nats.Connect(fx.url, nats.UserCredentials(fx.handlerCreds), nats.Timeout(waitFor))
	if err != nil {
		t.Fatalf("connect handler: %v", err)
	}
	defer nc.Close()

	svc, err := New(Config{
		Conn:           nc,
		Verifier:       idp.NewMock(),
		Router:         testRules(t, "dev"),
		SigningKey:     fx.appSK,
		IssuerAccount:  fx.appPub,
		ResponseSigner: fx.authSK,
		XKey:           fx.xkey,
	})
	if err != nil {
		t.Fatalf("a Config with no Mode should build as operator: %v", err)
	}
	if svc.Mode() != ModeOperator {
		t.Fatalf("expected mode %q, got %q", ModeOperator, svc.Mode())
	}
}
