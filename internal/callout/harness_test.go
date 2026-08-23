package callout

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// This file stands up REAL nats-servers in-process, in both authorization modes, so the
// acceptance rules the service depends on are verified against the server itself rather than
// against our reading of it.
//
// Why this matters more than a unit test: every rule that decides whether a User JWT is
// accepted lives in the server, not here. The two modes disagree on which claim carries the
// target account (IssuerAccount vs Audience) and a mistake is not a compile error — it is a
// service that rejects (or worse, accepts) every connection at runtime.

// testAccountName is the account clients land in. In config mode it is the value that must
// travel in the User JWT's Audience; in operator mode the account is identified by pubkey.
const testAccountName = "APP"

// waitFor bounds how long a test waits for the server to come up.
const waitFor = 5 * time.Second

// operatorFixture is a full operator-mode identity: operator, AUTH and APP accounts, the
// sentinel users and the callout configuration inside the AUTH account's JWT.
type operatorFixture struct {
	// appPub is the APP account pubkey: the IssuerAccount the User JWT must carry.
	appPub string
	// appSK signs User JWTs (an APP account signing key).
	appSK nkeys.KeyPair
	// authSK signs the authorization_response (an AUTH account signing key).
	authSK nkeys.KeyPair
	// xkey is the callout's curve pair.
	xkey nkeys.KeyPair
	// handlerCreds is the path to the sentinel-handler creds file.
	handlerCreds string
	// clientCreds is the path to the deny-all sentinel-client creds file.
	clientCreds string
	// url is the running server's URL.
	url string
}

// configFixture is a config-mode server: no operator, no account JWTs. A single account nkey
// is declared as the callout issuer, and it is that key which must sign the User JWT.
type configFixture struct {
	// issuerKP is the key declared in auth_callout.issuer. It signs the User JWT.
	issuerKP nkeys.KeyPair
	// xkey is the callout's curve pair.
	xkey nkeys.KeyPair
	// url is the running server's URL.
	url string
	// handlerUser/handlerPass are the credentials the callout connects with. This user is in
	// auth_users, so it bypasses the callout.
	handlerUser, handlerPass string
	// clientUser/clientPass are the credentials a client connects with. NOT in auth_users, so
	// connecting with them triggers the callout.
	clientUser, clientPass string
	// appAdminUser/appAdminPass are an unrestricted user of the APP account. It stands in for
	// the deployment itself: it is what creates the stream the authentication events land in,
	// because the callout deliberately cannot.
	appAdminUser, appAdminPass string
	// eventsUser/eventsPass are the events publisher's credentials, in the APP account and
	// carrying the MINIMAL permissions the documentation claims are enough. If that claim is
	// wrong, the event tests fail rather than the documentation being quietly optimistic.
	eventsUser, eventsPass string
}

// startConfigServer brings up a config-mode server with auth callout configured.
//
// The layout mirrors what an existing NATS would look like after adopting the callout: a
// dedicated AUTH account for the callout (never $G, which would let other connections observe
// the credential traffic on $SYS.REQ.USER.AUTH) and an APP account with JetStream enabled,
// which is required for the KV permissions the templates mint.
func startConfigServer(t *testing.T) *configFixture {
	t.Helper()

	issuerKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create issuer account key: %v", err)
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

		appAdminUser: "app-admin",
		appAdminPass: "app-admin-pass",
		eventsUser:   "callout-events",
		eventsPass:   "events-pass",
	}

	// JetStream is opt-in per account once an accounts{} block exists: an account without the
	// jetstream field silently has it disabled, and a KV permission then fails as a client
	// TIMEOUT rather than a permissions violation. Enabling it here keeps the fixture
	// representative of a working deployment.
	conf := fmt.Sprintf(`
port: -1
server_name: config-mode-test

jetstream { store_dir: %q }

accounts {
  AUTH: {
    users: [
      { user: %q, password: %q }
      { user: %q, password: %q }
    ]
  }
  # Two plain users, authenticated by the server itself rather than by the callout. What makes
  # that work is allowed_accounts below: in config mode every account is delegated to the
  # callout unless the delegation is scoped, and a delegated infrastructure connection has no
  # token to present. That is a real deployment requirement, not a test shortcut.
  %s: {
    jetstream: enabled
    users: [
      # The deployment's own administrator. It creates the stream; the callout never does.
      { user: %q, password: %q }

      # The events publisher. These are exactly the permissions docs/events.md asks for, and no
      # more: publish the event, read the stream's info for the startup check, and receive the
      # ack on its own inbox.
      {
        user: %q, password: %q
        permissions: {
          publish: { allow: [ %q, %q ] }
          subscribe: { allow: [ "_INBOX.>" ] }
        }
      }
    ]
  }
}

authorization {
  timeout: 5
  auth_callout {
    issuer: %q
    account: AUTH
    auth_users: [ %q ]
    xkey: %q

    # Only the AUTH account's users are delegated to the callout. Without this line EVERY
    # account is, and the plain users declared in APP below - the deployment's administrator and
    # the callout's own events publisher - would be sent to the callout too, which has no token
    # for them. The clients that MUST go through the callout connect as an AUTH user, so
    # scoping the delegation here changes nothing about them.
    allowed_accounts: [ AUTH ]
  }
}
`,
		t.TempDir(),
		fx.handlerUser, fx.handlerPass,
		fx.clientUser, fx.clientPass,
		testAccountName,
		fx.appAdminUser, fx.appAdminPass,
		fx.eventsUser, fx.eventsPass,
		testEventsSubject, "$JS.API.STREAM.INFO."+testEventsStream,
		issuerPub,
		fx.handlerUser,
		xkeyPub,
	)

	fx.url = startServerFromConf(t, conf)
	return fx
}

// startServerFromConf writes a config file, starts a server from it and registers cleanup.
func startServerFromConf(t *testing.T, conf string) string {
	t.Helper()

	path := writeTempFile(t, "nats-*.conf", conf)

	opts, err := natsserver.ProcessConfigFile(path)
	if err != nil {
		t.Fatalf("process config file: %v", err)
	}
	// Keep the server quiet unless a test is being debugged.
	opts.NoLog = true
	opts.NoSigs = true

	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(waitFor) {
		t.Fatal("server not ready for connections")
	}
	t.Cleanup(srv.Shutdown)

	return srv.ClientURL()
}

// writeTempFile writes content to a temp file and returns its path.
func writeTempFile(t *testing.T, pattern, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}

// connectHandler opens the callout's own connection (the one that bypasses the callout).
func (fx *configFixture) connectHandler(t *testing.T) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(fx.url,
		nats.UserInfo(fx.handlerUser, fx.handlerPass),
		nats.Name("callout-test-handler"),
	)
	if err != nil {
		t.Fatalf("connect handler: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// connectClient attempts a client connection carrying token, which triggers the callout. The
// error is returned rather than fatal: rejection is the expected outcome in several tests.
func (fx *configFixture) connectClient(token string) (*nats.Conn, error) {
	return nats.Connect(fx.url,
		nats.UserInfo(fx.clientUser, fx.clientPass),
		nats.Token(token),
		nats.Name("callout-test-client"),
		nats.Timeout(waitFor),
	)
}

// decodeUserJWT is a helper for asserting on what the service minted.
func decodeUserJWT(t *testing.T, token string) *jwt.UserClaims {
	t.Helper()
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatalf("decode user JWT: %v", err)
	}
	return claims
}

// writeFile is a tiny helper for fixture files.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
