package callout

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/events"
)

// This file verifies the authentication event END TO END, against real servers in both
// authorization modes: a client connects through the callout, and the event has to be in a
// JetStream stream in the account the application lives in.
//
// Two things make it worth the setup rather than a unit test with a fake:
//
//  1. THE ACCOUNT BOUNDARY. The callout's own connection is in the AUTH account, whose subject
//     namespace application clients cannot see. The events connection is a second connection
//     into the APP account, and no unit test can show that the boundary was actually crossed.
//  2. THE PERMISSION SET. The events credential here carries exactly the permissions the
//     documentation tells a deployment to grant. If publishing needs anything more, these tests
//     fail — which is the only way that claim stays true.

const (
	// testEventsStream is the stream the events land in.
	testEventsStream = "AUTH_EVENTS"
	// testEventsSubject is testEventsSubjectPattern expanded for the `dev` instance.
	testEventsSubject = "dev.events.auth"
	// testEventsSubjectPattern is what a deployment configures.
	testEventsSubjectPattern = "{{instance}}.events.auth"
)

// testEventsToken is a mock token carrying the claims the event reads: a role that matches the
// test rules, plus a name and an email like a person's token would have.
const testEventsToken = "mock:u-ana:ana@example.com:tester:email=ana@example.com,name=Ana Perez"

func TestConfigModeAuthenticationEventReachesTheStream(t *testing.T) {
	fx := startConfigServer(t)

	// The stream is created by the deployment's own administrator, exactly as documented: the
	// events credential has no authority to create streams and is not supposed to.
	admin := connectUserPass(t, fx.url, fx.appAdminUser, fx.appAdminPass)
	createEventsStream(t, admin)

	// The publisher's connection: the events credential, in the APP account.
	eventsConn := connectUserPass(t, fx.url, fx.eventsUser, fx.eventsPass)
	publisher := newEventsPublisher(t, eventsConn, testRules(t, "dev"))

	startConfigService(t, fx, func(cfg *Config) { cfg.Events = publisher })

	// A client connects the way a real one does: the deny-all sentinel credential plus its
	// access token.
	client, err := nats.Connect(fx.url,
		nats.UserInfo(fx.clientUser, fx.clientPass),
		nats.Token(testEventsToken),
		nats.CustomInboxPrefix("_INBOX."+authz.HashUserID("u-ana")),
		nats.Timeout(waitFor),
	)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer client.Close()

	event := waitForEvent(t, admin, publisher)
	assertAnaEvent(t, event)
}

func TestOperatorModeAuthenticationEventReachesTheStream(t *testing.T) {
	fx := buildOperatorFixture(t)

	// In operator mode the APP account's users are minted here rather than declared in a file.
	// The admin creates the stream; the events user gets the documented minimum.
	adminCreds := writeAppUserCreds(t, fx, "app-admin", nil, nil)
	eventsCreds := writeAppUserCreds(t, fx, "callout-events",
		[]string{testEventsSubject, "$JS.API.STREAM.INFO." + testEventsStream},
		[]string{"_INBOX.>"},
	)

	admin := connectCreds(t, fx.url, adminCreds)
	createEventsStream(t, admin)

	eventsConn := connectCreds(t, fx.url, eventsCreds)
	publisher := newEventsPublisher(t, eventsConn, testRules(t, "dev"))

	startOperatorService(t, fx, func(cfg *Config) { cfg.Events = publisher })

	client, err := nats.Connect(fx.url,
		nats.UserCredentials(fx.clientCreds),
		nats.Token(testEventsToken),
		nats.CustomInboxPrefix("_INBOX."+authz.HashUserID("u-ana")),
		nats.Timeout(waitFor),
	)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer client.Close()

	event := waitForEvent(t, admin, publisher)
	assertAnaEvent(t, event)
}

// TestAuthenticationEventIsNotPublishedForARejectedConnection pins the boundary of the feature:
// the event says a connection WAS authenticated. A token that does not verify, or a role that
// matches no rule, must leave the stream empty — otherwise a consumer counting logins would be
// counting failed attempts too.
func TestAuthenticationEventIsNotPublishedForARejectedConnection(t *testing.T) {
	fx := startConfigServer(t)

	admin := connectUserPass(t, fx.url, fx.appAdminUser, fx.appAdminPass)
	createEventsStream(t, admin)

	eventsConn := connectUserPass(t, fx.url, fx.eventsUser, fx.eventsPass)
	publisher := newEventsPublisher(t, eventsConn, testRules(t, "dev"))

	startConfigService(t, fx, func(cfg *Config) { cfg.Events = publisher })

	// A role no rule matches: the callout refuses the connection.
	_, err := nats.Connect(fx.url,
		nats.UserInfo(fx.clientUser, fx.clientPass),
		nats.Token("mock:u-mallory:mallory@example.com:not-a-declared-role"),
		nats.Timeout(waitFor),
	)
	if err == nil {
		t.Fatal("a token with no matching rule connected, want a rejection")
	}

	// Give the publisher every chance to have published something it should not have.
	drainPublisher(t, publisher)
	if msgs := streamMsgCount(t, admin); msgs != 0 {
		t.Errorf("the stream holds %d messages after a rejected connection, want 0", msgs)
	}
}

// --- helpers -------------------------------------------------------------------------------

// newEventsPublisher builds a publisher on conn, with the stream check the service does at
// startup.
func newEventsPublisher(t *testing.T, conn *nats.Conn, router *authz.Router) *events.Publisher {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()

	p, err := events.New(ctx, events.Config{
		Conn:    conn,
		Subject: testEventsSubjectPattern,
		Stream:  testEventsStream,
		Probe:   router.ProbeIdentity(),
	})
	if err != nil {
		t.Fatalf("build the events publisher: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), waitFor)
		defer closeCancel()
		_ = p.Close(closeCtx)
	})
	return p
}

// createEventsStream creates the stream the events land in, as the deployment would.
func createEventsStream(t *testing.T, conn *nats.Conn) {
	t.Helper()

	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()

	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name:       testEventsStream,
		Subjects:   []string{"dev.events.>"},
		Duplicates: 2 * time.Minute,
	}); err != nil {
		t.Fatalf("create the events stream: %v", err)
	}
}

// waitForEvent drains the publisher and returns the event stored in the stream.
func waitForEvent(t *testing.T, admin *nats.Conn, publisher *events.Publisher) events.Event {
	t.Helper()

	drainPublisher(t, publisher)

	js, err := jetstream.New(admin)
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()

	stream, err := js.Stream(ctx, testEventsStream)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}
	msg, err := stream.GetLastMsgForSubject(ctx, testEventsSubject)
	if err != nil {
		t.Fatalf("no authentication event on %s: %v", testEventsSubject, err)
	}

	var event events.Event
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		t.Fatalf("decode the event: %v", err)
	}
	return event
}

// drainPublisher closes the publisher so every queued event has been acked before the test
// looks at the stream.
func drainPublisher(t *testing.T, publisher *events.Publisher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if err := publisher.Close(ctx); err != nil {
		t.Fatalf("drain the events publisher: %v", err)
	}
}

// streamMsgCount reports how many messages the events stream holds.
func streamMsgCount(t *testing.T, admin *nats.Conn) uint64 {
	t.Helper()

	js, err := jetstream.New(admin)
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()

	stream, err := js.Stream(ctx, testEventsStream)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	return info.State.Msgs
}

// assertAnaEvent checks the payload against the token the client connected with.
func assertAnaEvent(t *testing.T, event events.Event) {
	t.Helper()

	if event.Type != events.TypeAuthenticated || event.Version != events.SchemaVersion {
		t.Errorf("type/version = %q/%d, want %q/%d",
			event.Type, event.Version, events.TypeAuthenticated, events.SchemaVersion)
	}
	if event.ID != "u-ana" {
		t.Errorf("id = %q, want the token's sub", event.ID)
	}
	if event.Name != "Ana Perez" {
		t.Errorf("name = %q, want the name claim", event.Name)
	}
	if event.Email != "ana@example.com" {
		t.Errorf("email = %q, want the email claim", event.Email)
	}
	if event.Username != "ana@example.com" {
		t.Errorf("username = %q, want the token's username", event.Username)
	}
	if len(event.Roles) != 1 || event.Roles[0] != "tester" {
		t.Errorf("roles = %v, want [tester]", event.Roles)
	}
	// The template as the RULE declares it, not the resolved path: the event travels off the box,
	// and an absolute path would publish where this deployment mounts its configuration.
	if event.Template != "person.yaml" {
		t.Errorf("template = %q, want the path the rule declares", event.Template)
	}
	if event.Instance != "dev" || event.IdentityType != "person" || event.MatchedRole != "tester" {
		t.Errorf("instance/type/matchedRole = %q/%q/%q, want dev/person/tester",
			event.Instance, event.IdentityType, event.MatchedRole)
	}
	// The session is the connection's user nkey, which the test cannot predict — but it has to
	// be there and it has to be a user key, because it is also the deduplication id.
	if len(event.Session) == 0 || event.Session[0] != 'U' {
		t.Errorf("session = %q, want the connection's user nkey", event.Session)
	}
	if event.AuthenticatedAt.IsZero() || event.ExpiresAt.IsZero() {
		t.Errorf("timestamps = %v / %v, want both set", event.AuthenticatedAt, event.ExpiresAt)
	}
	// The session must not outlive the token: the mock IdP issues an hour, so the announced
	// expiry has to be about an hour out and never zero.
	if ttl := event.ExpiresAt.Sub(event.AuthenticatedAt); ttl <= 0 || ttl > 2*time.Hour {
		t.Errorf("announced session TTL = %s, want a bounded positive one", ttl)
	}
	if event.ClientIP == "" {
		t.Errorf("client_ip is empty, want the connecting client's host")
	}
}

// connectUserPass connects with user/password credentials.
func connectUserPass(t *testing.T, url, user, password string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url, nats.UserInfo(user, password), nats.Timeout(waitFor))
	if err != nil {
		t.Fatalf("connect as %q: %v", user, err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// connectCreds connects with a .creds file.
func connectCreds(t *testing.T, url, creds string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url, nats.UserCredentials(creds), nats.Timeout(waitFor))
	if err != nil {
		t.Fatalf("connect with %q: %v", creds, err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// writeAppUserCreds mints a user of the APP account, signed with the APP signing key.
//
// Empty allow lists mean an unrestricted user, which is what the stand-in for the deployment's
// administrator needs to create a stream.
func writeAppUserCreds(t *testing.T, fx *operatorFixture, name string, allowPub, allowSub []string) string {
	t.Helper()

	userKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create user key: %v", err)
	}
	userPub, err := userKP.PublicKey()
	if err != nil {
		t.Fatalf("user pubkey: %v", err)
	}

	claims := jwt.NewUserClaims(userPub)
	claims.Name = name
	// Signed with a SIGNING key, so the JWT has to name the account it belongs to.
	claims.IssuerAccount = fx.appPub
	for _, subject := range allowPub {
		claims.Pub.Allow.Add(subject)
	}
	for _, subject := range allowSub {
		claims.Sub.Allow.Add(subject)
	}

	userJWT, err := claims.Encode(fx.appSK)
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
	return writeTempFile(t, name+"-*.creds", string(creds))
}

// TestConfigModeCoreDeliveryReachesALiveConsumer covers the other delivery mode: no stream, no
// ack, and a credential holding ONE publish permission and nothing else.
//
// It is worth its own end-to-end test for the same reason the acked one is: the claim that a
// single `publish` grant is enough can only be checked against a real server enforcing it. If
// core delivery needed an inbox — it does not, because there is no reply to receive — this test
// would fail, and the documentation would be wrong rather than optimistic.
func TestConfigModeCoreDeliveryReachesALiveConsumer(t *testing.T) {
	fx := startConfigServer(t)

	// No stream anywhere. Nothing in core delivery touches JetStream.
	eventsConn := connectUserPass(t, fx.url, fx.coreEventsUser, fx.coreEventsPass)

	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	publisher, err := events.New(ctx, events.Config{
		Conn:    eventsConn,
		Subject: testEventsSubjectPattern,
		Probe:   testRules(t, "dev").ProbeIdentity(),
	})
	if err != nil {
		t.Fatalf("build the core publisher: %v", err)
	}
	if publisher.Confirmed() {
		t.Error("Confirmed() is true with no stream configured")
	}

	// A live consumer, subscribed before the client authenticates. In core delivery this is the
	// only kind of consumer there is.
	consumer := connectUserPass(t, fx.url, fx.appAdminUser, fx.appAdminPass)
	received := make(chan []byte, 1)
	sub, err := consumer.Subscribe(testEventsSubject, func(msg *nats.Msg) { received <- msg.Data })
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe() //nolint:errcheck // test cleanup
	if err := consumer.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	startConfigService(t, fx, func(cfg *Config) { cfg.Events = publisher })

	client, err := nats.Connect(fx.url,
		nats.UserInfo(fx.clientUser, fx.clientPass),
		nats.Token(testEventsToken),
		nats.CustomInboxPrefix("_INBOX."+authz.HashUserID("u-ana")),
		nats.Timeout(waitFor),
	)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer client.Close()

	select {
	case data := <-received:
		var event events.Event
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatalf("decode the event: %v", err)
		}
		assertAnaEvent(t, event)
	case <-time.After(waitFor):
		t.Fatal("no authentication event reached the live consumer")
	}

	drainPublisher(t, publisher)
}
