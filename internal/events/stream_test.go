package events

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// These tests run a real nats-server with JetStream. What they verify cannot be verified any
// other way: whether the server ACCEPTS what the publisher sends, whether the ack comes back,
// and whether a stream that does not capture the subject is caught at startup rather than
// swallowing every event for months.

// testStream is the stream name the fixtures create.
const testStream = "AUTH_EVENTS"

// startJetStreamServer brings up an in-process nats-server with JetStream and no authorization.
// The account and permission side of the story is covered where it belongs, in the callout
// harness, which stands up both authorization modes.
func startJetStreamServer(t *testing.T) string {
	t.Helper()

	srv, err := natsserver.NewServer(&natsserver.Options{
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("build nats-server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

// connect opens a connection to url and closes it with the test.
func connect(t *testing.T, url string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// createStream creates a stream capturing subjects.
func createStream(t *testing.T, nc *nats.Conn, subjects ...string) jetstream.JetStream {
	t.Helper()

	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name:     testStream,
		Subjects: subjects,
		// The duplicate window is what makes a retry of an event whose ack was lost safe. It is
		// set explicitly here because the publisher's idempotency depends on it.
		Duplicates: 2 * time.Minute,
	}); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	return js
}

// newTestPublisher builds a publisher against url, with the stream already created.
func newTestPublisher(t *testing.T, url, subject string, queueSize int) *Publisher {
	t.Helper()

	nc := connect(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := New(ctx, Config{
		Conn:      nc,
		Subject:   subject,
		Stream:    testStream,
		Probe:     probe("prod"),
		QueueSize: queueSize,
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}
	return p
}

func TestPublisherLandsTheEventInTheStream(t *testing.T) {
	url := startJetStreamServer(t)
	js := createStream(t, connect(t, url), "prod.events.auth")

	p := newTestPublisher(t, url, "{{instance}}.events.auth", 0)
	p.Authenticated(sampleAuthentication())

	// Close drains: it is the publisher's guarantee that a shutdown does not lose queued events,
	// and here it is also the synchronisation the test needs.
	drain(t, p)

	msg := lastMsg(t, js, "prod.events.auth")

	var event Event
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		t.Fatalf("decode the stored event: %v", err)
	}
	if event.Type != TypeAuthenticated || event.Version != SchemaVersion {
		t.Errorf("type/version = %q/%d, want %q/%d", event.Type, event.Version, TypeAuthenticated, SchemaVersion)
	}
	if event.ID != "281234567890123456" || event.Email != "ana@example.com" {
		t.Errorf("id/email = %q/%q, want the authenticated identity's", event.ID, event.Email)
	}

	// The message id is what makes a retry idempotent, so it has to actually be on the message.
	if got := msg.Header.Get(jetstream.MsgIDHeader); got != sampleAuthentication().Session {
		t.Errorf("%s = %q, want the connection's user nkey", jetstream.MsgIDHeader, got)
	}
}

func TestPublisherDeduplicatesTheSameSession(t *testing.T) {
	url := startJetStreamServer(t)
	js := createStream(t, connect(t, url), "prod.events.auth")

	p := newTestPublisher(t, url, "{{instance}}.events.auth", 0)
	// The same connection announced twice — what a retry after a lost ack looks like to the
	// server. The stream's duplicate window has to collapse it, or "at least once with retries"
	// would mean duplicate logins in every consumer.
	p.Authenticated(sampleAuthentication())
	p.Authenticated(sampleAuthentication())
	drain(t, p)

	if msgs := streamMessages(t, js); msgs != 1 {
		t.Errorf("the stream holds %d messages, want 1 (the second is a duplicate of the same session)", msgs)
	}
}

func TestPublisherRefusesAMissingStream(t *testing.T) {
	url := startJetStreamServer(t)
	nc := connect(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := New(ctx, Config{
		Conn:    nc,
		Subject: "{{instance}}.events.auth",
		Stream:  testStream,
		Probe:   probe("prod"),
	})
	if err == nil {
		t.Fatal("New succeeded with no stream, want a startup error")
	}
	if !containsAll(err.Error(), "does not exist", testStream) {
		t.Errorf("error %q does not name the missing stream", err)
	}
}

func TestPublisherRefusesAStreamThatDoesNotCaptureTheSubject(t *testing.T) {
	url := startJetStreamServer(t)
	nc := connect(t, url)
	// The stream exists, JetStream is healthy, the credential works — and every event would land
	// nowhere, reporting nothing. This is the failure the startup check exists for.
	createStream(t, nc, "something.else.>")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := New(ctx, Config{
		Conn:    nc,
		Subject: "{{instance}}.events.auth",
		Stream:  testStream,
		Probe:   probe("prod"),
	})
	if err == nil {
		t.Fatal("New succeeded with a stream that does not capture the subject, want a startup error")
	}
	if !containsAll(err.Error(), "does not capture", "prod.events.auth", "something.else.>") {
		t.Errorf("error %q does not say what covers what", err)
	}
}

func TestPublisherDropsRatherThanBlockWhenJetStreamStops(t *testing.T) {
	url := startJetStreamServer(t)
	nc := connect(t, url)
	createStream(t, nc, "prod.events.auth")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := New(ctx, Config{
		Conn:    nc,
		Subject: "{{instance}}.events.auth",
		Stream:  testStream,
		Probe:   probe("prod"),
		// One slot, so the drop path is reachable without queueing a thousand events.
		QueueSize: 1,
	})
	if err != nil {
		t.Fatalf("build publisher: %v", err)
	}

	// Take the connection away: from here on nothing can be acked. The point of the test is that
	// the AUTHENTICATION path does not care — Authenticated has to keep returning immediately.
	nc.Close()

	start := time.Now()
	for i := 0; i < 20; i++ {
		in := sampleAuthentication()
		// A distinct session per call: these are different connections, not retries.
		in.Session = in.Session[:len(in.Session)-1] + string(rune('A'+i%26))
		p.Authenticated(in)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("queueing 20 events with a dead JetStream took %s: the authentication path is blocking", elapsed)
	}
	if dropped := p.dropped.Load(); dropped == 0 {
		t.Error("nothing was dropped with a full queue and a dead connection, want the drop path to have fired")
	}

	// Closing must not hang either: a shutdown that waits forever for a JetStream that is never
	// coming back is its own outage.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer closeCancel()
	if err := p.Close(closeCtx); err == nil {
		t.Error("Close reported success while events were stuck, want the deadline error")
	}
}

// drain closes the publisher and fails the test if the queued events did not make it out.
func drain(t *testing.T, p *Publisher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatalf("drain the publisher: %v", err)
	}
}

// lastMsg returns the last message stored on subject.
func lastMsg(t *testing.T, js jetstream.JetStream, subject string) *jetstream.RawStreamMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := js.Stream(ctx, testStream)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}
	msg, err := stream.GetLastMsgForSubject(ctx, subject)
	if err != nil {
		t.Fatalf("no message on %s: %v", subject, err)
	}
	return msg
}

// streamMessages reports how many messages the stream holds.
func streamMessages(t *testing.T, js jetstream.JetStream) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := js.Stream(ctx, testStream)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	return info.State.Msgs
}

// containsAll reports whether every fragment appears in text.
func containsAll(text string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			return false
		}
	}
	return true
}
