package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
)

// DefaultNameClaim and DefaultEmailClaim are the standard OIDC claims. Unlike the roles claim
// — which has no cross-provider convention and therefore cannot be defaulted — these two are
// in the OIDC core spec, so defaulting them is not guessing.
const (
	DefaultNameClaim  = "name"
	DefaultEmailClaim = "email"
)

// defaultQueueSize bounds how many events may be waiting to be published.
//
// The queue exists so the authentication path never waits for JetStream. It is bounded so that
// a JetStream that stops acking cannot grow the process's memory without limit: past this
// point events are DROPPED, loudly, which is the right trade when the alternative is an
// authentication service that dies of an event backlog.
const defaultQueueSize = 1024

// publishTimeout bounds one attempt at getting an ack.
const publishTimeout = 5 * time.Second

// maxPublishAttempts is how many times one event is attempted before it is given up on.
//
// Retrying is safe because every publish carries a Nats-Msg-Id (the connection's user nkey):
// within the stream's duplicate window the server collapses a retry of an ack that was lost on
// the way back, so an ambiguous timeout cannot produce two events for one connection.
const maxPublishAttempts = 3

// retryBackoff is the wait before each retry.
var retryBackoff = []time.Duration{250 * time.Millisecond, time.Second}

// streamCheckTimeout bounds the startup check against the stream.
const streamCheckTimeout = 5 * time.Second

// Config holds the publisher's dependencies.
type Config struct {
	// Conn is the connection the events are published on. It is a SEPARATE connection from the
	// callout's own, in the account where the consumers live: the callout handler connects in
	// the AUTH account, whose subject namespace no application client can see.
	Conn *nats.Conn
	// Subject is the subject pattern, with {{placeholder}} references expanded per event
	// exactly as a permission template's subjects are.
	Subject string
	// Stream is the name of the JetStream stream that must capture Subject. It is required:
	// waiting for an ack is only meaningful if something is there to ack, and naming the stream
	// is what lets startup verify the subject is actually covered by it.
	Stream string
	// NameClaim and EmailClaim are the claim paths the name and email are read from.
	NameClaim  string
	EmailClaim string
	// Probe is the identity the subject pattern is validated against at startup.
	Probe authz.Identity
	// Logger is the service's logger.
	Logger *zerolog.Logger
	// QueueSize overrides defaultQueueSize. Tests use it to make the drop path reachable.
	QueueSize int
}

// Publisher publishes an event per authenticated connection.
//
// A nil *Publisher is a working "disabled" publisher: every method is safe on it. That is what
// keeps the feature opt-in without a flag at the call site — with no subject configured the
// service holds nil and the callout path is unchanged.
type Publisher struct {
	js      jetstream.JetStream
	subject string
	stream  string

	nameClaim  string
	emailClaim string

	log *zerolog.Logger

	// queue hands events from the callout's goroutine to the publishing one. Nothing on the
	// authentication path ever blocks on it: a full queue drops.
	queue chan queued
	// done is closed when the worker has finished draining the queue.
	done chan struct{}
	// hardStop tells the worker to stop retrying, for a shutdown that has run out of patience.
	hardStop  chan struct{}
	closeOnce sync.Once
	stopOnce  sync.Once

	// dropped and failed count what did not make it: dropped never left the queue, failed
	// exhausted its attempts. They are reported at shutdown, where a number is more useful than
	// the individual log lines that already went out.
	dropped atomic.Uint64
	failed  atomic.Uint64
}

// queued is one event on its way out. The payload is already marshalled: doing it on the
// callout's goroutine costs microseconds and keeps the worker to network I/O only, so a
// marshalling problem is reported with the connection's context still at hand.
type queued struct {
	subject string
	data    []byte
	msgID   string
	userID  string
}

// New builds the publisher and verifies at startup everything that can be verified before
// serving traffic:
//
//   - the subject pattern expands against the probe identity and is a valid, literal subject;
//   - the stream exists;
//   - the stream actually CAPTURES that subject.
//
// The last one is the check worth having. A stream whose subject filter does not match the
// configured subject produces no permissions error and no publish error worth the name — the
// event simply lands nowhere, and the deployment believes it is auditing logins that no stream
// has ever seen.
func New(ctx context.Context, cfg Config) (*Publisher, error) {
	switch {
	case cfg.Conn == nil:
		return nil, errors.New("events: missing the NATS connection")
	case cfg.Subject == "":
		return nil, errors.New("events: missing the subject")
	case cfg.Stream == "":
		return nil, errors.New("events: missing the stream name")
	}

	probeSubject, err := ProbeSubject(cfg.Subject, cfg.Probe)
	if err != nil {
		return nil, err
	}

	js, err := jetstream.New(cfg.Conn)
	if err != nil {
		return nil, fmt.Errorf("events: JetStream context: %w", err)
	}

	log := cfg.Logger
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}

	p := &Publisher{
		js:         js,
		subject:    cfg.Subject,
		stream:     cfg.Stream,
		nameClaim:  orDefault(cfg.NameClaim, DefaultNameClaim),
		emailClaim: orDefault(cfg.EmailClaim, DefaultEmailClaim),
		log:        log,
		queue:      make(chan queued, queueSize),
		done:       make(chan struct{}),
		hardStop:   make(chan struct{}),
	}

	if err := CheckStream(ctx, cfg.Conn, cfg.Stream, probeSubject); err != nil {
		return nil, err
	}

	go p.run()
	return p, nil
}

// CheckStream confirms that streamName exists on conn's account and that it captures subject.
//
// It is exported because two callers need exactly this answer: the publisher, at startup, and
// `auth-callout verify`, before anything serves traffic. The subject has to be an already
// expanded, literal one.
//
// The coverage half is the reason it exists. A stream whose subject filter does not match what
// the service publishes reports nothing at runtime — no permissions error, and an ack that
// never comes looks like a dozen other things — so the events simply never accumulate anywhere.
func CheckStream(ctx context.Context, conn *nats.Conn, streamName, subject string) error {
	js, err := jetstream.New(conn)
	if err != nil {
		return fmt.Errorf("events: JetStream context: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, streamCheckTimeout)
	defer cancel()

	stream, err := js.Stream(ctx, streamName)
	if err != nil {
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return fmt.Errorf("events: the stream %q does not exist. Create it in the account the events connection lands in, "+
				"covering %q — the callout deliberately cannot create streams: %w", streamName, subject, err)
		}
		return fmt.Errorf("events: read the stream %q (the events credential needs pub on $JS.API.STREAM.INFO.%s): %w",
			streamName, streamName, err)
	}

	subjects := stream.CachedInfo().Config.Subjects
	if !subjectsCover(subjects, subject) {
		return fmt.Errorf("events: the stream %q does not capture %q (it covers %s). "+
			"Nothing would report this at runtime: the publish is accepted and the event lands in no stream",
			streamName, subject, strings.Join(subjects, ", "))
	}
	return nil
}

// ProbeSubject validates the configured subject pattern and expands it against an identity,
// without building a publisher.
//
// It holds every rule about what an events subject may be, so that the service at startup and
// `auth-callout verify` before it reach the same verdict on the same configuration:
//
//   - it may not use {{service}}, which is empty for people while events are published for
//     every authenticated connection;
//   - it has to expand to a valid subject (no unknown placeholder, no empty segment);
//   - it has to be LITERAL — a message is published to one subject, not to a wildcard;
//   - it may not live in the server's own `$` namespaces.
func ProbeSubject(pattern string, probe authz.Identity) (string, error) {
	for _, name := range authz.SubjectPlaceholders(pattern) {
		if name == "service" {
			return "", fmt.Errorf("events: the subject %q uses {{service}}, which is empty for people; "+
				"the events subject has to expand for every authenticated identity", pattern)
		}
	}

	subject, err := authz.ExpandSubject(pattern, probe)
	if err != nil {
		return "", fmt.Errorf("events: subject %q: %w", pattern, err)
	}
	if strings.ContainsAny(subject, "*>") {
		return "", fmt.Errorf("events: the subject %q contains a wildcard; a message is published to one literal subject", pattern)
	}
	if strings.HasPrefix(subject, "$") {
		// $SYS, $JS and $KV are the server's own namespaces. Publishing an application event
		// into one of them is never intended, and the failure would be reported as something
		// else entirely.
		return "", fmt.Errorf("events: the subject %q is in a reserved namespace (it starts with `$`)", subject)
	}
	return subject, nil
}

// Subject reports the configured subject pattern, for the startup log line.
func (p *Publisher) Subject() string {
	if p == nil {
		return ""
	}
	return p.subject
}

// Stream reports the configured stream name.
func (p *Publisher) Stream() string {
	if p == nil {
		return ""
	}
	return p.stream
}

// Authenticated queues an event for a connection that has just been authenticated.
//
// It never blocks and never fails the caller: it runs on the goroutine that serves the callout
// subject — one per subscription, delivering in order — so anything that waits here delays
// every connection queued behind it. A full queue is a dropped event and an error in the log.
func (p *Publisher) Authenticated(in Authentication) {
	if p == nil {
		return
	}

	subject, err := authz.ExpandSubject(p.subject, in.Identity)
	if err != nil {
		// Startup validated the pattern against the probe identity, so this is a value the
		// probe could not represent. It is logged rather than fatal: the connection is already
		// authenticated and refusing it now would be worse than not announcing it.
		p.log.Error().Err(err).Str("sub", in.Identity.UserID).Msg("expanding the authentication event subject failed")
		return
	}

	data, err := json.Marshal(newEvent(in, p.nameClaim, p.emailClaim))
	if err != nil {
		p.log.Error().Err(err).Str("sub", in.Identity.UserID).Msg("encoding the authentication event failed")
		return
	}

	item := queued{subject: subject, data: data, msgID: in.Session, userID: in.Identity.UserID}
	select {
	case p.queue <- item:
	default:
		count := p.dropped.Add(1)
		p.log.Error().
			Str("sub", in.Identity.UserID).
			Str("subject", subject).
			Uint64("droppedTotal", count).
			Msg("the authentication event queue is full: event dropped (JetStream is not keeping up or not acking)")
	}
}

// run is the publishing goroutine. One is enough: it exists to keep the ack off the
// authentication path, not to parallelise, and events for one user staying in order is worth
// more than the throughput a pool would add.
func (p *Publisher) run() {
	defer close(p.done)
	for item := range p.queue {
		p.publish(item)
	}
}

// publish sends one event and waits for the ack, retrying an inconclusive attempt.
func (p *Publisher) publish(item queued) {
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
		ack, err := p.js.Publish(ctx, item.subject, item.data,
			jetstream.WithMsgID(item.msgID),
			// The server rejects the message if the subject does not belong to this stream. It
			// makes a stream that was renamed or re-filtered after startup an error rather than
			// an event quietly landing somewhere else.
			jetstream.WithExpectStream(p.stream),
		)
		cancel()

		if err == nil {
			p.log.Debug().
				Str("sub", item.userID).
				Str("subject", item.subject).
				Str("stream", ack.Stream).
				Uint64("seq", ack.Sequence).
				Bool("duplicate", ack.Duplicate).
				Msg("authentication event published")
			return
		}

		// A server-side rejection is deterministic: the expected stream does not match, the
		// message is too large, the stream is at its limit. Retrying reproduces it.
		var apiErr *jetstream.APIError
		permanent := errors.As(err, &apiErr)

		if permanent || attempt >= maxPublishAttempts {
			count := p.failed.Add(1)
			p.log.Error().Err(err).
				Str("sub", item.userID).
				Str("subject", item.subject).
				Str("stream", p.stream).
				Int("attempts", attempt).
				Uint64("failedTotal", count).
				Msg("publishing the authentication event failed: the event is lost")
			return
		}

		wait := retryBackoff[min(attempt-1, len(retryBackoff)-1)]
		p.log.Warn().Err(err).
			Str("sub", item.userID).
			Int("attempt", attempt).
			Dur("retryIn", wait).
			Msg("publishing the authentication event failed; retrying")

		select {
		case <-time.After(wait):
		case <-p.hardStop:
			return
		}
	}
}

// Close stops accepting events and waits for the queued ones to be published.
//
// Draining matters precisely because delivery is acked: a deployment that asked for confirmed
// events should not lose the last few to a rolling restart. The wait is bounded by ctx —
// shutting down eventually wins over announcing a login.
func (p *Publisher) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() { close(p.queue) })

	var err error
	select {
	case <-p.done:
	case <-ctx.Done():
		// Tell the worker to stop waiting between retries, so the drain ends promptly rather
		// than holding the process open for a JetStream that is not answering.
		p.stopOnce.Do(func() { close(p.hardStop) })
		err = fmt.Errorf("events: %d event(s) still queued at shutdown: %w", len(p.queue), ctx.Err())
	}

	if dropped, failed := p.dropped.Load(), p.failed.Load(); dropped > 0 || failed > 0 {
		p.log.Warn().
			Uint64("dropped", dropped).
			Uint64("failed", failed).
			Msg("authentication events that never reached the stream")
	}
	return err
}

// subjectsCover reports whether any of the stream's subject filters matches subject.
func subjectsCover(filters []string, subject string) bool {
	for _, filter := range filters {
		if subjectMatches(filter, subject) {
			return true
		}
	}
	return false
}

// subjectMatches applies NATS subject matching: `*` covers exactly one token, `>` covers one
// or more trailing tokens.
//
// It is implemented here rather than imported because the only public implementation lives in
// the nats-server module, which is a test dependency: pulling the whole server into the
// binary to compare two subjects is not a trade worth making.
func subjectMatches(filter, subject string) bool {
	filterTokens := strings.Split(filter, ".")
	subjectTokens := strings.Split(subject, ".")

	for i, token := range filterTokens {
		if token == ">" {
			// `>` matches the rest, but there has to BE a rest.
			return i < len(subjectTokens)
		}
		if i >= len(subjectTokens) {
			return false
		}
		if token != "*" && token != subjectTokens[i] {
			return false
		}
	}
	return len(filterTokens) == len(subjectTokens)
}

// orDefault returns value, or fallback when value is empty.
func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
