package callout

import (
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// This file implements the pre-flight check: everything that can be established about a
// deployment's wiring WITHOUT serving real traffic.
//
// It exists because the three mistakes that cost the most in this system do not announce
// themselves. A client user left in auth_users connects fine and keeps its own permissions —
// the callout never runs, and nothing anywhere says so. A target account without JetStream
// turns every KV permission into a client timeout. A handler that cannot reach the callout
// subject leaves the service running and silent while every connection is refused.
//
// Each of those is a thirty-second check here and a long afternoon otherwise.

// verifyProbeTimeout bounds each individual probe. It is short on purpose: `verify` is meant to
// answer quickly, and a probe that hangs is itself a finding.
const verifyProbeTimeout = 3 * time.Second

// verifyProbeSettle is how long to wait for an ASYNCHRONOUS permissions violation after a
// flushed subscribe. The server has already processed the SUB by then, so this only covers the
// hop back through the client's error callback.
const verifyProbeSettle = 250 * time.Millisecond

// Severity is how much a finding matters.
type Severity string

const (
	// SeverityFail is a deployment that cannot work, or one that is open. Anything at this
	// level means do not put traffic through it.
	SeverityFail Severity = "FAIL"
	// SeverityWarn is something that works but is likely not what was intended.
	SeverityWarn Severity = "WARN"
	// SeverityPass is a check that held.
	SeverityPass Severity = "PASS"
)

// Finding is the result of one check.
type Finding struct {
	// Severity is how much it matters.
	Severity Severity
	// Check names what was checked, in the deployment's own vocabulary.
	Check string
	// Detail says what was observed.
	Detail string
	// Fix says what to do about it. Empty for a passing check.
	Fix string
}

// Report is the outcome of a verification run.
type Report struct {
	Findings []Finding
}

// Add appends a finding.
func (r *Report) Add(f Finding) { r.Findings = append(r.Findings, f) }

// pass, warn and fail are shorthands, so the checks below read as prose.
func (r *Report) pass(check, detail string) { r.Add(Finding{SeverityPass, check, detail, ""}) }
func (r *Report) warn(check, detail, fix string) {
	r.Add(Finding{SeverityWarn, check, detail, fix})
}
func (r *Report) fail(check, detail, fix string) {
	r.Add(Finding{SeverityFail, check, detail, fix})
}

// OK reports whether nothing failed. Warnings do not make a deployment unusable.
func (r *Report) OK() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityFail {
			return false
		}
	}
	return true
}

// Counts returns how many findings there are at each severity.
func (r *Report) Counts() (pass, warn, fail int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityPass:
			pass++
		case SeverityWarn:
			warn++
		case SeverityFail:
			fail++
		}
	}
	return pass, warn, fail
}

// VerifyInput is what the checks need. It is deliberately not the whole Config: verification
// runs before the service is built, and asking for only these makes it usable from a test.
type VerifyInput struct {
	// Conn is the callout's own connection, already established with the handler credentials.
	Conn *nats.Conn
	// Mode is the declared server authorization mode.
	Mode Mode
	// ClientCreds, when set, is a credentials file for the user CLIENTS connect with. Supplying
	// it enables the bypass check, which is the most valuable check here.
	ClientCreds string
	// ClientUser and ClientPassword are the config-mode form of the same thing.
	ClientUser, ClientPassword string
	// NATSURL is where to reach the server for the client probe.
	NATSURL string
	// XKeyConfigured reports whether the callout has an XKey.
	XKeyConfigured bool
	// TargetAccount is the account name clients land in (config mode).
	TargetAccount string
}

// Verify runs every check that does not require serving real traffic.
//
// It never mutates anything: the probes subscribe and connect, they do not publish application
// messages or create streams.
func Verify(in VerifyInput) *Report {
	report := &Report{}

	checkHandlerConnection(in, report)
	checkCalloutSubject(in, report)
	checkClientDoesNotBypass(in, report)
	checkEncryption(in, report)

	return report
}

// checkHandlerConnection confirms the callout's own connection is usable.
//
// It is first because every other check depends on it, and because a failure here has a
// different cause per mode: an operator-mode server refuses user/password, and a config-mode
// server ignores a .creds JWT.
func checkHandlerConnection(in VerifyInput, report *Report) {
	if in.Conn == nil || !in.Conn.IsConnected() {
		report.fail("handler connection",
			"the callout is not connected to NATS",
			"check CALLOUT_NATS_URL and that the handler credential form matches the server's authorization mode")
		return
	}
	report.pass("handler connection", fmt.Sprintf("connected to %s (server %q)",
		in.Conn.ConnectedUrlRedacted(), in.Conn.ConnectedServerName()))
}

// checkCalloutSubject confirms the handler may actually serve $SYS.REQ.USER.AUTH.
//
// Without this permission the service starts, logs that it is listening, and every connection
// is refused while nothing in its own log says why: the requests simply never arrive.
func checkCalloutSubject(in VerifyInput, report *Report) {
	if in.Conn == nil || !in.Conn.IsConnected() {
		return // already reported
	}

	// A subscription permissions violation is reported ASYNCHRONOUSLY: SubscribeSync returns
	// nil, Flush succeeds, and the rejection arrives on the connection's error handler a moment
	// later. Watching only the return values reports a denied handler as working — which is the
	// same class of silent failure this command exists to catch, so it is worth the plumbing.
	// The callback's *Subscription is nil for a subscribe-permissions violation — the server
	// rejects the SUB before the client binds it to one — so the subject cannot be matched on.
	// Since this probe holds the only subscription in flight, any violation arriving here is
	// this one.
	violation := make(chan error, 1)
	previous := in.Conn.Opts.AsyncErrorCB
	in.Conn.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		if err == nil || !strings.Contains(err.Error(), "permissions violation") {
			return
		}
		select {
		case violation <- err:
		default:
		}
	})
	defer in.Conn.SetErrorHandler(previous)

	sub, err := in.Conn.SubscribeSync(AuthSubject)
	if err != nil {
		report.fail("callout subject",
			fmt.Sprintf("the handler cannot subscribe to %s: %v", AuthSubject, err),
			"grant the handler that subscription, and check it is the user declared in "+authUsersFieldName(in.Mode))
		return
	}
	defer sub.Unsubscribe() //nolint:errcheck // best effort on a probe

	// Flush forces the round trip, so the server has processed the SUB by the time it returns.
	if err := in.Conn.FlushTimeout(verifyProbeTimeout); err != nil {
		report.fail("callout subject",
			fmt.Sprintf("subscribing to %s was rejected: %v", AuthSubject, err),
			"the handler needs permission to subscribe to "+AuthSubject)
		return
	}

	// The violation callback runs on another goroutine, so give it the moment it needs to
	// arrive. Nothing arriving is the passing case.
	select {
	case err := <-violation:
		report.fail("callout subject",
			fmt.Sprintf("the handler is not allowed to subscribe to %s: %v", AuthSubject, err),
			"grant that subscription to the handler; without it the service starts, reports that it is listening, and every connection is refused while its own log stays silent")
	case <-time.After(verifyProbeSettle):
		report.pass("callout subject", "the handler can serve "+AuthSubject)
	}
}

// checkClientDoesNotBypass is the reason this command exists.
//
// If the user clients connect with is listed in auth_users (config mode) or --auth-user
// (operator mode), the server authorizes it DIRECTLY and the callout never fires. The client
// connects successfully and keeps whatever permissions that user carries — an authorization
// bypass that produces no error anywhere.
//
// The probe: connect as a client while the callout is NOT serving. A correctly wired deployment
// must REFUSE that connection, because the callout is what would have authorized it. If the
// connection succeeds, the user is bypassing.
//
// This is why the check runs before Start(): once the service is serving, a bypassing client and
// a properly authorized one both connect, and the two become indistinguishable from outside.
func checkClientDoesNotBypass(in VerifyInput, report *Report) {
	opt, ok := clientProbeOption(in)
	if !ok {
		report.warn("client bypass",
			"not checked: no client credentials supplied",
			"pass the credentials clients use (--client-creds, or --client-user with --client-password) to check the highest-impact misconfiguration in this system")
		return
	}

	nc, err := nats.Connect(in.NATSURL, opt,
		nats.Timeout(verifyProbeTimeout),
		nats.MaxReconnects(0),
		nats.Name("nats-auth-callout-verify"),
	)
	if err != nil {
		// The refusal is the CORRECT outcome: it means the server delegated to a callout that is
		// not answering yet.
		report.pass("client bypass",
			"the client credential is refused while the callout is not serving, so connections do go through the callout")
		return
	}
	defer nc.Close()

	report.fail("client bypass",
		"the client credential CONNECTED while the callout is not serving, so the callout is bypassed entirely and this connection keeps whatever permissions that user carries",
		"remove that user from "+authUsersFieldName(in.Mode)+" — only the callout's own handler belongs there")
}

// checkEncryption reports on XKey configuration.
//
// A callout with no XKey means the clients' access tokens travel in the clear on
// $SYS.REQ.USER.AUTH, where anything else in that account can read them. It is a warning rather
// than a failure because a server with no XKey configured is a working, if weaker, deployment.
func checkEncryption(in VerifyInput, report *Report) {
	if in.XKeyConfigured {
		report.pass("request encryption", "an XKey is configured, so callout requests are encrypted")
		return
	}
	report.warn("request encryption",
		"no XKey: callout requests, which carry the clients' access tokens, travel in the clear over "+AuthSubject,
		"generate a curve key and declare its public half in "+xkeyFieldName(in.Mode))
}

// clientProbeOption builds the connection option for the client probe, reporting whether any
// client credential was supplied at all.
func clientProbeOption(in VerifyInput) (nats.Option, bool) {
	switch {
	case in.ClientCreds != "":
		return nats.UserCredentials(in.ClientCreds), true
	case in.ClientUser != "":
		return nats.UserInfo(in.ClientUser, in.ClientPassword), true
	default:
		return nil, false
	}
}

// authUsersFieldName names the server-side field the handler is declared in, so a finding can
// point at the right place in the right file.
func authUsersFieldName(mode Mode) string {
	if mode == ModeConfig {
		return "authorization.auth_callout.auth_users (nats-server.conf)"
	}
	return "--auth-user (nsc edit authcallout)"
}

// xkeyFieldName does the same for the encryption key.
func xkeyFieldName(mode Mode) string {
	if mode == ModeConfig {
		return "authorization.auth_callout.xkey (nats-server.conf)"
	}
	return "--curve (nsc edit authcallout)"
}

// String renders a report as the command's output.
func (r *Report) String() string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%-5s %s\n", f.Severity, f.Check)
		fmt.Fprintf(&b, "      %s\n", f.Detail)
		if f.Fix != "" {
			fmt.Fprintf(&b, "      fix: %s\n", f.Fix)
		}
	}

	pass, warn, fail := r.Counts()
	fmt.Fprintf(&b, "\n%d passed, %d warning(s), %d failure(s)\n", pass, warn, fail)
	if fail > 0 {
		b.WriteString("\nThis deployment is not ready to serve traffic.\n")
	}
	return b.String()
}
