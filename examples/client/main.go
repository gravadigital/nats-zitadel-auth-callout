// Command client is a minimal NATS client authenticated through the auth callout.
//
// It exists because connecting is where adopters lose the most time, and the reason is always
// one of the same three things:
//
//   - the CREDENTIALS are not the client's identity. Every client connects with the same
//     sentinel credential, which grants nothing on its own; the identity is the access token.
//   - the TOKEN goes in the CONNECT frame, not in a header or a message body.
//   - the INBOX PREFIX has to be set explicitly. Its absence is the failure that says the
//     least: requests are delivered, the service replies, and the reply never arrives.
//
// This is a reference, not a library. Copy the three lines that matter into your own client.
//
// Usage:
//
//	client --creds sentinel.creds --token "$ACCESS_TOKEN" --subject dev.<user-id>.demo.ping
//
// With CALLOUT_INBOX_MODE=passthrough on the callout, pass --no-inbox-prefix: in that mode the
// server expects the client's default inbox and a scoped one would be denied.
package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		url           = flag.String("url", "nats://127.0.0.1:4222", "NATS URL")
		creds         = flag.String("creds", "", "sentinel credentials file (required)")
		token         = flag.String("token", "", "access token from the identity provider (required)")
		subject       = flag.String("subject", "", "subject to send a request to (required)")
		payload       = flag.String("payload", "ping", "request payload")
		userID        = flag.String("user-id", "", "the token's `sub`, when it cannot be read from the token itself (mock tokens, opaque tokens)")
		noInboxPrefix = flag.Bool("no-inbox-prefix", false, "do not set a custom inbox prefix (for CALLOUT_INBOX_MODE=passthrough)")
		timeout       = flag.Duration("timeout", 5*time.Second, "request timeout")
	)
	flag.Parse()

	switch {
	case *creds == "":
		return errors.New("--creds is required")
	case *token == "":
		return errors.New("--token is required")
	case *subject == "":
		return errors.New("--subject is required")
	}

	opts := []nats.Option{
		// The sentinel credential authorizes NOTHING by itself: it exists so the server hands
		// the connection to the callout instead of authorizing it directly. It is the same file
		// for every client and safe to distribute.
		nats.UserCredentials(*creds),

		// The access token IS the identity. The callout verifies it, reads the roles, and mints
		// the permissions this connection gets. nats.Token() puts it in the CONNECT frame;
		// nats.UserInfo("", token) would also work, since the callout accepts either.
		nats.Token(*token),

		nats.Name("example-client"),
		nats.Timeout(*timeout),
	}

	if !*noInboxPrefix {
		// The part that is easy to miss. Permissions scope this client's replies to
		// `_INBOX.<hash(user-id)>`; the default random `_INBOX.<nuid>` matches no permission, so
		// the subscription is denied and replies silently never arrive.
		//
		// The hash is derived from the token's own `sub`, with no side channel — which is what
		// makes it reproducible in any language. See cmd/session for the reference.
		// Normally the client reads its own `sub` straight out of its token. --user-id covers
		// the cases where it cannot: a mock token in development, or an opaque one.
		sub := *userID
		if sub == "" {
			var err error
			if sub, err = subjectFromToken(*token); err != nil {
				return fmt.Errorf("%w (pass --user-id to set it explicitly)", err)
			}
		}
		prefix := "_INBOX." + hashUserID(sub)
		opts = append(opts, nats.CustomInboxPrefix(prefix))
		fmt.Printf("user id      %s\ninbox prefix %s\n", sub, prefix)
	}

	nc, err := nats.Connect(*url, opts...)
	if err != nil {
		// Worth distinguishing: an authorization error means the callout refused the token or
		// no rule matched it, whereas a timeout usually means the callout is not answering at
		// all. See docs/troubleshooting.md.
		return fmt.Errorf("connect: %w", err)
	}
	defer nc.Close()

	fmt.Printf("connected to %s\n\n", nc.ConnectedUrlRedacted())

	reply, err := nc.Request(*subject, []byte(*payload), *timeout)
	if err != nil {
		// A denied publish is reported asynchronously, so a request that is refused looks like
		// a timeout rather than a permissions error.
		return fmt.Errorf("request to %q: %w (a permissions failure looks like this too — check the nats-server log)", *subject, err)
	}

	fmt.Printf("reply: %s\n", reply.Data)
	return nil
}

// hashUserID derives the inbox token from a user id: sha256, base32 without padding,
// lowercased, first 16 characters.
//
// It is reimplemented here rather than imported so this file can be copied into another project
// as-is — which is the point of an example. It has to match the callout exactly, so treat
// `go run ./cmd/session <sub>` as the reference when porting it to another language: a prefix
// that differs by one character is a subscription nobody authorizes, and the symptom is replies
// that never arrive.
//
// The encoding is chosen so the result is safe in a NATS subject: base32 has no `.`, `*` or `>`.
func hashUserID(userID string) string {
	sum := sha256.Sum256([]byte(userID))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(encoded[:16])
}

// subjectFromToken pulls the `sub` out of a JWT WITHOUT verifying it.
//
// That is safe here and only here: a client reading its own identity to build its own inbox
// prefix. A forged `sub` would only produce a prefix whose permission the callout never grants.
// Verification is the callout's job, against the provider's JWKS.
func subjectFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("the token is not a JWT (an opaque token cannot be verified by the callout either — see docs/zitadel.md)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode the token payload: %w", err)
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("parse the token payload: %w", err)
	}
	if claims.Subject == "" {
		return "", errors.New("the token carries no `sub`")
	}
	return claims.Subject, nil
}
