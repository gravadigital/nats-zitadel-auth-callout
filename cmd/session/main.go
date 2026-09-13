// Command session prints the identity the callout would derive — user id and inbox prefix —
// for a Zitadel `sub`.
//
// It exists for two reasons:
//
//   - Diagnosis: to read a subject from a log or from monitoring and tell whose it is.
//   - Contract with clients: every client has to derive its own user id hash in order to set
//     its inbox prefix. This command is the reference to verify an implementation in another
//     language against.
//
// Usage:
//
//	session <sub> [instance]            # from the Zitadel `sub`
//	session --token <access-token>      # from a token (extracts the `sub` from it)
//
// The --token mode does NOT verify the signature: it only decodes the payload to pull out the
// `sub`. Verifying is the callout's job.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
)

// defaultInstance is the instance assumed when none is passed. It matches the callout
// binary's default.
const defaultInstance = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "session: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: session <sub> [instance]  |  session --token <access-token> [instance]")
	}

	var subject string
	instance := defaultInstance

	if args[0] == "--token" {
		if len(args) < 2 {
			return fmt.Errorf("--token needs the access token")
		}
		var err error
		subject, err = subjectFromToken(args[1])
		if err != nil {
			return err
		}
		if len(args) > 2 {
			instance = args[2]
		}
	} else {
		subject = args[0]
		if len(args) > 1 {
			instance = args[1]
		}
	}

	if instance = strings.TrimSpace(instance); instance == "" {
		instance = defaultInstance
	}

	id := authz.Identity{
		Instance: instance,
		UserID:   subject,
	}

	fmt.Printf("user-id   %s\n", id.UserID)
	fmt.Printf("inbox     %s\n", id.InboxPrefix())
	fmt.Printf("pub       %s.%s.<svc>.<method>\n", id.Instance, id.UserID)
	return nil
}

// subjectFromToken pulls the `sub` out of a JWT payload. It does not verify the signature: it
// is a diagnostic helper, and the callout is what validates.
func subjectFromToken(token string) (string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("does not look like a JWT (it has %d parts instead of 3): "+
			"if Zitadel issued an opaque token, set the access token type to JWT", len(parts))
	}

	// The payload comes in base64url without padding.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode the token payload: %w", err)
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse the token payload: %w", err)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("the token carries no `sub`")
	}
	return claims.Subject, nil
}
