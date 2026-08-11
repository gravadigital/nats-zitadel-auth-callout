package authz

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"testing"
)

// exampleClientHashUserID is a copy of the derivation in examples/client/main.go.
//
// That example reimplements the hash instead of importing it, so it can be copied into another
// project as-is. The duplication is deliberate; this test is what keeps it honest.
func exampleClientHashUserID(userID string) string {
	sum := sha256.Sum256([]byte(userID))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(encoded[:16])
}

// TestExampleClientHashMatches pins the example client's inbox derivation to the callout's.
//
// If they drift, the example produces a prefix no permission authorizes, and the failure it
// causes is the quietest one in the system: requests are delivered, the service replies, and
// the reply never arrives. Nothing else in the test suite would notice.
func TestExampleClientHashMatches(t *testing.T) {
	for _, userID := range []string{
		"u-ana",
		"100000000000000001",               // a numeric provider id
		"auth0|507f1f77bcf86cd799439011",   // Auth0's format
		"0198f3a2-1c4e-7c3a-9f2b-6d5e4c3b", // a UUID
		"x",
		"",
	} {
		if got, want := exampleClientHashUserID(userID), HashUserID(userID); got != want {
			t.Errorf("sub %q: examples/client derives %q, the callout derives %q — clients using the example would subscribe to an inbox nobody authorizes",
				userID, got, want)
		}
	}
}
