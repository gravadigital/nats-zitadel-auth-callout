package callout

import (
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/nkeys"
)

// LoadKeyPair resolves an nkey from a configuration value that may be either the seed itself
// or the path to a file containing it.
//
// Both forms are accepted because two deployment styles coexist: the bootstrap writes the
// seeds to files (mounted as secrets), whereas an orchestrator usually injects them as
// environment variables. Telling them apart by the seed's prefix avoids having two variables
// per key.
func LoadKeyPair(seedOrPath string) (nkeys.KeyPair, error) {
	seed, err := resolveSeed(seedOrPath)
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("callout: invalid seed: %w", err)
	}
	return kp, nil
}

// LoadCurveKeyPair resolves a curve25519 pair (XKey), whose seed starts with SX.
func LoadCurveKeyPair(seedOrPath string) (nkeys.KeyPair, error) {
	seed, err := resolveSeed(seedOrPath)
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromCurveSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("callout: invalid XKey seed: %w", err)
	}
	return kp, nil
}

// resolveSeed returns the seed, reading it from the file if what was passed is a path.
//
// An nkey seed always starts with `S` and contains no path separators, so the prefix is
// enough to tell them apart without touching the filesystem.
func resolveSeed(seedOrPath string) (string, error) {
	value := strings.TrimSpace(seedOrPath)
	if value == "" {
		return "", fmt.Errorf("callout: empty seed")
	}

	if strings.HasPrefix(value, "S") && !strings.ContainsAny(value, "/\\") {
		return value, nil
	}

	data, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("callout: read the seed from %q: %w", value, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadPubKey reads an account public key, accepting — just like LoadKeyPair — either the
// value directly or a path.
func ReadPubKey(valueOrPath string) (string, error) {
	value := strings.TrimSpace(valueOrPath)
	if value == "" {
		return "", fmt.Errorf("callout: empty pubkey")
	}
	// An account public key starts with `A`.
	if strings.HasPrefix(value, "A") && !strings.ContainsAny(value, "/\\") {
		return value, nil
	}
	data, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("callout: read the pubkey from %q: %w", value, err)
	}
	return strings.TrimSpace(string(data)), nil
}
