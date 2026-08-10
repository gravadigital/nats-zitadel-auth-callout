// Package authz translates an authenticated identity (role + user type) into the set of
// NATS permissions the callout mints into the User JWT.
//
// The model has two pieces:
//
//	rules.yaml   token role -> (user type, template)          [routing, first-match-wins]
//	templates/   template -> pub/sub permissions + KV access  [the concrete permission]
//
// Both are mounted by path and read at startup: changing who can do what does NOT require
// recompiling.
package authz

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Template errors.
var (
	// ErrUnknownPlaceholder flags a template using a {{...}} that does not exist.
	ErrUnknownPlaceholder = errors.New("authz: unknown placeholder in template")
	// ErrInvalidSubject flags a subject that, once expanded, is not a valid NATS subject.
	ErrInvalidSubject = errors.New("authz: invalid subject")
	// ErrInvalidKVAccess flags a KV access level that does not exist.
	ErrInvalidKVAccess = errors.New("authz: invalid KV access level")
	// ErrEmptyBucket flags a KV entry with no bucket.
	ErrEmptyBucket = errors.New("authz: missing bucket in kv entry")
)

// placeholderRE captures {{name}} with optional spaces: {{ session }} works too.
var placeholderRE = regexp.MustCompile(`\{\{\s*([a-z][a-z0-9_]*)\s*\}\}`)

// Access levels for the DATA in a KV bucket.
//
// A bucket's lifecycle (create, reconfigure, purge) is a SEPARATE axis: KVAccess.Manage.
// They are different things and it pays to be able to combine them: the BFF owns the
// preferences bucket — it creates and migrates it — but only READS the preferences, because
// writing someone's preference belongs to that someone. A single "admin" level that
// included writing could not express that.
const (
	// KVNone grants no access to the data. It is useful combined with Manage: the service
	// administering a bucket's lifecycle does not necessarily have to be able to read what
	// is inside (e.g. the one running migrations on someone else's bucket).
	KVNone = "none"
	// KVRead allows opening the bucket and reading keys (Get).
	KVRead = "read"
	// KVReadWrite adds writing and deleting keys (Put/Delete).
	KVReadWrite = "read-write"
)

// Template is a permission template: the YAML as written in config/templates/. Subjects may
// carry {{...}} placeholders that are expanded per session with the already-authenticated
// identity (see Identity.placeholders).
type Template struct {
	// Pub holds the publish permissions.
	Pub SubjectSet `yaml:"pub"`
	// Sub holds the subscribe permissions.
	Sub SubjectSet `yaml:"sub"`
	// KV declares high-level access to KV buckets. The loader translates them into the
	// concrete $KV.*/$JS.API.* subjects and appends them to Pub/Sub — that way a template
	// does not have to know the JetStream protocol.
	KV []KVAccess `yaml:"kv"`
	// Response controls allow_responses: it enables replying to the caller's inbox without
	// an explicit pub permission toward that inbox. It is what a service needs in order to
	// answer requests.
	Response *ResponseRule `yaml:"response"`
}

// SubjectSet is an allow/deny pair of subjects. NATS evaluates deny over allow, so deny is
// useful for trimming a broad allow (e.g. allowing `svc.>` minus one method).
type SubjectSet struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// KVAccess is a declared access to a KV bucket.
type KVAccess struct {
	// Bucket is the bucket name (without the stream's KV_ prefix).
	Bucket string `yaml:"bucket"`
	// Access is access to the DATA: read | read-write. Defaults to read.
	Access string `yaml:"access"`
	// Manage enables the bucket's LIFECYCLE: creating, reconfiguring, deleting and purging
	// it. It is orthogonal to Access, and every bucket needs exactly one service that has
	// it — otherwise nobody can create the bucket and data operations fail with
	// "stream not found" without saying why.
	Manage bool `yaml:"manage"`
	// Keys narrows WHICH keys the permission reaches, as a NATS subject pattern relative to
	// the bucket. It accepts placeholders: `{{user_id}}.>` lets the caller operate only
	// under its own user id. Defaults to `>` (all of them).
	Keys string `yaml:"keys"`
	// Watch enables Watch()/Keys(), which create an ephemeral consumer over the bucket. It
	// is separate because it cannot be narrowed by key: a watcher sees the whole bucket.
	Watch bool `yaml:"watch"`
}

// ResponseRule is allow_responses: how many replies and for how long.
type ResponseRule struct {
	Max int    `yaml:"max"`
	TTL string `yaml:"ttl"`
}

// Permissions is the already-expanded result: what goes into the User JWT.
type Permissions struct {
	PubAllow []string
	PubDeny  []string
	SubAllow []string
	SubDeny  []string
	// RespMax and RespTTL are allow_responses; RespMax 0 means no allow_responses.
	RespMax int
	RespTTL time.Duration
}

// LoadTemplate reads and parses a template, and validates that it expands cleanly. The
// validation happens here, at startup, against a probe identity: a mistyped placeholder or
// an invalid subject breaks startup instead of emitting a broken JWT in production.
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read template %q: %w", path, err)
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("authz: parse template %q: %w", path, err)
	}
	// Expansion dry run: catches unknown placeholders, empty buckets, invalid access levels
	// and malformed subjects before serving any traffic.
	probe := Identity{Instance: "probe", UserID: "probe", Service: "probe"}
	if _, err := t.Expand(probe); err != nil {
		return nil, fmt.Errorf("authz: validate template %q: %w", path, err)
	}
	return &t, nil
}

// Expand resolves the template against a concrete identity and returns the final
// permissions, with KV access already translated into subjects.
func (t *Template) Expand(id Identity) (*Permissions, error) {
	vars := id.placeholders()

	pubAllow, err := expandAll(t.Pub.Allow, vars)
	if err != nil {
		return nil, err
	}
	pubDeny, err := expandAll(t.Pub.Deny, vars)
	if err != nil {
		return nil, err
	}
	subAllow, err := expandAll(t.Sub.Allow, vars)
	if err != nil {
		return nil, err
	}
	subDeny, err := expandAll(t.Sub.Deny, vars)
	if err != nil {
		return nil, err
	}

	// KV access is appended to the same allow-lists: to NATS a KV permission is nothing
	// special, it is pub/sub over JetStream's internal subjects.
	if len(t.KV) > 0 {
		// Every JetStream client starts by asking about the account. It is not per bucket, so
		// it is granted once rather than per entry. Without it, initializing the JetStream
		// context hangs and the error the client sees is a timeout, which says nothing about
		// the real cause.
		pubAllow = append(pubAllow, jsAccountInfoSubject)

		for _, kv := range t.KV {
			kvPub, kvSub, err := kv.subjects(vars)
			if err != nil {
				return nil, err
			}
			pubAllow = append(pubAllow, kvPub...)
			subAllow = append(subAllow, kvSub...)
		}
	}

	perms := &Permissions{
		PubAllow: pubAllow,
		PubDeny:  pubDeny,
		SubAllow: subAllow,
		SubDeny:  subDeny,
	}

	if t.Response != nil && t.Response.Max > 0 {
		perms.RespMax = t.Response.Max
		perms.RespTTL = defaultResponseTTL
		if t.Response.TTL != "" {
			ttl, err := time.ParseDuration(t.Response.TTL)
			if err != nil {
				return nil, fmt.Errorf("authz: response.ttl %q: %w", t.Response.TTL, err)
			}
			perms.RespTTL = ttl
		}
	}

	return perms, nil
}

// defaultResponseTTL is how long allow_responses lasts when the template sets `max` but not
// `ttl`. 30s is the NATS default.
const defaultResponseTTL = 30 * time.Second

// jsAccountInfoSubject is the account's JetStream info request. Every client issues it when
// initializing its JetStream context. It exposes the account's limits and usage, not the
// data in any bucket.
const jsAccountInfoSubject = "$JS.API.INFO"

// subjects translates a KVAccess into the pub/sub subjects that access level requires.
//
// The mapping comes from the JetStream KV protocol (verified against nats.go/jetstream):
//
//	open bucket    pub  $JS.API.STREAM.INFO.KV_<b>
//	Get(key)       pub  $JS.API.DIRECT.GET.KV_<b>.$KV.<b>.<key>   (get-last-by-subject)
//	               sub  $KV.<b>.<key>                             (the value arrives)
//	Put/Delete     pub  $KV.<b>.<key>
//	Watch/Keys     pub  $JS.API.CONSUMER.CREATE.KV_<b>.>
//
// The fact that direct-get carries the key INSIDE the subject is what makes it possible to
// scope reads by key — and therefore by user, via the {{user_id}} placeholder.
func (k KVAccess) subjects(vars map[string]string) (pub, sub []string, err error) {
	if k.Bucket == "" {
		return nil, nil, ErrEmptyBucket
	}
	bucket, err := expandOne(k.Bucket, vars)
	if err != nil {
		return nil, nil, err
	}

	keys := k.Keys
	if keys == "" {
		keys = ">"
	}
	keys, err = expandOne(keys, vars)
	if err != nil {
		return nil, nil, err
	}

	stream := "KV_" + bucket             // name of the stream backing the bucket
	data := "$KV." + bucket + "." + keys // the bucket's data subjects, already scoped

	access := k.Access
	if access == "" {
		access = KVRead
	}

	switch access {
	case KVNone, KVRead, KVReadWrite:
	default:
		return nil, nil, fmt.Errorf("%w: %q (expected %s|%s|%s)",
			ErrInvalidKVAccess, access, KVNone, KVRead, KVReadWrite)
	}

	if access != KVNone {
		// Reading: open the bucket + direct-get the allowed keys + receive the value.
		pub = append(pub,
			"$JS.API.STREAM.INFO."+stream,
			"$JS.API.DIRECT.GET."+stream+"."+data,
		)
		sub = append(sub, data)

		// Get by revision (GetRevision) uses STREAM.MSG.GET, which does NOT carry the key in
		// the subject and therefore cannot be scoped. It is only granted when the access
		// already covers the whole bucket; otherwise granting it would defeat key scoping.
		if keys == ">" {
			pub = append(pub, "$JS.API.STREAM.MSG.GET."+stream)
		}

		if k.Watch {
			// An ephemeral consumer sees the entire bucket: there is no way to scope it by key.
			pub = append(pub,
				"$JS.API.CONSUMER.CREATE."+stream+".>",
				"$JS.API.CONSUMER.DELETE."+stream+".>",
			)
		}
	}

	if access == KVReadWrite {
		pub = append(pub, data) // Put/Delete publish to the key's subject
	}

	if k.Manage {
		pub = append(pub,
			"$JS.API.STREAM.CREATE."+stream,
			"$JS.API.STREAM.UPDATE."+stream,
			"$JS.API.STREAM.DELETE."+stream,
			"$JS.API.STREAM.PURGE."+stream,
		)
		// Creating a bucket starts by checking whether it already exists, so administering it
		// requires STREAM.INFO. With read access it was already granted above; with `none`,
		// it was not.
		if access == KVNone {
			pub = append(pub, "$JS.API.STREAM.INFO."+stream)
		}
	}

	return pub, sub, nil
}

// expandAll expands a list of subjects and validates each result.
func expandAll(subjects []string, vars map[string]string) ([]string, error) {
	if len(subjects) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		expanded, err := expandOne(s, vars)
		if err != nil {
			return nil, err
		}
		if err := validateSubject(expanded); err != nil {
			return nil, err
		}
		out = append(out, expanded)
	}
	return out, nil
}

// expandOne replaces the {{placeholder}} occurrences in s. An unknown placeholder is an
// error rather than an empty replacement: a subject with an empty segment never matches
// anything, so failing here avoids minting permissions that silently do nothing.
func expandOne(s string, vars map[string]string) (string, error) {
	var missing []string
	out := placeholderRE.ReplaceAllStringFunc(s, func(match string) string {
		name := placeholderRE.FindStringSubmatch(match)[1]
		value, ok := vars[name]
		if !ok {
			missing = append(missing, name)
			return match
		}
		return value
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("%w: %s (in %q; available: %s)",
			ErrUnknownPlaceholder, strings.Join(missing, ", "), s, availablePlaceholders(vars))
	}
	return out, nil
}

// availablePlaceholders lists the valid placeholders, so the startup error can say what
// could have been used.
func availablePlaceholders(vars map[string]string) string {
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	// Stable order so the error message is reproducible.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return strings.Join(names, ", ")
}

// validateSubject checks that an already-expanded subject is valid for NATS: no empty
// segments, and `>` only as the last token.
func validateSubject(subject string) error {
	if subject == "" {
		return fmt.Errorf("%w: empty", ErrInvalidSubject)
	}
	tokens := strings.Split(subject, ".")
	for i, tok := range tokens {
		if tok == "" {
			return fmt.Errorf("%w: %q has an empty segment at position %d", ErrInvalidSubject, subject, i)
		}
		if tok == ">" && i != len(tokens)-1 {
			return fmt.Errorf("%w: %q uses `>` without being the last token", ErrInvalidSubject, subject)
		}
	}
	return nil
}
