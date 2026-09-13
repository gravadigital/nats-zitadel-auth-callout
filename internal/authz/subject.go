package authz

import "slices"

// This file exposes the subject machinery to callers OUTSIDE the permission path.
//
// Templates are the reason it exists: they are expanded and validated in template.go with
// unexported helpers, because a permission subject is only ever built from a template. The
// authentication event's subject is the one other thing in this service that is a subject
// built from the authenticated identity — and it has to be expanded by exactly the same rules,
// including the guard that a claim-sourced value can never be a wildcard.
//
// So these are thin wrappers rather than a second implementation: the day the placeholder
// grammar changes, it changes in one place.

// ExpandSubject expands the {{placeholder}} references in pattern against id and validates
// the result as a NATS subject.
//
// It is the same expansion templates get, deliberately: the values come from the identity
// (already validated as single literal subject tokens by Router.Resolve), an unknown
// placeholder is an error rather than an empty replacement, and the expanded subject cannot
// have an empty segment or a misplaced `>`.
func ExpandSubject(pattern string, id Identity) (string, error) {
	expanded, err := expandOne(pattern, id.placeholders())
	if err != nil {
		return "", err
	}
	if err := validateSubject(expanded); err != nil {
		return "", err
	}
	return expanded, nil
}

// SubjectPlaceholders lists the placeholder names pattern references, without expanding it.
//
// It exists so a caller can inspect a pattern's placeholders — to refuse one it cannot honour
// for every identity — at startup rather than per event.
func SubjectPlaceholders(pattern string) []string {
	referenced := referencedPlaceholders([]byte(pattern))
	names := make([]string, 0, len(referenced))
	for name := range referenced {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ProbeIdentity is the identity startup validation expands against: a placeholder value for
// every declared name and the deployment's real instance.
//
// Callers use it to fail at startup on a pattern that could never expand, which is the same
// contract templates already get from LoadTemplate.
func (r *Router) ProbeIdentity() Identity { return r.probeIdentity() }
