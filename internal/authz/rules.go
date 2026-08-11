package authz

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// MatchAny is the catch-all `match`: it applies to any authenticated identity whose roles
// did not match an earlier rule.
const MatchAny = "*"

// Routing errors.
var (
	// ErrNoRuleMatched is returned when no role in the token matches a rule and there is no
	// catch-all. It is a deliberate rejection: with no rule there are no permissions to mint.
	ErrNoRuleMatched = errors.New("authz: no role in the token matches a rule and there is no catch-all")
	// ErrInvalidUserType flags a rule whose `type` is neither person nor service.
	ErrInvalidUserType = errors.New("authz: invalid `type` in rule")
	// ErrEmptyTemplate flags a rule with no template.
	ErrEmptyTemplate = errors.New("authz: missing `template` in rule")
	// ErrServiceNameRequired flags a service rule with no service name. The name is the
	// service's endpoint, so without it the identity cannot be assembled.
	ErrServiceNameRequired = errors.New("authz: a `type: service` rule needs `service`")
	// ErrServiceNameOnPerson flags a person rule that declares `service`. It is almost
	// always a misplaced `type`, so it is rejected instead of ignored.
	ErrServiceNameOnPerson = errors.New("authz: `service` does not apply to a `type: person` rule")
	// ErrReservedPlaceholder flags an attempt to redefine a built-in placeholder.
	ErrReservedPlaceholder = errors.New("authz: reserved placeholder name")
	// ErrInvalidPlaceholderName flags a declared placeholder whose name a template could never
	// reference, because it does not match the {{...}} grammar.
	ErrInvalidPlaceholderName = errors.New("authz: invalid placeholder name")
	// ErrMissingPlaceholderClaim flags a declared placeholder whose claim the token did not
	// carry. It is a rejection: expanding it to empty would mint permissions that silently
	// match nothing.
	ErrMissingPlaceholderClaim = errors.New("authz: token carries no value for a declared placeholder")
	// ErrUnsafePlaceholderValue flags a claim value that is not a single, literal subject token.
	//
	// This is a privilege-escalation guard, not a hygiene check. A placeholder is substituted
	// into a permission subject, so a value containing `*` or `>` turns a scoped permission into
	// a wildcard one: a `tenant` claim of `*` expands `{{tenant}}.{{user_id}}.>` into
	// `*.<user>.>`, reaching EVERY tenant. A value containing `.` adds a segment and shifts the
	// whole grammar. The value comes from the token, which in a multi-tenant deployment is
	// exactly what the scoping is meant to constrain.
	//
	// It cannot be caught after expansion: at that point an injected `*` is indistinguishable
	// from one a template author wrote on purpose, and templates legitimately contain wildcards.
	ErrUnsafePlaceholderValue = errors.New("authz: unsafe value for a declared placeholder")
	// ErrUnreachableRule flags a rule no token can ever match, because an earlier rule already
	// claims everything it would. A rule that cannot fire is almost always a mistake about
	// first-match-wins ordering, and silently ignoring it means the permissions someone believes
	// they granted are never the ones minted.
	ErrUnreachableRule = errors.New("authz: unreachable rule")
	// ErrUnusedPlaceholder flags a declared placeholder no template references. It is not
	// harmless: every connection is then required to carry that claim and is REJECTED without
	// it, so a leftover declaration turns into an authentication requirement with no purpose.
	ErrUnusedPlaceholder = errors.New("authz: declared placeholder is never used by any template")
	// ErrUnusedInstance flags a configured instance no template references. The deployment
	// believes it is isolated per instance while nothing in the minted subjects says so — the
	// mirror image of `{{instance}}` with no instance configured, which already fails.
	ErrUnusedInstance = errors.New("authz: an instance is configured but no template uses {{instance}}")
)

// maxPlaceholderValueLen bounds a claim-sourced value. Without a cap, a multi-kilobyte claim
// becomes a multi-kilobyte subject in every minted User JWT. No legitimate tenant or region id
// approaches this.
const maxPlaceholderValueLen = 128

// placeholderNameRE is the grammar of a declared placeholder name. It matches the capture in
// template.go's placeholderRE, so a declared name is always referenceable from a template.
var placeholderNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Rule is a routing rule: a Zitadel role -> which kind of identity it is and which
// permission template belongs to it.
type Rule struct {
	// Match is the role name exactly as it travels in the token, or "*" for the catch-all.
	Match string `yaml:"match"`
	// Type is person or service. It decides how the identity is derived.
	Type UserType `yaml:"type"`
	// Service is the service name, required (and only valid) when Type is service. It is
	// the service's endpoint, the one it serves: `<instance>.*.<service>.>`.
	Service string `yaml:"service"`
	// Template is the template path, relative to the directory holding rules.yaml.
	Template string `yaml:"template"`
}

// RulesConfig is the content of examples/rules.yaml.
//
// Routing depends ONLY on the role: there is no heuristic guessing whether a token belongs
// to a person or to a service. The rule declares it, and whoever administers Zitadel
// assigns the role. That makes the question "what permissions does X have?" answerable by
// reading two files, without running anything.
type RulesConfig struct {
	Version int `yaml:"version"`
	// Placeholders declares deployment-defined template placeholders and which token claim
	// each one reads from. It is what lets a deployment express a subject grammar this project
	// did not design (tenant-first, region-scoped, ...) without changing code.
	//
	//	placeholders:
	//	  tenant: tenant_id            # top-level claim
	//	  region: metadata.region      # dot-separated path into a nested claim
	Placeholders map[string]string `yaml:"placeholders"`
	Rules        []Rule            `yaml:"rules"`
}

// LoadRulesConfig reads and parses a rules.yaml.
func LoadRulesConfig(path string) (*RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read rules %q: %w", path, err)
	}
	var cfg RulesConfig
	if err := decodeStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("authz: parse rules %q: %w", path, err)
	}
	return &cfg, nil
}

// decodeStrict parses YAML and REJECTS keys the target struct does not declare.
//
// yaml.Unmarshal ignores unknown keys, which turns a typo into silence: a template writing
// `publish:` instead of `pub:` parses cleanly, grants nothing, and the client connects fine and
// then has every publish denied — a failure that surfaces far from its cause. The same applies
// to `templates:` for `template:` in a rule.
//
// Strict decoding is right for both files because they are hand-written authorization
// configuration: there is no forward-compatibility story that a silently ignored key would
// serve, and a misconfiguration must not start.
func decodeStrict(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		// An empty file decodes to io.EOF rather than an error. The callers treat an empty
		// config as "declares no rules", which they already report with a clearer message.
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// resolvedRule is a rule with its template already loaded and validated.
type resolvedRule struct {
	Rule
	template     *Template
	templatePath string
}

// Router picks the rule for each request and expands its template. It is immutable after
// construction, so it is safe for concurrent use.
type Router struct {
	instance string
	rules    []resolvedRule
	// placeholders maps a declared placeholder name to the claim path it reads from.
	placeholders map[string]string
	// inboxMode is how the private inbox is derived.
	inboxMode InboxMode
	// warnings holds configuration that is suspicious but has a legitimate reading, collected at
	// construction so the caller can log it once at startup. See Warnings.
	warnings []string
}

// RouterOption configures a Router.
type RouterOption func(*Router)

// WithInboxMode selects how the inbox prefix is derived. Default is InboxHashed.
func WithInboxMode(mode InboxMode) RouterOption {
	return func(r *Router) {
		if mode != "" {
			r.inboxMode = mode
		}
	}
}

// NewRouter builds a Router from a rules config. Templates are loaded and validated here:
// if one is missing, fails to parse or uses a non-existent placeholder, startup fails. That
// is intentional — better not to start at all than to authenticate with broken permissions.
func NewRouter(cfg *RulesConfig, configDir, instance string, opts ...RouterOption) (*Router, error) {
	// The instance is deliberately allowed to be empty: a deployment adopting an existing
	// subject grammar often has nowhere to put an extra leading token. A template that
	// references {{instance}} without one configured fails the startup validation below, which
	// is where the mistake is actually visible.
	r := &Router{
		instance:     instance,
		placeholders: make(map[string]string, len(cfg.Placeholders)),
		inboxMode:    InboxHashed,
	}
	for _, opt := range opts {
		opt(r)
	}

	for name, claim := range cfg.Placeholders {
		if name == "" {
			return nil, errors.New("authz: a declared placeholder has an empty name")
		}
		if !placeholderNameRE.MatchString(name) {
			return nil, fmt.Errorf("%w: %q (expected lowercase letters, digits and underscore, starting with a letter)",
				ErrInvalidPlaceholderName, name)
		}
		// Redefining a built-in would let a template mint permissions for an identity other
		// than the one that authenticated: `user_id` sourced from an attacker-controllable
		// claim is exactly the scoping bypass the subject grammar exists to prevent.
		if IsBuiltinPlaceholder(name) {
			return nil, fmt.Errorf("%w: %q is built-in and cannot be redefined", ErrReservedPlaceholder, name)
		}
		if claim == "" {
			return nil, fmt.Errorf("authz: placeholder %q declares no claim to read from", name)
		}
		r.placeholders[name] = claim
	}

	// The same template may appear in several rules; it is loaded only once.
	cache := make(map[string]*Template)

	for i, rule := range cfg.Rules {
		if !rule.Type.IsValid() {
			return nil, fmt.Errorf("%w: rule %d (match=%q): %q", ErrInvalidUserType, i, rule.Match, rule.Type)
		}
		if rule.Template == "" {
			return nil, fmt.Errorf("%w: rule %d (match=%q)", ErrEmptyTemplate, i, rule.Match)
		}
		if rule.Type == UserTypeService && rule.Service == "" {
			return nil, fmt.Errorf("%w: rule %d (match=%q)", ErrServiceNameRequired, i, rule.Match)
		}
		if rule.Type == UserTypePerson && rule.Service != "" {
			return nil, fmt.Errorf("%w: rule %d (match=%q)", ErrServiceNameOnPerson, i, rule.Match)
		}

		path := rule.Template
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, path)
		}

		tmpl, ok := cache[path]
		if !ok {
			// The probe identity carries the declared placeholders and the real instance, so
			// startup validation catches a template referencing an undeclared placeholder — or
			// {{instance}} with no instance configured — before any traffic is served.
			loaded, err := LoadTemplate(path, r.probeIdentity())
			if err != nil {
				return nil, fmt.Errorf("authz: rule %d (match=%q): %w", i, rule.Match, err)
			}
			cache[path] = loaded
			tmpl = loaded
		}

		r.rules = append(r.rules, resolvedRule{Rule: rule, template: tmpl, templatePath: path})
	}

	if len(r.rules) == 0 {
		return nil, errors.New("authz: rules.yaml declares no rules")
	}

	// Coherence checks. Everything above validates each piece in isolation; these validate that
	// the pieces together can actually do something. A configuration that cannot work must not
	// start: the alternative is a service that authenticates clients into permissions nobody
	// intended, and every one of these failures surfaces far from its cause.
	if err := r.checkReachableRules(); err != nil {
		return nil, err
	}
	if err := r.checkPlaceholdersUsed(); err != nil {
		return nil, err
	}
	r.warnings = r.collectWarnings()

	return r, nil
}

// Warnings returns configuration that is suspicious but not provably wrong, for the caller to
// log at startup.
//
// The split from the hard failures above is deliberate: these have a legitimate reading, so
// refusing to start would block a valid deployment. A publish-only template that never expects a
// reply is a real shape, and so is a service that only serves.
func (r *Router) Warnings() []string { return r.warnings }

// collectWarnings looks for templates that grant no inbox.
//
// Without an inbox permission a client can publish but never receives a reply, and the symptom
// is a request that times out with no permissions error anywhere — the single most confusing
// failure this service produces, which is why it is called out even though it can be intentional.
func (r *Router) collectWarnings() []string {
	// The same template can back several rules; report it once.
	reported := make(map[string]struct{}, len(r.rules))
	var out []string

	for _, rule := range r.rules {
		if _, done := reported[rule.templatePath]; done {
			continue
		}
		reported[rule.templatePath] = struct{}{}

		if !grantsAnInbox(rule.template) {
			out = append(out, fmt.Sprintf(
				"template %q grants no inbox subscription, so a client using it can publish but will never receive a reply (add %s to sub.allow, unless these clients only ever publish)",
				rule.templatePath, suggestedInbox(r.inboxMode)))
		}
	}

	sort.Strings(out)
	return out
}

// grantsAnInbox reports whether any sub.allow entry could cover a reply inbox.
//
// The test is deliberately loose — any subscription starting with `_INBOX`, or a bare `>` — so
// that an unusual but working template does not produce a warning nobody can silence.
func grantsAnInbox(t *Template) bool {
	for _, subject := range t.Sub.Allow {
		if subject == ">" || strings.HasPrefix(subject, "_INBOX") {
			return true
		}
	}
	return false
}

// suggestedInbox names the inbox shape that fits the configured mode, so the warning can be
// acted on without a trip to the documentation.
func suggestedInbox(mode InboxMode) string {
	if mode == InboxPassthrough {
		return "`_INBOX.>` (passthrough mode: clients keep their default inbox)"
	}
	return "`_INBOX.{{user_id_hash}}.>`"
}

// checkReachableRules rejects a rule that no token can ever match.
//
// Matching is first-match-wins in file order, so a rule is dead if an earlier one has the same
// `match`, or if an earlier one is the catch-all. Both are ordering mistakes, and both are
// invisible at runtime: the connection succeeds, with the permissions of a rule its author was
// not looking at.
func (r *Router) checkReachableRules() error {
	seen := make(map[string]int, len(r.rules))
	for i, rule := range r.rules {
		if first, ok := seen[rule.Match]; ok {
			return fmt.Errorf("%w: rule %d (match=%q) repeats the `match` of rule %d, so it can never fire (matching is first-match-wins in file order)",
				ErrUnreachableRule, i, rule.Match, first)
		}
		seen[rule.Match] = i

		if rule.Match == MatchAny && i != len(r.rules)-1 {
			return fmt.Errorf("%w: rule %d is the catch-all `match: \"%s\"` but %d rule(s) follow it, and first-match-wins makes them dead; move the catch-all last",
				ErrUnreachableRule, i, MatchAny, len(r.rules)-1-i)
		}
	}
	return nil
}

// checkPlaceholdersUsed rejects configuration that declares placeholder inputs nothing consumes.
//
// Both cases are dead configuration WITH a consequence, which is why they fail rather than warn:
// an unused declared placeholder makes its claim mandatory on every connection (Resolve rejects
// a token that lacks it), and an unused instance leaves a deployment believing it is isolated
// per instance when no minted subject mentions it.
func (r *Router) checkPlaceholdersUsed() error {
	usedBySomeTemplate := func(name string) bool {
		for _, rule := range r.rules {
			if rule.template.References(name) {
				return true
			}
		}
		return false
	}

	unused := make([]string, 0, len(r.placeholders))
	for name := range r.placeholders {
		if !usedBySomeTemplate(name) {
			unused = append(unused, name)
		}
	}
	if len(unused) > 0 {
		// Sorted so the message is identical across runs: map iteration order is not.
		sort.Strings(unused)
		return fmt.Errorf("%w: %s (declared in rules.yaml but referenced by no template; every connection would still be required to carry the claim, and rejected without it — remove the declaration or use it)",
			ErrUnusedPlaceholder, strings.Join(unused, ", "))
	}

	if r.instance != "" && !usedBySomeTemplate("instance") {
		return fmt.Errorf("%w: CALLOUT_INSTANCE=%q has no effect, because no template references {{instance}}; add it to the templates that should be scoped per instance, or unset the variable",
			ErrUnusedInstance, r.instance)
	}

	return nil
}

// NewRouterFromFile loads rules.yaml from a path and resolves the templates relative to the
// directory containing it.
func NewRouterFromFile(rulesPath, instance string, opts ...RouterOption) (*Router, error) {
	cfg, err := LoadRulesConfig(rulesPath)
	if err != nil {
		return nil, err
	}
	return NewRouter(cfg, filepath.Dir(rulesPath), instance, opts...)
}

// validatePlaceholderValue checks that a claim-sourced value is a single literal subject token.
//
// The rule is the same one CALLOUT_INSTANCE already enforces, and for the same stated reason:
// these characters do not make a subject invalid, they make it mean something BROADER than the
// template author wrote. It is applied here because the value arrives at runtime from the token,
// so no startup check can see it.
//
// The reason it cannot live in validateSubject (which runs post-expansion) is that by then an
// injected `*` is indistinguishable from a deliberate one — and templates legitimately use
// wildcards, e.g. `{{instance}}.*.{{service}}.>` in the shipped service template.
func validatePlaceholderValue(value string) error {
	if len(value) > maxPlaceholderValueLen {
		return fmt.Errorf("longer than %d characters", maxPlaceholderValueLen)
	}
	for _, r := range value {
		switch {
		case r == '.':
			// A dot adds a segment, making the grammar's shape token-controlled. If a deployment
			// genuinely needs a multi-token value, that deserves an explicit per-placeholder
			// opt-in rather than being allowed by default for everyone.
			return errors.New("contains `.`, which would add a subject segment")
		case r == '*' || r == '>':
			return fmt.Errorf("contains the NATS wildcard %q, which would widen the permission", r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			return errors.New("contains whitespace")
		case r < 0x20 || r == 0x7f:
			return errors.New("contains a control character")
		}
	}
	return nil
}

// probeIdentity is the identity templates are validated against at startup. It carries a
// placeholder value for every DECLARED name, so a template referencing an undeclared one fails
// here rather than per-connection.
//
// The instance is the REAL one (not a probe value) so that a template using {{instance}} with
// none configured is caught: the expansion would otherwise produce an empty subject segment,
// which matches nothing and is invisible until a client cannot publish.
func (r *Router) probeIdentity() Identity {
	extra := make(map[string]string, len(r.placeholders))
	for name := range r.placeholders {
		extra[name] = "probe"
	}
	return Identity{
		Instance:  r.instance,
		UserID:    "probe",
		Service:   "probe",
		Extra:     extra,
		InboxMode: r.inboxMode,
	}
}

// Placeholders returns the declared placeholder-to-claim mapping. The caller (the callout)
// uses it to know which claims to extract per request.
func (r *Router) Placeholders() map[string]string {
	out := make(map[string]string, len(r.placeholders))
	for name, claim := range r.placeholders {
		out[name] = claim
	}
	return out
}

// InboxMode reports how the router derives inbox prefixes.
func (r *Router) InboxMode() InboxMode { return r.inboxMode }

// Match picks the first rule whose `match` is the catch-all or matches one of the token's
// roles. First-match-wins in file order: specific rules go on top and `*` at the end.
func (r *Router) Match(roles []string) (Rule, string, bool) {
	present := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		present[role] = struct{}{}
	}
	for _, rule := range r.rules {
		if rule.Match == MatchAny {
			return rule.Rule, rule.templatePath, true
		}
		if _, ok := present[rule.Match]; ok {
			return rule.Rule, rule.templatePath, true
		}
	}
	return Rule{}, "", false
}

// Decision records WHY a connection received the permissions it received. It goes into the
// log line of every authentication: without the winning role, a token carrying several
// roles leaves the log ambiguous.
type Decision struct {
	// Rule is the `match` of the winning rule (the role name, or "*").
	Rule string
	// Template is the path of the template that was expanded.
	Template string
	// IdentityModel is the rule's `type`: person or service. It is the IDENTITY MODEL that
	// was applied, not the class of user in Zitadel — a machine user whose role is declared
	// `type: person` receives a person identity, and that is on purpose.
	IdentityModel UserType
}

// Resolve is the whole path: from the token's roles to the identity and the permissions.
//
// subject is the token's `sub`, username the human-readable name (which may be empty) and
// extra the values of the declared placeholders, already read from the token's claims.
func (r *Router) Resolve(roles []string, subject, username string, extra map[string]string) (Identity, *Permissions, Decision, error) {
	rule, templatePath, ok := r.Match(roles)
	if !ok {
		return Identity{}, nil, Decision{}, ErrNoRuleMatched
	}

	// The user id is a subject token too, and it comes from the token's `sub` — so it needs the
	// same guard as the declared placeholders.
	//
	// It is not hypothetical just because a well-behaved IdP issues opaque ids: `{{user_id}}`
	// appears in essentially every template, so a `sub` of `*` would widen EVERY deployment's
	// per-user scoping rather than one placeholder's. The cost of checking is nil and the
	// consequence of not checking is the whole grammar.
	// A dotted `sub` — which some LDAP-backed providers issue as an email address — is refused
	// too, for the same reason: it would add segments and shift every following token. Such a
	// deployment has to map `sub` to an opaque id in the IdP rather than have this service
	// silently reshape its subjects.
	if err := validatePlaceholderValue(subject); err != nil {
		return Identity{}, nil, Decision{}, fmt.Errorf("%w: user_id (from the token's `sub`): %v",
			ErrUnsafePlaceholderValue, err)
	}

	// Every declared placeholder must have arrived with a value, and that value has to be a
	// single literal subject token.
	//
	// Both checks reject rather than sanitise. A missing claim would expand to an empty segment
	// and mint permissions that silently match nothing; a value carrying `*`, `>` or `.` would
	// WIDEN the minted permission past what the template author wrote — see
	// ErrUnsafePlaceholderValue. Rewriting either into something acceptable would hide a broken
	// IdP configuration or an attack, so the connection is refused instead.
	for name, claimPath := range r.placeholders {
		value := extra[name]
		if value == "" {
			return Identity{}, nil, Decision{}, fmt.Errorf("%w: %q (claim %q carried no value)",
				ErrMissingPlaceholderClaim, name, claimPath)
		}
		if err := validatePlaceholderValue(value); err != nil {
			// The value itself is deliberately NOT in the error: it is token content, and this
			// error reaches the client and the logs.
			return Identity{}, nil, Decision{}, fmt.Errorf("%w: %q (from claim %q): %v",
				ErrUnsafePlaceholderValue, name, claimPath, err)
		}
	}

	// The user id is the token's `sub`, the same for a person and for a service: both are
	// Zitadel users. What a service adds is its endpoint NAME, which is a different thing
	// (several replicas share an endpoint on purpose — that is how NATS balances with queue
	// groups — but each one connects with the service user's user id).
	id := Identity{
		Instance:  r.instance,
		Type:      rule.Type,
		UserID:    subject,
		Username:  username,
		Extra:     extra,
		InboxMode: r.inboxMode,
	}
	if rule.Type == UserTypeService {
		id.Service = rule.Service
	}

	// The template was looked up by path in the router's cache, so it always exists here.
	var tmpl *Template
	for _, resolved := range r.rules {
		if resolved.templatePath == templatePath {
			tmpl = resolved.template
			break
		}
	}

	perms, err := tmpl.Expand(id)
	if err != nil {
		return Identity{}, nil, Decision{}, fmt.Errorf("authz: expand %q for match=%q: %w", templatePath, rule.Match, err)
	}

	decision := Decision{
		Rule:          rule.Match,
		Template:      templatePath,
		IdentityModel: rule.Type,
	}
	return id, perms, decision, nil
}
