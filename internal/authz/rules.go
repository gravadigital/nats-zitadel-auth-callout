package authz

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
)

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

// RulesConfig is the content of config/rules.yaml.
//
// Routing depends ONLY on the role: there is no heuristic guessing whether a token belongs
// to a person or to a service. The rule declares it, and whoever administers Zitadel
// assigns the role. That makes the question "what permissions does X have?" answerable by
// reading two files, without running anything.
type RulesConfig struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// LoadRulesConfig reads and parses a rules.yaml.
func LoadRulesConfig(path string) (*RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read rules %q: %w", path, err)
	}
	var cfg RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("authz: parse rules %q: %w", path, err)
	}
	return &cfg, nil
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
}

// NewRouter builds a Router from a rules config. Templates are loaded and validated here:
// if one is missing, fails to parse or uses a non-existent placeholder, startup fails. That
// is intentional — better not to start at all than to authenticate with broken permissions.
func NewRouter(cfg *RulesConfig, configDir, instance string) (*Router, error) {
	if instance == "" {
		return nil, errors.New("authz: instance cannot be empty")
	}

	r := &Router{instance: instance}

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
			loaded, err := LoadTemplate(path)
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

	return r, nil
}

// NewRouterFromFile loads rules.yaml from a path and resolves the templates relative to the
// directory containing it.
func NewRouterFromFile(rulesPath, instance string) (*Router, error) {
	cfg, err := LoadRulesConfig(rulesPath)
	if err != nil {
		return nil, err
	}
	return NewRouter(cfg, filepath.Dir(rulesPath), instance)
}

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
// subject is the token's `sub` and username the human-readable name (which may be empty).
func (r *Router) Resolve(roles []string, subject, username string) (Identity, *Permissions, Decision, error) {
	rule, templatePath, ok := r.Match(roles)
	if !ok {
		return Identity{}, nil, Decision{}, ErrNoRuleMatched
	}

	// The user id is the token's `sub`, the same for a person and for a service: both are
	// Zitadel users. What a service adds is its endpoint NAME, which is a different thing
	// (several replicas share an endpoint on purpose — that is how NATS balances with queue
	// groups — but each one connects with the service user's user id).
	id := Identity{
		Instance: r.instance,
		Type:     rule.Type,
		UserID:   subject,
		Username: username,
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
