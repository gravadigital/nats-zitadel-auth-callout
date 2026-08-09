package authz

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// MatchAny es el `match` catch-all: aplica a cualquier identidad autenticada cuyos roles
// no matchearon una regla anterior.
const MatchAny = "*"

// Errores de routing.
var (
	// ErrNoRuleMatched se devuelve cuando ningún rol del token matchea una regla y no
	// hay catch-all. Es un rechazo deliberado: sin regla no hay permisos que minteear.
	ErrNoRuleMatched = errors.New("authz: ningún rol del token matchea una regla y no hay catch-all")
	// ErrInvalidUserType marca una regla con un `type` que no es person ni service.
	ErrInvalidUserType = errors.New("authz: `type` inválido en la regla")
	// ErrEmptyTemplate marca una regla sin plantilla.
	ErrEmptyTemplate = errors.New("authz: falta `template` en la regla")
	// ErrServiceNameRequired marca una regla de servicio sin nombre de servicio. El
	// nombre es la sesión del servicio, así que sin él no se puede armar la identidad.
	ErrServiceNameRequired = errors.New("authz: una regla `type: service` necesita `service`")
	// ErrServiceNameOnPerson marca una regla de persona que declara `service`. Es casi
	// siempre un `type` mal puesto, así que se rechaza en vez de ignorarse.
	ErrServiceNameOnPerson = errors.New("authz: `service` no aplica a una regla `type: person`")
)

// Rule es una regla de routing: un rol de Zitadel -> qué tipo de identidad es y qué
// plantilla de permisos le corresponde.
type Rule struct {
	// Match es el nombre del rol tal como viaja en el token, o "*" para el catch-all.
	Match string `yaml:"match"`
	// Type es person o service. Decide cómo se deriva la sesión.
	Type UserType `yaml:"type"`
	// Service es el nombre del servicio, obligatorio (y solo válido) si Type es service.
	// Es la sesión del servicio y el endpoint que atiende: `<instancia>.*.<service>.>`.
	Service string `yaml:"service"`
	// Template es el path de la plantilla, relativo al directorio del rules.yaml.
	Template string `yaml:"template"`
}

// RulesConfig es el contenido de config/rules.yaml.
//
// El routing depende SOLO del rol: no hay heurística que adivine si un token es de una
// persona o de un servicio. Lo declara la regla, y el rol lo asigna quien administra
// Zitadel. Eso hace que la pregunta "¿qué permisos tiene X?" se conteste leyendo dos
// archivos, sin ejecutar nada.
type RulesConfig struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// LoadRulesConfig lee y parsea un rules.yaml.
func LoadRulesConfig(path string) (*RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: leer rules %q: %w", path, err)
	}
	var cfg RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("authz: parsear rules %q: %w", path, err)
	}
	return &cfg, nil
}

// resolvedRule es una regla con su plantilla ya cargada y validada.
type resolvedRule struct {
	Rule
	template     *Template
	templatePath string
}

// Router elige la regla de cada request y expande su plantilla. Es inmutable después de
// construirse, así que es seguro usarlo concurrentemente.
type Router struct {
	instance string
	rules    []resolvedRule
}

// NewRouter construye un Router desde una config de reglas. Las plantillas se cargan y
// validan acá: si alguna falta, no parsea o usa un placeholder inexistente, el arranque
// falla. Es intencional — es mejor no arrancar que autenticar con permisos rotos.
func NewRouter(cfg *RulesConfig, configDir, instance string) (*Router, error) {
	if instance == "" {
		return nil, errors.New("authz: la instancia no puede estar vacía")
	}

	r := &Router{instance: instance}

	// Una misma plantilla puede aparecer en varias reglas; se carga una sola vez.
	cache := make(map[string]*Template)

	for i, rule := range cfg.Rules {
		if !rule.Type.IsValid() {
			return nil, fmt.Errorf("%w: regla %d (match=%q): %q", ErrInvalidUserType, i, rule.Match, rule.Type)
		}
		if rule.Template == "" {
			return nil, fmt.Errorf("%w: regla %d (match=%q)", ErrEmptyTemplate, i, rule.Match)
		}
		if rule.Type == UserTypeService && rule.Service == "" {
			return nil, fmt.Errorf("%w: regla %d (match=%q)", ErrServiceNameRequired, i, rule.Match)
		}
		if rule.Type == UserTypePerson && rule.Service != "" {
			return nil, fmt.Errorf("%w: regla %d (match=%q)", ErrServiceNameOnPerson, i, rule.Match)
		}

		path := rule.Template
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, path)
		}

		tmpl, ok := cache[path]
		if !ok {
			loaded, err := LoadTemplate(path)
			if err != nil {
				return nil, fmt.Errorf("authz: regla %d (match=%q): %w", i, rule.Match, err)
			}
			cache[path] = loaded
			tmpl = loaded
		}

		r.rules = append(r.rules, resolvedRule{Rule: rule, template: tmpl, templatePath: path})
	}

	if len(r.rules) == 0 {
		return nil, errors.New("authz: rules.yaml no declara ninguna regla")
	}

	return r, nil
}

// NewRouterFromFile carga rules.yaml de un path y resuelve las plantillas relativas al
// directorio que lo contiene.
func NewRouterFromFile(rulesPath, instance string) (*Router, error) {
	cfg, err := LoadRulesConfig(rulesPath)
	if err != nil {
		return nil, err
	}
	return NewRouter(cfg, filepath.Dir(rulesPath), instance)
}

// Match elige la primera regla cuyo `match` sea el catch-all o coincida con alguno de
// los roles del token. First-match-wins por orden del archivo: las reglas específicas
// van arriba y el `*` al final.
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

// Decision registra POR QUÉ una conexión recibió los permisos que recibió. Va al log de
// cada autenticación: sin el rol que ganó, un token con varios roles deja el log ambiguo.
type Decision struct {
	// Rule es el `match` de la regla que ganó (el nombre del rol, o "*").
	Rule string
	// Template es el path de la plantilla que se expandió.
	Template string
	// IdentityModel es el `type` de la regla: person o service. Es el MODELO DE IDENTIDAD
	// que se aplicó, no la clase de usuario que sea en Zitadel — un machine user con un rol
	// declarado `type: person` recibe identidad de persona, y es a propósito.
	IdentityModel UserType
}

// Resolve es el camino completo: de los roles del token a la identidad y los permisos.
//
// subject es el `sub` del token y username el nombre legible (puede venir vacío).
func (r *Router) Resolve(roles []string, subject, username string) (Identity, *Permissions, Decision, error) {
	rule, templatePath, ok := r.Match(roles)
	if !ok {
		return Identity{}, nil, Decision{}, ErrNoRuleMatched
	}

	// El user id es el `sub` del token, igual para persona y para servicio: los dos son
	// usuarios de Zitadel. Lo que agrega un servicio es su NOMBRE de endpoint, que es
	// otra cosa (varias réplicas comparten endpoint a propósito —así NATS balancea con
	// queue groups— pero cada una conecta con el user id del service user).
	id := Identity{
		Instance: r.instance,
		Type:     rule.Type,
		UserID:   subject,
		Username: username,
	}
	if rule.Type == UserTypeService {
		id.Service = rule.Service
	}

	// La plantilla se buscó por path en el cache del router, así que acá siempre existe.
	var tmpl *Template
	for _, resolved := range r.rules {
		if resolved.templatePath == templatePath {
			tmpl = resolved.template
			break
		}
	}

	perms, err := tmpl.Expand(id)
	if err != nil {
		return Identity{}, nil, Decision{}, fmt.Errorf("authz: expandir %q para match=%q: %w", templatePath, rule.Match, err)
	}

	decision := Decision{
		Rule:          rule.Match,
		Template:      templatePath,
		IdentityModel: rule.Type,
	}
	return id, perms, decision, nil
}
