package authz

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeRules deja un rules.yaml y las plantillas que referencia en un directorio temporal.
func writeRules(t *testing.T, rules string, templates map[string]string) string {
	t.Helper()
	dir := t.TempDir()

	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatalf("escribir rules.yaml: %v", err)
	}

	tmplDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(tmplDir, 0o750); err != nil {
		t.Fatalf("crear templates/: %v", err)
	}
	for name, content := range templates {
		if err := os.WriteFile(filepath.Join(tmplDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("escribir %s: %v", name, err)
		}
	}
	return rulesPath
}

// minimalPersonTemplate es una plantilla de persona válida.
const minimalPersonTemplate = `
pub:
  allow:
    - "{{instance}}.{{user_id}}.api.>"
sub:
  allow:
    - "_INBOX.{{user_id_hash}}.>"
`

// minimalServiceTemplate es una plantilla de servicio válida.
const minimalServiceTemplate = `
sub:
  allow:
    - "{{instance}}.*.{{service}}.>"
`

func TestMatchIsFirstMatchWins(t *testing.T) {
	// `external-user` está declarado ANTES de `user`: una cuenta con los dos roles debe
	// caer en el más restrictivo. Es la garantía que sostiene el orden de rules.yaml.
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: external-user
    type: person
    template: templates/external.yaml
  - match: user
    type: person
    template: templates/user.yaml
`, map[string]string{
		"external.yaml": minimalPersonTemplate,
		"user.yaml":     minimalPersonTemplate,
	})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	rule, _, ok := router.Match([]string{"user", "external-user"})
	if !ok {
		t.Fatal("esperaba match")
	}
	if rule.Match != "external-user" {
		t.Fatalf("esperaba que ganara external-user, ganó %q", rule.Match)
	}
}

func TestMatchCatchAll(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: admin
    type: person
    template: templates/admin.yaml
  - match: "*"
    type: person
    template: templates/guest.yaml
`, map[string]string{
		"admin.yaml": minimalPersonTemplate,
		"guest.yaml": minimalPersonTemplate,
	})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	rule, _, ok := router.Match([]string{"rol-que-no-existe"})
	if !ok || rule.Match != MatchAny {
		t.Fatalf("esperaba el catch-all, obtuve %q (ok=%v)", rule.Match, ok)
	}

	// Sin ningún rol también cae en el catch-all.
	if _, _, ok := router.Match(nil); !ok {
		t.Fatal("esperaba que un token sin roles caiga en el catch-all")
	}
}

// Sin catch-all, un rol desconocido se RECHAZA. No hay permisos por defecto.
func TestResolveWithoutCatchAllRejects(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: svc-api
    type: service
    service: api
    template: templates/svc.yaml
`, map[string]string{"svc.yaml": minimalServiceTemplate})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	_, _, _, err = router.Resolve([]string{"otro-rol"}, "sub-1", "quien-sea")
	if !errors.Is(err, ErrNoRuleMatched) {
		t.Fatalf("esperaba ErrNoRuleMatched, obtuve %v", err)
	}
}

func TestResolvePersonIdentity(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: "*"
    type: person
    template: templates/person.yaml
`, map[string]string{"person.yaml": minimalPersonTemplate})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	id, perms, _, err := router.Resolve([]string{"user"}, "zitadel-user-123", "ana@grava.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if id.Type != UserTypePerson {
		t.Fatalf("esperaba type person, obtuve %q", id.Type)
	}
	if id.UserID != "zitadel-user-123" {
		t.Fatalf("el user id debe ser el sub del token, obtuve %q", id.UserID)
	}
	// El user id va CRUDO en los subjects de mensajería: es lo que hace legible el subject
	// y lo que deja a un servicio saber quién lo llamó leyéndolo.
	if !slices.Contains(perms.PubAllow, "prod.zitadel-user-123.api.>") {
		t.Fatalf("esperaba el user id crudo en el subject de pub, obtuve %v", perms.PubAllow)
	}
	// El inbox, en cambio, va bajo el hash.
	wantInbox := "_INBOX." + HashUserID("zitadel-user-123") + ".>"
	if !slices.Contains(perms.SubAllow, wantInbox) {
		t.Fatalf("esperaba el inbox %q, obtuve %v", wantInbox, perms.SubAllow)
	}
	if id.Username != "ana@grava.io" {
		t.Fatalf("esperaba el username del token, obtuve %q", id.Username)
	}
}

func TestResolveServiceIdentity(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: svc-jira
    type: service
    service: jira
    template: templates/svc.yaml
`, map[string]string{"svc.yaml": minimalServiceTemplate})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	id, perms, _, err := router.Resolve([]string{"svc-jira"}, "machine-user-9", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if id.Type != UserTypeService {
		t.Fatalf("esperaba type service, obtuve %q", id.Type)
	}
	// Un service user tiene las DOS cosas: su propio user id (el `sub`, igual que una
	// persona) y el nombre del endpoint que atiende. Son ejes distintos.
	if id.UserID != "machine-user-9" || id.Service != "jira" {
		t.Fatalf("esperaba userID=machine-user-9 service=jira, obtuve userID=%q service=%q", id.UserID, id.Service)
	}
	assertSubjects(t, "sub allow", perms.SubAllow, []string{"prod.*.jira.>"})
}

// El modelo de identidad lo decide la REGLA, no la clase de usuario que sea en Zitadel.
//
// Un machine user cuyo rol está declarado `type: person` recibe identidad de persona: sin
// nombre de servicio, así que no puede atender un endpoint. Es intencional —permite ejercitar
// el camino de persona sin un login interactivo— y es lo que el log reporta como
// `identity=person`, que se lee raro al lado de un service user si no se sabe esto.
func TestIdentityModelComesFromTheRuleNotThePrincipal(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: poc-user
    type: person
    template: templates/person.yaml
`, map[string]string{"person.yaml": minimalPersonTemplate})

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	// El `sub` es de un machine user de Zitadel; la regla dice person.
	id, _, decision, err := router.Resolve([]string{"poc-user"}, "385270818583609346", "poc_user")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if decision.IdentityModel != UserTypePerson || id.Type != UserTypePerson {
		t.Fatalf("esperaba modelo person, obtuve decision=%q identity=%q", decision.IdentityModel, id.Type)
	}
	if id.UserID != "385270818583609346" {
		t.Fatalf("el user id debe ser el sub del token, obtuve %q", id.UserID)
	}
	if id.Service != "" {
		t.Fatalf("una identidad de persona no lleva nombre de servicio, obtuve %q", id.Service)
	}
	// El rol que ganó tiene que quedar registrado: con varios roles en el token, el log sin
	// esto no permite saber por qué recibió esos permisos.
	if decision.Rule != "poc-user" {
		t.Fatalf("esperaba matchedBy=poc-user, obtuve %q", decision.Rule)
	}
}

// Dos usuarios distintos no pueden compartir el hash: es lo que aísla sus inboxes.
func TestHashUserIDIsStableAndDistinct(t *testing.T) {
	a1 := HashUserID("user-a")
	a2 := HashUserID("user-a")
	b := HashUserID("user-b")

	if a1 != a2 {
		t.Fatalf("la derivación debe ser determinista: %q != %q", a1, a2)
	}
	if a1 == b {
		t.Fatal("dos user ids distintos no pueden derivar el mismo hash")
	}
	if len(a1) != userIDHashLen {
		t.Fatalf("esperaba %d caracteres, obtuve %d (%q)", userIDHashLen, len(a1), a1)
	}
	// Tiene que ser un token de subject válido: sin separadores ni wildcards.
	if err := validateSubject("_INBOX." + a1 + ".x"); err != nil {
		t.Fatalf("el hash derivado no es un token de subject válido: %v", err)
	}
}

// El inbox NO usa el user id crudo: un `sub` de Zitadel puede traer caracteres que no son
// un token de subject válido, y el prefijo tiene que ser de largo fijo.
func TestInboxPrefixUsesHashNotRawUserID(t *testing.T) {
	id := Identity{Instance: "prod", UserID: "385270818583609346"}

	want := "_INBOX." + HashUserID("385270818583609346")
	if got := id.InboxPrefix(); got != want {
		t.Fatalf("esperaba %q, obtuve %q", want, got)
	}
	if strings.Contains(id.InboxPrefix(), id.UserID) {
		t.Fatalf("el inbox no debe llevar el user id crudo: %q", id.InboxPrefix())
	}
}

// --- validación de configuración ------------------------------------------------------
//
// Todo esto tiene que fallar al construir el router, no al atender la primera conexión.

func TestRouterRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		want  error
	}{
		{
			name: "type inválido",
			rules: `
version: 1
rules:
  - match: x
    type: robot
    template: templates/person.yaml
`,
			want: ErrInvalidUserType,
		},
		{
			name: "sin template",
			rules: `
version: 1
rules:
  - match: x
    type: person
`,
			want: ErrEmptyTemplate,
		},
		{
			name: "servicio sin nombre",
			rules: `
version: 1
rules:
  - match: svc-x
    type: service
    template: templates/svc.yaml
`,
			want: ErrServiceNameRequired,
		},
		{
			name: "persona con service",
			rules: `
version: 1
rules:
  - match: x
    type: person
    service: api
    template: templates/person.yaml
`,
			want: ErrServiceNameOnPerson,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rulesPath := writeRules(t, tc.rules, map[string]string{
				"person.yaml": minimalPersonTemplate,
				"svc.yaml":    minimalServiceTemplate,
			})
			_, err := NewRouterFromFile(rulesPath, "prod")
			if !errors.Is(err, tc.want) {
				t.Fatalf("esperaba %v, obtuve %v", tc.want, err)
			}
		})
	}
}

func TestRouterRejectsMissingTemplateFile(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: x
    type: person
    template: templates/no-existe.yaml
`, nil)

	if _, err := NewRouterFromFile(rulesPath, "prod"); err == nil {
		t.Fatal("esperaba error por plantilla inexistente")
	}
}

func TestRouterRejectsEmptyInstance(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: "*"
    type: person
    template: templates/person.yaml
`, map[string]string{"person.yaml": minimalPersonTemplate})

	if _, err := NewRouterFromFile(rulesPath, ""); err == nil {
		t.Fatal("esperaba error por instancia vacía")
	}
}

// --- la configuración que se despliega ------------------------------------------------

// Valida config/rules.yaml y TODAS sus plantillas reales. Es la red que hace que un error
// de tipeo en una plantilla se vea en `go test` y no en un deploy.
func TestShippedConfigIsValid(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no hay config desplegable en %s: %v", rulesPath, err)
	}

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("la configuración desplegable no valida: %v", err)
	}

	// Cada rol declarado tiene que resolver a permisos expandibles.
	for _, roles := range [][]string{
		{"poc-admin"}, {"poc-user"}, {"poc-service"},
	} {
		t.Run(roles[0], func(t *testing.T) {
			id, perms, decision, err := router.Resolve(roles, "sub-de-prueba", "prueba")
			if err != nil {
				t.Fatalf("Resolve(%v): %v", roles, err)
			}
			if len(perms.PubAllow) == 0 && len(perms.SubAllow) == 0 {
				t.Fatalf("%s no concede ningún permiso", decision.Template)
			}
			// Ninguna plantilla debe dejar un placeholder sin expandir.
			for _, subject := range slices.Concat(perms.PubAllow, perms.SubAllow, perms.PubDeny, perms.SubDeny) {
				if placeholderRE.MatchString(subject) {
					t.Fatalf("%s dejó un placeholder sin expandir: %q", decision.Template, subject)
				}
			}
			// Una persona nunca debe recibir permisos de un servicio y al revés: el
			// aislamiento entre tipos de usuario depende de esto.
			if id.Type == UserTypePerson && id.Service != "" {
				t.Fatalf("%s: una persona no debe tener nombre de servicio", decision.Template)
			}
		})
	}
}

// Todo bucket de KV necesita EXACTAMENTE un servicio con `manage: true`.
//
// Con cero, nadie puede crearlo y las operaciones de datos fallan con "stream not found",
// que no dice nada sobre la causa real. Con más de uno, dos servicios pueden reconfigurar
// o purgar el mismo bucket y la última migración que corra gana.
//
// Este invariante no lo puede chequear el loader de una plantilla —es global al config— así
// que se verifica acá.
func TestEveryKVBucketHasExactlyOneManager(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no hay config desplegable: %v", err)
	}

	cfg, err := LoadRulesConfig(rulesPath)
	if err != nil {
		t.Fatalf("LoadRulesConfig: %v", err)
	}

	managers := map[string][]string{} // bucket -> plantillas que lo administran
	seen := map[string]bool{}         // bucket -> aparece en alguna plantilla

	for _, rule := range cfg.Rules {
		path := filepath.Join(filepath.Dir(rulesPath), rule.Template)
		tmpl, err := LoadTemplate(path)
		if err != nil {
			t.Fatalf("LoadTemplate(%s): %v", path, err)
		}
		for _, kv := range tmpl.KV {
			seen[kv.Bucket] = true
			if kv.Manage {
				managers[kv.Bucket] = append(managers[kv.Bucket], filepath.Base(path))
			}
		}
	}

	if len(seen) == 0 {
		t.Skip("la config no referencia ningún bucket de KV")
	}

	for bucket := range seen {
		switch n := len(managers[bucket]); {
		case n == 0:
			t.Errorf("el bucket %q no tiene ninguna plantilla con `manage: true`: nadie puede crearlo", bucket)
		case n > 1:
			t.Errorf("el bucket %q tiene %d administradores (%v): debe tener exactamente uno",
				bucket, n, managers[bucket])
		}
	}
}

// Una persona solo puede publicar bajo SU PROPIO user id. Es la propiedad que sostiene todo
// el modelo: si un cliente pudiera publicar bajo otro user id, el receptor no podría confiar
// en la identidad que lee del subject y habría que reautorizar en cada servicio.
func TestPersonTemplatesPublishOnlyUnderOwnUserID(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no hay config desplegable: %v", err)
	}

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	for _, role := range []string{"poc-admin", "poc-user"} {
		id, perms, decision, err := router.Resolve([]string{role}, "sub-"+role, role)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", role, err)
		}
		if id.Type != UserTypePerson {
			t.Fatalf("%s: esperaba una identidad de persona", decision.Template)
		}
		for _, subject := range perms.PubAllow {
			// Los subjects de KV/JetStream no siguen esta gramática; se saltean.
			if strings.HasPrefix(subject, "$") {
				continue
			}
			want := "dev." + id.UserID + "."
			if !strings.HasPrefix(subject, want) {
				t.Fatalf("%s: una persona no debería poder publicar en %q (esperaba el prefijo %q)",
					decision.Template, subject, want)
			}
		}
	}
}

// Sin catch-all en el config desplegado, un token válido de Zitadel con un rol que no está
// declarado NO conecta. Es una de las cosas que la prueba contra Zitadel real verifica.
func TestShippedConfigRejectsUnknownRole(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no hay config desplegable: %v", err)
	}

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	for _, roles := range [][]string{nil, {"rol-inexistente"}, {"ad-admin", "vd-user"}} {
		if _, _, _, err := router.Resolve(roles, "sub-x", "x"); !errors.Is(err, ErrNoRuleMatched) {
			t.Fatalf("Resolve(%v): esperaba ErrNoRuleMatched, obtuve %v", roles, err)
		}
	}
}
