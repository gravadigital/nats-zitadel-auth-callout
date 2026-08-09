package authz

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// personIdentity es una identidad de persona de prueba.
func personIdentity() Identity {
	return Identity{Instance: "prod", UserID: "abc123", Type: UserTypePerson}
}

// serviceIdentity es una identidad de servicio de prueba. Un service user tiene su propio
// user id (su `sub`) además del nombre de endpoint: son ejes distintos, así que acá llevan
// valores distintos a propósito.
func serviceIdentity() Identity {
	return Identity{Instance: "prod", UserID: "svc-sub-1", Service: "api", Type: UserTypeService}
}

func TestExpandPlaceholders(t *testing.T) {
	tmpl := &Template{
		Pub: SubjectSet{
			Allow: []string{"{{instance}}.{{user_id}}.api.>"},
			Deny:  []string{"{{instance}}.{{user_id}}.api.danger"},
		},
		Sub: SubjectSet{Allow: []string{"_INBOX.{{user_id_hash}}.>"}},
	}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	assertSubjects(t, "pub allow", perms.PubAllow, []string{"prod.abc123.api.>"})
	assertSubjects(t, "pub deny", perms.PubDeny, []string{"prod.abc123.api.danger"})
	// El inbox va bajo el HASH del user id, no bajo el user id crudo.
	assertSubjects(t, "sub allow", perms.SubAllow, []string{"_INBOX." + HashUserID("abc123") + ".>"})
}

func TestExpandServicePlaceholder(t *testing.T) {
	tmpl := &Template{
		Sub: SubjectSet{Allow: []string{"{{instance}}.*.{{service}}.>"}},
	}

	perms, err := tmpl.Expand(serviceIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	assertSubjects(t, "sub allow", perms.SubAllow, []string{"prod.*.api.>"})
}

func TestExpandUnknownPlaceholderFails(t *testing.T) {
	tmpl := &Template{Pub: SubjectSet{Allow: []string{"{{instance}}.{{tenant}}.api.>"}}}

	_, err := tmpl.Expand(personIdentity())
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("esperaba ErrUnknownPlaceholder, obtuve %v", err)
	}
}

// Un placeholder desconocido no debe resolverse a vacío: eso produciría un subject con un
// segmento faltante que nunca matchea, y el permiso quedaría inerte sin que nadie lo note.
func TestExpandUnknownPlaceholderDoesNotSilentlyDrop(t *testing.T) {
	tmpl := &Template{Pub: SubjectSet{Allow: []string{"{{instance}}.{{nope}}.api.>"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err == nil {
		t.Fatalf("esperaba error, obtuve permisos %v", perms.PubAllow)
	}
}

func TestExpandRejectsInvalidSubject(t *testing.T) {
	cases := map[string][]string{
		"segmento vacío": {"prod..api.>"},
		"> no terminal":  {"prod.>.api"},
		"subject vacío":  {""},
	}
	for name, subjects := range cases {
		t.Run(name, func(t *testing.T) {
			tmpl := &Template{Pub: SubjectSet{Allow: subjects}}
			_, err := tmpl.Expand(personIdentity())
			if !errors.Is(err, ErrInvalidSubject) {
				t.Fatalf("esperaba ErrInvalidSubject, obtuve %v", err)
			}
		})
	}
}

func TestResponseRule(t *testing.T) {
	t.Run("ttl explícito", func(t *testing.T) {
		tmpl := &Template{Response: &ResponseRule{Max: 2, TTL: "45s"}}
		perms, err := tmpl.Expand(personIdentity())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if perms.RespMax != 2 || perms.RespTTL != 45*time.Second {
			t.Fatalf("esperaba max=2 ttl=45s, obtuve max=%d ttl=%s", perms.RespMax, perms.RespTTL)
		}
	})

	t.Run("ttl por defecto", func(t *testing.T) {
		tmpl := &Template{Response: &ResponseRule{Max: 1}}
		perms, err := tmpl.Expand(personIdentity())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if perms.RespTTL != defaultResponseTTL {
			t.Fatalf("esperaba el TTL por defecto %s, obtuve %s", defaultResponseTTL, perms.RespTTL)
		}
	})

	t.Run("sin response no hay allow_responses", func(t *testing.T) {
		perms, err := (&Template{}).Expand(personIdentity())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if perms.RespMax != 0 {
			t.Fatalf("esperaba RespMax=0, obtuve %d", perms.RespMax)
		}
	})
}

// --- KV -------------------------------------------------------------------------------
//
// Estos tests fijan el mapeo de acceso KV -> subjects de JetStream. Es la parte del
// diseño más fácil de romper sin darse cuenta: un subject mal armado no falla al
// arrancar, simplemente hace que el KV no funcione (o que funcione de más).

func TestKVReadSubjects(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "gestion-catalog", Access: KVRead, Keys: ">"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	assertSubjects(t, "pub", perms.PubAllow, []string{
		jsAccountInfoSubject,
		"$JS.API.STREAM.INFO.KV_gestion-catalog",
		"$JS.API.DIRECT.GET.KV_gestion-catalog.$KV.gestion-catalog.>",
		"$JS.API.STREAM.MSG.GET.KV_gestion-catalog",
	})
	assertSubjects(t, "sub", perms.SubAllow, []string{"$KV.gestion-catalog.>"})

	// Lectura no implica escritura: el subject de datos no puede estar en pub.
	if slices.Contains(perms.PubAllow, "$KV.gestion-catalog.>") {
		t.Fatal("el acceso read no debe conceder pub sobre el subject de datos (sería escritura)")
	}
}

// El caso que sostiene "permisos de KV variables por usuario": el direct-get lleva la
// clave DENTRO del subject, así que acotar por {{user_id}} lo hace cumplir el servidor.
func TestKVScopedByUserID(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "gestion-prefs",
		Access: KVReadWrite,
		Keys:   "{{user_id}}.>",
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	assertSubjects(t, "pub", perms.PubAllow, []string{
		jsAccountInfoSubject,
		"$JS.API.STREAM.INFO.KV_gestion-prefs",
		"$JS.API.DIRECT.GET.KV_gestion-prefs.$KV.gestion-prefs.abc123.>",
		"$KV.gestion-prefs.abc123.>",
	})
	assertSubjects(t, "sub", perms.SubAllow, []string{"$KV.gestion-prefs.abc123.>"})
}

// Con acceso acotado por clave NO se concede STREAM.MSG.GET: ese subject no lleva la
// clave, así que permitirlo dejaría leer todo el bucket por número de revisión y anularía
// el scoping.
func TestKVScopedAccessDeniesRevisionGet(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "gestion-prefs",
		Access: KVRead,
		Keys:   "{{user_id}}.>",
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if slices.Contains(perms.PubAllow, "$JS.API.STREAM.MSG.GET.KV_gestion-prefs") {
		t.Fatal("un acceso acotado por clave no debe conceder STREAM.MSG.GET (permitiría leer todo el bucket)")
	}
}

func TestKVWatchAddsConsumerSubjects(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "gestion-sessions",
		Access: KVRead,
		Keys:   ">",
		Watch:  true,
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	for _, want := range []string{
		"$JS.API.CONSUMER.CREATE.KV_gestion-sessions.>",
		"$JS.API.CONSUMER.DELETE.KV_gestion-sessions.>",
	} {
		if !slices.Contains(perms.PubAllow, want) {
			t.Fatalf("falta %q en pub allow: %v", want, perms.PubAllow)
		}
	}
}

func TestKVWatchDisabledByDefault(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b", Access: KVRead, Keys: ">"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if slices.Contains(perms.PubAllow, "$JS.API.CONSUMER.CREATE.KV_b.>") {
		t.Fatal("watch no debe estar habilitado si la plantilla no lo pide")
	}
}

func TestKVManageAddsStreamManagement(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "gestion-catalog",
		Access: KVRead,
		Manage: true,
		Keys:   ">",
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	for _, want := range []string{
		"$JS.API.STREAM.CREATE.KV_gestion-catalog",
		"$JS.API.STREAM.UPDATE.KV_gestion-catalog",
		"$JS.API.STREAM.DELETE.KV_gestion-catalog",
		"$JS.API.STREAM.PURGE.KV_gestion-catalog",
	} {
		if !slices.Contains(perms.PubAllow, want) {
			t.Fatalf("falta %q en pub allow: %v", want, perms.PubAllow)
		}
	}
	// `manage` es el ciclo de vida del bucket, NO acceso a los datos: administrar sin
	// `read-write` no debe conceder escritura. Es lo que permite que el BFF sea dueño del
	// bucket de preferencias y a la vez no pueda escribir las de nadie.
	if slices.Contains(perms.PubAllow, "$KV.gestion-catalog.>") {
		t.Fatal("manage no debe conceder escritura de datos")
	}
}

// El caso manage-sin-datos: administrar un bucket ajeno sin poder leer lo que hay adentro.
func TestKVManageWithoutDataAccess(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "gestion-sync-state",
		Access: KVNone,
		Manage: true,
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	// Crear un bucket empieza por consultar si existe, así que STREAM.INFO es necesario.
	for _, want := range []string{
		"$JS.API.STREAM.CREATE.KV_gestion-sync-state",
		"$JS.API.STREAM.INFO.KV_gestion-sync-state",
	} {
		if !slices.Contains(perms.PubAllow, want) {
			t.Fatalf("falta %q en pub allow: %v", want, perms.PubAllow)
		}
	}

	// Y nada de datos: ni leer ni escribir.
	if len(perms.SubAllow) != 0 {
		t.Fatalf("access none no debe conceder sub sobre los datos: %v", perms.SubAllow)
	}
	for _, unwanted := range []string{
		"$KV.gestion-sync-state.>",
		"$JS.API.DIRECT.GET.KV_gestion-sync-state.$KV.gestion-sync-state.>",
	} {
		if slices.Contains(perms.PubAllow, unwanted) {
			t.Fatalf("access none no debe conceder %q: %v", unwanted, perms.PubAllow)
		}
	}
}

// access: none sin manage no concede NADA sobre el bucket — es una entrada inerte, pero
// válida (sirve para dejarlo documentado en la plantilla y habilitarlo después).
//
// Lo único que queda es $JS.API.INFO, que se concede por plantilla y no por bucket: es el
// request de info de la cuenta, no expone ningún dato.
func TestKVNoneWithoutManageGrantsNothingOnTheBucket(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b", Access: KVNone}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	assertSubjects(t, "pub", perms.PubAllow, []string{jsAccountInfoSubject})
	if len(perms.SubAllow) != 0 {
		t.Fatalf("esperaba ningún sub, obtuve %v", perms.SubAllow)
	}
}

// $JS.API.INFO se concede solo si la plantilla declara algún acceso a KV: una plantilla sin
// `kv:` no debe poder consultar la cuenta de JetStream.
func TestJetStreamInfoOnlyWhenKVDeclared(t *testing.T) {
	tmpl := &Template{Pub: SubjectSet{Allow: []string{"{{instance}}.{{user_id}}.api.>"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if slices.Contains(perms.PubAllow, jsAccountInfoSubject) {
		t.Fatalf("una plantilla sin kv: no debe conceder %s", jsAccountInfoSubject)
	}
}

func TestKVDefaultsToReadAllKeys(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	assertSubjects(t, "sub", perms.SubAllow, []string{"$KV.b.>"})
	if slices.Contains(perms.PubAllow, "$KV.b.>") {
		t.Fatal("el acceso por defecto debe ser de solo lectura")
	}
}

func TestKVInvalidAccessFails(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b", Access: "write-only"}}}

	_, err := tmpl.Expand(personIdentity())
	if !errors.Is(err, ErrInvalidKVAccess) {
		t.Fatalf("esperaba ErrInvalidKVAccess, obtuve %v", err)
	}
}

func TestKVEmptyBucketFails(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Access: KVRead}}}

	_, err := tmpl.Expand(personIdentity())
	if !errors.Is(err, ErrEmptyBucket) {
		t.Fatalf("esperaba ErrEmptyBucket, obtuve %v", err)
	}
}

// --- carga desde disco ----------------------------------------------------------------

func TestLoadTemplateRejectsBadPlaceholderAtLoad(t *testing.T) {
	// La validación tiene que pasar al CARGAR, no en la primera conexión: un error de
	// tipeo en una plantilla debe impedir el arranque.
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	content := "pub:\n  allow:\n    - \"{{instance}}.{{nope}}.api.>\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadTemplate(path); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("esperaba ErrUnknownPlaceholder al cargar, obtuve %v", err)
	}
}

func TestLoadTemplateMissingFile(t *testing.T) {
	if _, err := LoadTemplate(filepath.Join(t.TempDir(), "no-existe.yaml")); err == nil {
		t.Fatal("esperaba error por archivo inexistente")
	}
}

// assertSubjects compara sin importar el orden: el orden en el JWT no cambia la semántica
// del permiso, y fijarlo haría el test frágil ante un reordenamiento inocuo.
func assertSubjects(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: esperaba %d subjects %v, obtuve %d %v", label, len(want), want, len(got), got)
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Fatalf("%s: falta %q en %v", label, w, got)
		}
	}
}
