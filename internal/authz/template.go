// Package authz traduce la identidad autenticada (rol + tipo de usuario) en el set de
// permisos NATS que el callout mintea en el User JWT.
//
// El modelo tiene dos piezas:
//
//	rules.yaml   rol del token -> (tipo de usuario, plantilla)   [routing, first-match-wins]
//	templates/   plantilla -> permisos pub/sub + accesos a KV     [el permiso concreto]
//
// Ambas se montan por path y se leen al arrancar: cambiar quién puede qué NO recompila.
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

// Errores de plantilla.
var (
	// ErrUnknownPlaceholder marca una plantilla que usa un {{...}} que no existe.
	ErrUnknownPlaceholder = errors.New("authz: placeholder desconocido en la plantilla")
	// ErrInvalidSubject marca un subject que, ya expandido, no es un subject NATS válido.
	ErrInvalidSubject = errors.New("authz: subject inválido")
	// ErrInvalidKVAccess marca un nivel de acceso a KV que no existe.
	ErrInvalidKVAccess = errors.New("authz: nivel de acceso KV inválido")
	// ErrEmptyBucket marca una entrada de KV sin bucket.
	ErrEmptyBucket = errors.New("authz: falta el bucket en la entrada kv")
)

// placeholderRE captura {{nombre}} con espacios opcionales: {{ session }} también vale.
var placeholderRE = regexp.MustCompile(`\{\{\s*([a-z][a-z0-9_]*)\s*\}\}`)

// Niveles de acceso a los DATOS de un bucket KV.
//
// El ciclo de vida del bucket (crear, reconfigurar, purgar) es un eje SEPARADO: KVAccess.Manage.
// Son cosas distintas y conviene poder combinarlas: el BFF es dueño del bucket de
// preferencias —lo crea y lo migra— pero solo LEE las preferencias, porque escribir la
// preferencia de alguien le corresponde a ese alguien. Un único nivel "admin" que
// incluyera escritura no permitiría expresar eso.
const (
	// KVNone no da acceso a los datos. Sirve combinado con Manage: el servicio que
	// administra el ciclo de vida de un bucket no necesariamente tiene que poder leer lo
	// que hay adentro (p.ej. el que corre las migraciones de un bucket ajeno).
	KVNone = "none"
	// KVRead permite abrir el bucket y leer claves (Get).
	KVRead = "read"
	// KVReadWrite agrega escritura y borrado de claves (Put/Delete).
	KVReadWrite = "read-write"
)

// Template es una plantilla de permisos: el YAML tal como se escribe en
// config/templates/. Los subjects pueden llevar placeholders {{...}} que se expanden
// por sesión con la identidad ya autenticada (ver Identity.placeholders).
type Template struct {
	// Pub son los permisos de publicación.
	Pub SubjectSet `yaml:"pub"`
	// Sub son los permisos de suscripción.
	Sub SubjectSet `yaml:"sub"`
	// KV declara accesos a buckets KV en alto nivel. El loader los traduce a los
	// subjects $KV.*/$JS.API.* concretos y los agrega a Pub/Sub — así una plantilla
	// no tiene que conocer el protocolo de JetStream.
	KV []KVAccess `yaml:"kv"`
	// Response controla allow_responses: habilita responder al inbox del caller sin
	// un permiso de pub explícito hacia ese inbox. Es lo que necesita un servicio
	// para contestar requests.
	Response *ResponseRule `yaml:"response"`
}

// SubjectSet es un par allow/deny de subjects. NATS evalúa deny sobre allow, así que
// deny sirve para recortar un allow amplio (p.ej. permitir `svc.>` menos un método).
type SubjectSet struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// KVAccess es un acceso declarado a un bucket KV.
type KVAccess struct {
	// Bucket es el nombre del bucket (sin el prefijo KV_ del stream).
	Bucket string `yaml:"bucket"`
	// Access es el acceso a los DATOS: read | read-write. Default read.
	Access string `yaml:"access"`
	// Manage habilita el CICLO DE VIDA del bucket: crearlo, reconfigurarlo, borrarlo y
	// purgarlo. Es ortogonal a Access, y cada bucket necesita exactamente un servicio que
	// lo tenga — si no, nadie puede crearlo y las operaciones de datos fallan con
	// "stream not found" sin decir por qué.
	Manage bool `yaml:"manage"`
	// Keys acota QUÉ claves alcanza el permiso, como patrón de subject NATS relativo
	// al bucket. Admite placeholders: `{{session}}.>` deja al caller operar solo bajo
	// su propia sesión. Default `>` (todas).
	Keys string `yaml:"keys"`
	// Watch habilita Watch()/Keys(), que crean un consumer efímero sobre el bucket.
	// Va aparte porque no se puede acotar por clave: un watcher ve todo el bucket.
	Watch bool `yaml:"watch"`
}

// ResponseRule es allow_responses: cuántas respuestas y por cuánto tiempo.
type ResponseRule struct {
	Max int    `yaml:"max"`
	TTL string `yaml:"ttl"`
}

// Permissions es el resultado ya expandido: lo que va al User JWT.
type Permissions struct {
	PubAllow []string
	PubDeny  []string
	SubAllow []string
	SubDeny  []string
	// RespMax y RespTTL son allow_responses; RespMax 0 significa sin allow_responses.
	RespMax int
	RespTTL time.Duration
}

// LoadTemplate lee y parsea una plantilla, y valida que expanda limpio. La validación
// se hace acá, al arrancar, con una identidad de prueba: un placeholder mal escrito o
// un subject inválido rompe el arranque en vez de emitir un JWT roto en producción.
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: leer plantilla %q: %w", path, err)
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("authz: parsear plantilla %q: %w", path, err)
	}
	// Dry-run de expansión: detecta placeholders desconocidos, buckets vacíos,
	// niveles de acceso inválidos y subjects malformados antes de servir tráfico.
	probe := Identity{Instance: "probe", Session: "probe", Service: "probe"}
	if _, err := t.Expand(probe); err != nil {
		return nil, fmt.Errorf("authz: validar plantilla %q: %w", path, err)
	}
	return &t, nil
}

// Expand resuelve la plantilla contra una identidad concreta y devuelve los permisos
// finales, con los accesos a KV ya traducidos a subjects.
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

	// Los accesos a KV se agregan a los mismos allow-lists: para NATS un permiso de KV
	// no es nada especial, es pub/sub sobre los subjects internos de JetStream.
	if len(t.KV) > 0 {
		// Todo cliente de JetStream arranca preguntando por la cuenta. No es por bucket, así
		// que se concede una vez y no por entrada. Sin esto, la inicialización del contexto
		// de JetStream se queda esperando y el error que ve el cliente es un timeout, que no
		// dice nada sobre la causa real.
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

// defaultResponseTTL es la vigencia de allow_responses cuando la plantilla fija `max`
// pero no `ttl`. 30s es el default de NATS.
const defaultResponseTTL = 30 * time.Second

// jsAccountInfoSubject es el request de info de JetStream de la cuenta. Lo hace todo
// cliente al inicializar su contexto de JetStream. Expone los límites y el uso de la
// cuenta, no datos de ningún bucket.
const jsAccountInfoSubject = "$JS.API.INFO"

// subjects traduce un KVAccess a los subjects pub/sub que ese nivel de acceso requiere.
//
// El mapeo sale del protocolo de JetStream KV (verificado contra nats.go/jetstream):
//
//	abrir bucket   pub  $JS.API.STREAM.INFO.KV_<b>
//	Get(key)       pub  $JS.API.DIRECT.GET.KV_<b>.$KV.<b>.<key>   (get-last-by-subject)
//	               sub  $KV.<b>.<key>                             (llega el valor)
//	Put/Delete     pub  $KV.<b>.<key>
//	Watch/Keys     pub  $JS.API.CONSUMER.CREATE.KV_<b>.>
//
// Que el direct-get lleve la clave DENTRO del subject es lo que hace posible acotar la
// lectura por clave — y por lo tanto por usuario, vía el placeholder {{session}}.
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

	stream := "KV_" + bucket             // nombre del stream que respalda el bucket
	data := "$KV." + bucket + "." + keys // subjects de datos del bucket, ya acotados

	access := k.Access
	if access == "" {
		access = KVRead
	}

	switch access {
	case KVNone, KVRead, KVReadWrite:
	default:
		return nil, nil, fmt.Errorf("%w: %q (esperaba %s|%s|%s)",
			ErrInvalidKVAccess, access, KVNone, KVRead, KVReadWrite)
	}

	if access != KVNone {
		// Lectura: abrir el bucket + direct-get de las claves permitidas + recibir el valor.
		pub = append(pub,
			"$JS.API.STREAM.INFO."+stream,
			"$JS.API.DIRECT.GET."+stream+"."+data,
		)
		sub = append(sub, data)

		// Get por revisión (GetRevision) usa STREAM.MSG.GET, que NO lleva la clave en el
		// subject y por lo tanto no se puede acotar. Solo se concede cuando el acceso ya
		// cubre todo el bucket; si no, dárselo anularía el scoping por clave.
		if keys == ">" {
			pub = append(pub, "$JS.API.STREAM.MSG.GET."+stream)
		}

		if k.Watch {
			// Un consumer efímero ve el bucket completo: no hay forma de acotarlo por clave.
			pub = append(pub,
				"$JS.API.CONSUMER.CREATE."+stream+".>",
				"$JS.API.CONSUMER.DELETE."+stream+".>",
			)
		}
	}

	if access == KVReadWrite {
		pub = append(pub, data) // Put/Delete publican en el subject de la clave
	}

	if k.Manage {
		pub = append(pub,
			"$JS.API.STREAM.CREATE."+stream,
			"$JS.API.STREAM.UPDATE."+stream,
			"$JS.API.STREAM.DELETE."+stream,
			"$JS.API.STREAM.PURGE."+stream,
		)
		// Crear un bucket empieza por consultar si ya existe, así que administrarlo exige
		// STREAM.INFO. Con acceso de lectura ya se concedió arriba; con `none`, no.
		if access == KVNone {
			pub = append(pub, "$JS.API.STREAM.INFO."+stream)
		}
	}

	return pub, sub, nil
}

// expandAll expande una lista de subjects y valida cada resultado.
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

// expandOne reemplaza los {{placeholder}} de s. Un placeholder desconocido es un error
// y no un reemplazo vacío: un subject con un segmento vacío nunca matchea nada, así que
// fallar acá evita minteear permisos que silenciosamente no sirven.
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
		return "", fmt.Errorf("%w: %s (en %q; disponibles: %s)",
			ErrUnknownPlaceholder, strings.Join(missing, ", "), s, availablePlaceholders(vars))
	}
	return out, nil
}

// availablePlaceholders lista los placeholders válidos, para que el error de arranque
// diga qué se podía usar.
func availablePlaceholders(vars map[string]string) string {
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	// Orden estable para que el mensaje de error sea reproducible.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return strings.Join(names, ", ")
}

// validateSubject chequea que un subject ya expandido sea válido para NATS: sin
// segmentos vacíos y con `>` solo como último token.
func validateSubject(subject string) error {
	if subject == "" {
		return fmt.Errorf("%w: vacío", ErrInvalidSubject)
	}
	tokens := strings.Split(subject, ".")
	for i, tok := range tokens {
		if tok == "" {
			return fmt.Errorf("%w: %q tiene un segmento vacío en la posición %d", ErrInvalidSubject, subject, i)
		}
		if tok == ">" && i != len(tokens)-1 {
			return fmt.Errorf("%w: %q usa `>` sin ser el último token", ErrInvalidSubject, subject)
		}
	}
	return nil
}
