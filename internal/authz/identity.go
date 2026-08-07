package authz

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// UserType distingue las dos clases de identidad que el callout autentica. Determina
// cómo se deriva la sesión (y por lo tanto qué subjects puede tocar el cliente), no
// qué permisos recibe: eso lo decide la plantilla.
type UserType string

const (
	// UserTypePerson es una persona: un usuario humano de Zitadel que entra por OIDC.
	// Su sesión se deriva del `sub` del token.
	UserTypePerson UserType = "person"
	// UserTypeService es un service user (machine user de Zitadel) que representa a un
	// backend. Su sesión es el nombre del servicio, declarado en la regla.
	UserTypeService UserType = "service"
)

// IsValid indica si t es un tipo de usuario conocido.
func (t UserType) IsValid() bool {
	return t == UserTypePerson || t == UserTypeService
}

// Identity es la identidad ya resuelta de una conexión: lo que las plantillas expanden.
//
// Es deliberadamente chica. La gramática de subjects es
// `<instancia>.<session>.<svc>.<method>`, así que a una plantilla le alcanza con saber
// en qué instancia está, quién es el caller (session) y —si es un servicio— cómo se
// llama para poder atender su propio endpoint.
type Identity struct {
	// Instance es la instancia de deploy (dev/stage/prod). Primer token de todo
	// subject: aísla despliegues que comparten un NATS.
	Instance string
	// Session identifica al caller dentro de la instancia. Para una persona es un hash
	// estable de su `sub`; para un servicio es su nombre.
	Session string
	// Service es el nombre del servicio cuando Type es service; vacío para personas.
	Service string
	// Type es person o service.
	Type UserType
	// Subject es el `sub` del token (userId de Zitadel). Para trazas y auditoría.
	Subject string
	// Username es el nombre legible del token, si vino. Va al campo Name del User JWT,
	// que es lo que aparece en `nats server report connections`.
	Username string
}

// placeholders expone la identidad como el mapa que consumen las plantillas.
//
// `service` se expone siempre (vacío para personas) para que una plantilla de persona
// que lo use por error falle en la validación de arranque y no en runtime.
func (id Identity) placeholders() map[string]string {
	return map[string]string{
		"instance": id.Instance,
		"session":  id.Session,
		"service":  id.Service,
	}
}

// InboxPrefix es el prefijo de inbox privado que le corresponde a esta identidad.
//
// El cliente DEBE configurar este prefijo al conectar (`nats.CustomInboxPrefix` en Go,
// `inboxPrefix` en nats.js). Sin eso la librería genera `_INBOX.<nuid>` aleatorio, que
// ningún permiso acotado autoriza — y la única alternativa sería conceder `_INBOX.>`,
// con lo que cualquier cliente de la cuenta podría leer las respuestas de los demás.
//
// Por eso la sesión de una persona es determinista: el cliente la recalcula de su
// propio token, sin canal lateral. Cada conexión agrega su propio token único bajo el
// prefijo, así que dos conexiones del mismo usuario no se cruzan.
func (id Identity) InboxPrefix() string {
	return "_INBOX." + id.Session
}

// sessionEncoding produce sesiones cortas y seguras para un subject NATS: base32 sin
// padding y en minúscula, sin `.`, `*` ni `>`.
var sessionEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// sessionLen es el largo de la sesión derivada. 16 caracteres base32 son 80 bits de
// sha256: de sobra para que no haya colisiones entre usuarios y corto para leer en logs.
const sessionLen = 16

// DeriveSession deriva la sesión de una persona a partir del `sub` del token.
//
// Es determinista a propósito (mismo usuario -> misma sesión), porque el cliente tiene
// que poder reconstruir su prefijo de inbox por su cuenta. La contrapartida es que la
// sesión no distingue conexiones del mismo usuario; no hace falta que lo haga, porque
// el aislamiento que se busca es entre usuarios.
//
// Se hashea en vez de usar el `sub` crudo para no filtrar identificadores de Zitadel en
// los subjects (que se ven en logs, monitoreo y trazas).
func DeriveSession(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return strings.ToLower(sessionEncoding.EncodeToString(sum[:])[:sessionLen])
}
