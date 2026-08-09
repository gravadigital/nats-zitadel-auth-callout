package authz

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// UserType distingue las dos clases de identidad que el callout autentica. Determina
// qué endpoint puede atender un cliente, no qué permisos recibe: eso lo decide la
// plantilla.
//
// Lo que NO distingue es el user id: persona y servicio son ambos usuarios de Zitadel y
// ambos traen `sub`, así que los dos usan su `sub` como user id.
type UserType string

const (
	// UserTypePerson es una persona: un usuario humano de Zitadel que entra por OIDC.
	UserTypePerson UserType = "person"
	// UserTypeService es un service user (machine user de Zitadel) que representa a un
	// backend. Además del user id tiene un nombre de servicio, declarado en la regla,
	// que es el endpoint que atiende.
	UserTypeService UserType = "service"
)

// IsValid indica si t es un tipo de usuario conocido.
func (t UserType) IsValid() bool {
	return t == UserTypePerson || t == UserTypeService
}

// Identity es la identidad ya resuelta de una conexión: lo que las plantillas expanden.
//
// Es deliberadamente chica. La gramática de subjects es
// `<instancia>.<user-id>.<svc>.<method>`, así que a una plantilla le alcanza con saber
// en qué instancia está, quién es el caller (user id) y —si es un servicio— cómo se
// llama para poder atender su propio endpoint.
type Identity struct {
	// Instance es la instancia de deploy (dev/stage/prod). Primer token de todo
	// subject: aísla despliegues que comparten un NATS.
	Instance string
	// UserID identifica al caller dentro de la instancia: es el `sub` del token, el
	// userId de Zitadel, tal cual. Vale igual para personas y para service users, porque
	// ambos son usuarios de Zitadel.
	//
	// Va CRUDO en el subject, a propósito: es lo que hace que un subject sea legible y
	// que un servicio pueda saber quién lo llamó leyendo el subject (avalado por el
	// callout) en vez del cuerpo del mensaje. La contrapartida es que el userId de
	// Zitadel queda visible en subjects, logs y trazas.
	UserID string
	// Service es el nombre del servicio cuando Type es service; vacío para personas.
	// Es el ENDPOINT que atiende, no su identidad: quién es lo dice UserID.
	Service string
	// Type es person o service.
	Type UserType
	// Username es el nombre legible del token, si vino. Va al campo Name del User JWT,
	// que es lo que aparece en `nats server report connections`.
	Username string
}

// placeholders expone la identidad como el mapa que consumen las plantillas.
//
// `service` se expone siempre (vacío para personas) para que una plantilla de persona
// que lo use por error falle en la validación de arranque y no en runtime.
//
// `user_id_hash` se expone ya calculado para que una plantilla pueda escribir el inbox
// como `_INBOX.{{user_id_hash}}.>` sin conocer cómo se deriva.
func (id Identity) placeholders() map[string]string {
	return map[string]string{
		"instance":     id.Instance,
		"user_id":      id.UserID,
		"user_id_hash": HashUserID(id.UserID),
		"service":      id.Service,
	}
}

// InboxPrefix es el prefijo de inbox privado que le corresponde a esta identidad:
// `_INBOX.<hash(user-id)>`.
//
// El cliente DEBE configurar este prefijo al conectar (`nats.CustomInboxPrefix` en Go,
// `inboxPrefix` en nats.js). Sin eso la librería genera `_INBOX.<nuid>` aleatorio, que
// ningún permiso acotado autoriza — y la única alternativa sería conceder `_INBOX.>`,
// con lo que cualquier cliente de la cuenta podría leer las respuestas de los demás.
//
// Por eso el hash es determinista: el cliente lo recalcula de su propio token, sin canal
// lateral. Cada conexión agrega su propio token único bajo el prefijo, así que dos
// conexiones del mismo usuario no se cruzan.
func (id Identity) InboxPrefix() string {
	return "_INBOX." + HashUserID(id.UserID)
}

// userIDHashEncoding produce hashes cortos y seguros para un subject NATS: base32 sin
// padding y en minúscula, sin `.`, `*` ni `>`.
var userIDHashEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// userIDHashLen es el largo del hash. 16 caracteres base32 son 80 bits de sha256: de
// sobra para que no haya colisiones entre usuarios y corto para leer en logs.
const userIDHashLen = 16

// HashUserID deriva el hash de user id que se usa como prefijo de inbox.
//
// Es determinista a propósito (mismo usuario -> mismo inbox), porque el cliente tiene
// que poder reconstruir su prefijo por su cuenta. No distingue conexiones del mismo
// usuario; no hace falta que lo haga, porque el aislamiento que se busca es entre
// usuarios.
//
// Nota sobre qué protege y qué no: el user id va crudo en los subjects de mensajería, así
// que este hash no oculta la identidad de nadie —quien vea un subject ya vio el user id—.
// Existe porque el inbox necesita UN token opaco y de largo fijo, no porque sea un
// secreto.
func HashUserID(userID string) string {
	sum := sha256.Sum256([]byte(userID))
	return strings.ToLower(userIDHashEncoding.EncodeToString(sum[:])[:userIDHashLen])
}
