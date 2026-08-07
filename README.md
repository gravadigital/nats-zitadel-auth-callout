# auth-callout — autenticación NATS ↔ Zitadel con permisos variables por rol

Servicio de **auth callout** de NATS para la migración de gestión. Autentica contra Zitadel
las dos clases de conexión al bus —**personas** y **service users**— y le mintea a cada una
los permisos que le corresponden **por rol**, tanto para **mensajes** como para **KV**.

No es un proxy ni un guardián en el camino de los datos: interviene **una sola vez, en el
handshake** de cada conexión. Después, quien aplica los permisos es el propio servidor NATS,
en cada publicación y en cada suscripción.

> **Estado: prueba de concepto.** Los subjects de `config/` son de **ejemplo** —un servicio
> `demo` con tres métodos— elegidos para validar el mecanismo, no el dominio de gestión. El
> mapeo real se define cuando exista el contrato del BFF sobre el bus.
>
> Para correrla contra Zitadel real: **[docs/prueba-zitadel.md](docs/prueba-zitadel.md)**.

---

## 1. Cómo funciona el intercambio

```
                    ┌──────────────┐
                    │   Zitadel    │
                    └──────▲───────┘
                           │ 3. valida el token (JWKS, local)
                           │
  ┌────────┐   1. CONNECT  │        ┌──────────────┐
  │ cliente├───sentinel-client──────▶  NATS server │
  └────────┘   + access token       └──┬────────▲──┘
                                       │        │
                    2. $SYS.REQ.USER.AUTH│      │ 5. User JWT firmado
                       (encriptado XKey) │      │    con los permisos
                                       ┌─▼──────┴──┐
                                       │auth-callout│ 4. rol → plantilla → permisos
                                       └────────────┘
```

1. El cliente conecta con las creds del **`sentinel-client`** (que no concede nada por sí
   solo) y pasa su **access token de Zitadel** en el campo `Token` del CONNECT.
2. Como ese sentinel **no** está declarado en `--auth-user`, el servidor no lo autoriza por
   su cuenta: publica un `authorization_request` en `$SYS.REQ.USER.AUTH`.
3. El callout valida el token contra el JWKS de Zitadel. Verificación **local**, sin
   introspección: no hay un round-trip por conexión.
4. Rutea el **rol** del token a una plantilla y expande los permisos con la identidad de esa
   conexión.
5. Devuelve un **User JWT** recién firmado con esos permisos y con la expiración del token.
   El servidor acepta la conexión con exactamente eso.

Nada de esto vuelve a ocurrir mientras la conexión viva. El costo es un handshake más lento,
no un salto por mensaje.

---

## 2. La gramática de subjects

```
<instancia>.<session>.<svc>.<method>
```

| Segmento | Qué es | Ejemplo |
|---|---|---|
| `instancia` | Despliegue. Aísla dev/stage/prod en un mismo NATS. | `dev` |
| `session` | **Quién llama.** Persona: hash estable de su `sub`. Servicio: su nombre. | `h53hnzl2yizywbco`, `api` |
| `svc` | **A quién le habla.** | `api`, `jira`, `email` |
| `method` | Qué le pide. | `create_project` |

La pieza que sostiene todo es que **`session` es parte del subject y la fija el permiso, no
la aplicación**. Un cliente solo puede publicar bajo su propia sesión, así que el receptor
puede leer del subject quién le habla y confiar en ese dato: viene avalado por el callout, no
por el cuerpo del mensaje.

Un servicio atiende con el caller en wildcard —`dev.*.api.>`— y responde por
`allow_responses`, sin necesitar permiso de publicación hacia el inbox del cliente.

### El prefijo de inbox no es opcional

Cada identidad tiene su inbox privado: `_INBOX.<session>.>`. **El cliente tiene que
configurarlo al conectar**:

```go
nats.Connect(url, nats.UserCredentials(sentinel), nats.Token(accessToken),
    nats.CustomInboxPrefix("_INBOX."+session))       // Go
```
```js
connect({ servers, authenticator, token, inboxPrefix: `_INBOX.${session}` })  // nats.js
```

Sin eso la librería genera un `_INBOX.<aleatorio>` que ningún permiso acotado autoriza, y las
respuestas nunca llegan. La alternativa sería conceder `_INBOX.>`, pero entonces cualquier
cliente de la cuenta podría suscribirse a las respuestas de los demás.

Por eso la sesión de una persona es **determinista**: el cliente la recalcula de su propio
token, sin canal lateral. `cmd/session` es la referencia:

```console
$ go run ./cmd/session 312094857203948572 dev
session      h53hnzl2yizywbco
inbox        _INBOX.h53hnzl2yizywbco
pub (a api)  dev.h53hnzl2yizywbco.api.<method>
```

---

## 3. Los permisos: dos archivos, sin recompilar

```
config/rules.yaml        rol del token  →  (tipo de identidad, plantilla)   [first-match-wins]
config/templates/*.yaml  plantilla      →  permisos pub/sub + accesos a KV
```

Ambos se montan por path y se leen al arrancar. Cambiar quién puede qué **no** recompila.

**El rol es lo único que decide.** No hay heurística que adivine si un token es de una
persona o de un servicio: lo declara `type` en la regla, y el rol lo asigna quien administra
Zitadel. Así "¿qué puede hacer X?" se contesta leyendo dos archivos, sin ejecutar nada.

```yaml
# rules.yaml (el de la PoC)
rules:
  - match: poc-admin        # persona, permisos amplios
    type: person
    template: templates/poc-person-admin.yaml

  - match: poc-user         # persona, permisos acotados
    type: person
    template: templates/poc-person.yaml

  - match: poc-service      # machine user
    type: service
    service: demo           # su sesión y su endpoint
    template: templates/poc-service.yaml
```

Sin coincidencia, **la conexión se rechaza**. No hay permisos por defecto — la PoC no declara
catch-all a propósito, para poder verificarlo.

El orden importa: si un token puede traer dos roles, el que quede **arriba** gana. Poné el más
restrictivo primero.

`type` determina cómo se construye la **identidad**, no los permisos:

| `type` | `session` | Para qué |
|---|---|---|
| `person` | `sha256(sub)` en base32, 16 chars | Aísla usuario de usuario. Determinista para que el cliente derive su inbox. Se hashea para no filtrar identificadores de Zitadel en subjects, que se ven en logs y monitoreo. |
| `service` | el nombre del servicio | Legible en subjects, y **compartido entre réplicas** a propósito: es lo que permite balancear con queue groups. |

### Plantillas

```yaml
pub:
  allow: ["{{instance}}.{{session}}.demo.>"]
  deny:  []
sub:
  allow: ["_INBOX.{{session}}.>"]
kv:
  - bucket: poc-kv
    access: read-write          # none | read | read-write   (datos)
    manage: false               # ciclo de vida del bucket    (ortogonal)
    keys: "{{session}}.>"       # QUÉ claves alcanza
    watch: false
response:
  max: 1                        # allow_responses
  ttl: 45s
```

Placeholders: `{{instance}}`, `{{session}}`, `{{service}}`.

**Allow-list, no deny-list.** Las plantillas de persona enumeran los métodos uno por uno.
Es más largo de mantener, y es a propósito: con una deny-list, un método nuevo queda
accesible hasta que alguien se acuerde de restringirlo. Con una allow-list, no lo alcanza
nadie hasta que se lo habilita. Falla cerrado.

---

## 4. Permisos de KV variables por usuario

Para NATS un permiso de KV no es nada especial: es pub/sub sobre los subjects internos de
JetStream. El bloque `kv:` existe para que ninguna plantilla tenga que conocerlos.

| Operación | Subject | Permiso |
|---|---|---|
| abrir bucket | `$JS.API.STREAM.INFO.KV_<b>` | pub |
| `Get(key)` | `$JS.API.DIRECT.GET.KV_<b>.$KV.<b>.<key>` | pub |
| recibir el valor | `$KV.<b>.<key>` | sub |
| `Put`/`Delete(key)` | `$KV.<b>.<key>` | pub |
| `Watch`/`Keys` | `$JS.API.CONSUMER.CREATE.KV_<b>.>` | pub |
| crear/migrar bucket | `$JS.API.STREAM.{CREATE,UPDATE,DELETE,PURGE}.KV_<b>` | pub |
| (siempre, si hay `kv:`) | `$JS.API.INFO` | pub |

**Que el direct-get lleve la clave dentro del subject es lo que hace posible el scoping por
usuario**, y es el servidor el que lo aplica:

```yaml
kv:
  - bucket: poc-kv
    access: read-write
    keys: "{{session}}.>"     # escribe y lee SOLO lo suyo
```

Tres detalles que el modelo resuelve y conviene conocer:

- **`access` y `manage` son ejes separados.** Un servicio puede ser *dueño* de un bucket —lo
  crea y lo migra— y a la vez solo **leer** los datos: escribir la preferencia de un usuario
  le corresponde a ese usuario. Un único nivel "admin" no permitiría expresarlo. `access: none`
  con `manage: true` es el extremo: administra el bucket sin ver lo que hay adentro.
- **Todo bucket necesita exactamente un `manage: true`.** Con cero, nadie puede crearlo y las
  operaciones fallan con `stream not found`, que no dice nada de la causa. Con más de uno,
  dos servicios pueden purgar el mismo bucket. Hay un test que lo verifica sobre el config
  desplegado.
- **`Get` por revisión y `Watch` no se pueden acotar por clave.** `STREAM.MSG.GET` no lleva
  la clave en el subject, así que solo se concede cuando el acceso ya cubre el bucket
  completo; y un watcher ve todo el bucket, por eso `watch` es un flag aparte.

---

## 5. Topología de cuentas

```
operator gestion
├── SYS
├── GESTION        cuenta APP  — acá aterrizan TODAS las conexiones. JetStream + KV.
└── GESTION_AUTH   cuenta AUTH — el callout y sus dos sentinelas.
```

**Una sola cuenta APP para personas y servicios.** El aislamiento entre ellos lo dan los
permisos de subject, que aplica el servidor. Separarlos en dos cuentas agregaría una frontera
que habría que perforar con export/import para **cada** endpoint y **cada** bucket que
compartan — y en gestión comparten casi todo, porque el BFF atiende a las personas. Una sola
cuenta también deja los buckets en un namespace único, que es lo que permite que una persona
y un servicio tengan permisos **distintos sobre el mismo bucket**.

### Las dos sentinelas — el detalle que más se paga si se hace mal

En modo operator, si el user con el que conecta un cliente es el **mismo** que está declarado
en `--auth-user`, NATS lo autoriza directo y **el callout nunca se dispara**: el cliente se
queda con los permisos plenos de ese user. Por eso hacen falta dos:

| Sentinela | En `--auth-user` | Quién lo usa |
|---|---|---|
| `sentinel-handler` | **sí** → bypasea el callout | el propio callout (no puede autorizarse a sí mismo) |
| `sentinel-client` | **no** → dispara el callout | los clientes. Deny-all de lo suyo: el único acceso viene del User JWT. |

`sentinel-client` es **seguro de distribuir**: por sí solo no autoriza nada.

### Las dos signing keys

También son distintas, y confundirlas es el otro error clásico:

| Clave | Firma | Para qué |
|---|---|---|
| signing key de `GESTION` (APP) | el **User JWT** | define en qué cuenta aterriza el usuario (`IssuerAccount`) |
| signing key de `GESTION_AUTH` | el **authorization_response** | es el issuer del callout que el servidor tiene configurado |

Los requests van **encriptados con XKey** (curve25519): sin eso, el access token del cliente
viajaría en claro por `$SYS.REQ.USER.AUTH`.

---

## 6. Levantarlo

Requisitos: **Go 1.26+**, y `nsc` + `nats-server` en el PATH.

```sh
go install github.com/nats-io/nsc/v2@latest
go install github.com/nats-io/nats-server/v2@latest
```

```sh
make bootstrap    # genera operator, cuentas, sentinelas, XKey, authcallout y el resolver
make run          # levanta NATS + el callout en foreground
make test         # unitarios (incluye validar el config desplegable)
make              # lista todos los targets
```

El bootstrap es **idempotente**: si ya hay identidad en `nats/out/`, la reusa. Regenerarla
rompe la confianza del servidor y obliga a reemitir todas las creds (`make clean-identity`).

### Probarlo a mano

El modo por defecto es `mock`: un IdP en proceso que decodifica la identidad del texto del
token, sin secretos ni red. El formato es `mock:<sub>:<username>:<roles>`.

El modo por defecto es `mock`: un IdP en proceso que decodifica la identidad del texto del
token, sin secretos ni red. El formato es `mock:<sub>:<username>:<roles>`.

```sh
NATS="nats --server nats://127.0.0.1:4322 --creds nats/out/sentinel-client.creds"
S=$(go run ./cmd/session zit-ana dev | awk '/^session/{print $2}')
U="$NATS --token mock:zit-ana:ana@grava.io:poc-user --inbox-prefix _INBOX.$S"

# Bajo su propia sesión y un método habilitado: OK
$U pub "dev.$S.demo.ping" hola

# Método solo de poc-admin: Permissions Violation
$U pub "dev.$S.demo.admin_reset" x

# Sesión de otro: Permissions Violation
$U pub "dev.otro.demo.ping" x

# KV acotado por usuario (el bucket lo crea antes el service user poc-service)
$U kv put poc-kv "$S.theme" dark      # OK
$U kv put poc-kv "otro.theme" x       # falla
```

> **Para lo que debe fallar, usá `pub` y no `request`.** Una publicación denegada se reporta de
> forma **asíncrona**: `nats request` la manda, no recibe respuesta y **sale con 0 sin imprimir
> nada** — parece que funcionó. `nats pub` sí muestra `permissions violation` en el momento.
>
> Y **una violación sobre un subject de JetStream nunca se ve como violación**: el request se
> queda sin respuesta y el cliente reporta un timeout. Cuando algo de KV "no responde", el
> subject exacto que falta está en el log del `nats-server` como `Publish Violation`.

### Contra Zitadel real

Runbook completo, con lo que hay que crear en Zitadel y la matriz de pruebas:
**[docs/prueba-zitadel.md](docs/prueba-zitadel.md)**. En resumen:

```sh
GESTION_IDP_MODE=zitadel
GESTION_ZITADEL_ISSUER_URL=https://id.grava.io
GESTION_ZITADEL_PROJECT_ID=<projectId>          # recomendado
```

```sh
make test-live    # verifica discovery + JWKS antes de levantar nada
```

El callout loguea el modo en la primera línea: **verificá que diga `idp=zitadel`**, no
`idp=mock`.

Tres cosas que hacen fallar la autenticación y no son obvias:

- **El token tiene que ser JWT.** En Zitadel, un machine user con *Access Token Type: Bearer*
  emite un token **opaco**; el callout valida por firma y lo rechaza. Se cambia a **JWT** en el
  service user. `scripts/token-info.sh` lo detecta y lo dice.
- **El token tiene que traer los roles.** Los flujos machine-to-machine solo incluyen la claim
  de roles si se pide el scope `urn:zitadel:iam:org:projects:roles` — el genérico, no el de un
  proyecto puntual. `scripts/zitadel-token.sh` ya lo manda.
- **El JWKS de una instancia self-hosted no está donde el de Cloud.** `id.grava.io` lo sirve en
  `/oauth/v2/keys`, no en `/.well-known/jwks.json`. El callout lo resuelve por OIDC discovery,
  así que funciona con las dos.

`GESTION_ZITADEL_PROJECT_ID` acota la lectura de roles a un proyecto; sin él se leen los de
todos los proyectos del token, y un rol homónimo de otro proyecto podría matchear una regla.

> Si relanzás el stack, **matá primero el anterior**. `make run` solo detiene el
> `nats-server` que arrancó él. Si queda un callout viejo vivo, el `nats-server` nuevo no
> puede bindear el puerto y muere, mientras el callout viejo sigue atendiendo el subject en
> su modo anterior. El síntoma es desconcertante: cambiás la config y no pasa nada.

---

## 7. Qué hay en cada lugar

```
cmd/callout               el binario
cmd/session               deriva sesión e inbox de un `sub` o de un token
internal/authz            el motor de permisos: routing por rol, plantillas, KV, identidad
internal/idp              verificación del token (Zitadel por JWKS; mock para dev/CI)
internal/callout          el protocolo de auth callout (XKey, JWTs, firma)
internal/config           entorno → Config
config/                   rules.yaml + las plantillas (se montan por path)
nats/                     bootstrap.sh, nats-server.conf, .env.example
scripts/run.sh            make run
scripts/zitadel-token.sh  access token de un service user (key JSON o client secret)
scripts/token-info.sh     qué trae un token y por qué el callout lo rechazaría
docs/prueba-zitadel.md    runbook de la prueba contra Zitadel real
```

La configuración se parte en dos fuentes a propósito: **`nats/.env`** lleva lo que decide una
persona, y **`nats/out/callout-env.sh`** —que genera el bootstrap— expone las seeds, creds y
pubkeys. Así las claves nunca se escriben a mano y regenerar la identidad no obliga a editar
configuración.

---

## 8. Agregar un rol o un servicio

1. Crear la plantilla en `config/templates/`.
2. Agregar la regla en `config/rules.yaml`. **El orden importa** (first-match-wins): lo más
   restrictivo arriba, y el `"*"` al final si querés un catch-all (la PoC no tiene).
3. `make test` — valida que la plantilla cargue, que expanda sin placeholders sueltos, que el
   routing elija la que corresponde, y que todo bucket siga teniendo exactamente un
   administrador.
4. Asignar el rol en Zitadel. Para un service user: machine user + su key JSON + el rol sobre
   el proyecto.

No hace falta recompilar ni reiniciar nada más que el callout.

---

## 9. Estado

**Prueba de concepto funcionando.** Verificado end-to-end contra un `nats-server` real (modo
mock, con la config de `config/`) — los 16 casos del runbook:

- **mensajes:** `poc-user` alcanza solo sus métodos; `poc-admin` alcanza todos; ninguno puede
  publicar bajo la sesión de otro, ni cruzar de instancia, ni suscribirse como si fuera el
  servicio;
- **KV, mismo bucket y alcances distintos por rol:** `poc-user` solo su propia clave;
  `poc-admin` lee todas y escribe solo la suya; el service user lo crea y lo opera;
- **rechazos:** sin token, con token mal formado, o con un rol que no está en `rules.yaml`
  (no hay catch-all) → `Authorization Violation`.

También verificado contra **Zitadel real** (`id.grava.io`): el discovery resuelve el JWKS en
`/oauth/v2/keys` y un token inválido se rechaza como tal (`make test-live`).

**Lo que falta:** correr el runbook completo contra `id.grava.io` con los service users dados
de alta (ver [docs/prueba-zitadel.md](docs/prueba-zitadel.md)); definir los subjects reales de
gestión cuando exista el contrato del BFF; automatizar el runbook en `test/e2e/`; el Dockerfile
y el compose; y cache de tokens verificados si el volumen de conexiones lo justifica (hoy la
firma se valida localmente, que es barato, pero el enriquecimiento de username por `userinfo`
sí es una llamada HTTP por conexión de service user).
