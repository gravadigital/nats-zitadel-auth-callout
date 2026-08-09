# Prueba de concepto: NATS local + Zitadel de producción (`id.grava.io`)

Runbook para validar el auth-callout contra Zitadel real. NATS corre local; la identidad
sale de `id.grava.io`.

**Qué se valida:** que el rol del token y el tipo de usuario cambien los permisos que se
mintean, tanto para **mensajes** como para **KV**. Los subjects son de ejemplo (un servicio
`demo` con tres métodos): lo que se prueba es el mecanismo, no el dominio de gestión.

---

## 1. Qué crear en Zitadel

### 1.1 Un proyecto

Podés reusar uno existente. Anotá su **Resource Id** (numérico, p. ej.
`379892408592106248`): es el `GESTION_ZITADEL_PROJECT_ID`.

### 1.2 Tres roles en ese proyecto

*Project → Roles → New.* El **Key** es lo que viaja en el token y lo que matchea
`config/rules.yaml`, así que tiene que ser exacto:

| Key | Para qué |
|---|---|
| `poc-user` | persona con permisos acotados |
| `poc-admin` | persona con permisos amplios |
| `poc-service` | el service user que atiende `demo` |

### 1.3 Tres service users

*Users → Service Users → New*, uno por rol:

| User Name | Rol que se le concede |
|---|---|
| `poc_user` | `poc-user` |
| `poc_admin` | `poc-admin` |
| `poc_demo` | `poc-service` |

> **Access Token Type = JWT** en cada uno. Es el campo del formulario del service user, y
> por defecto viene en **Bearer**, que emite un token **opaco**. El callout valida por
> firma (JWKS), así que con un token opaco no tiene nada que verificar y lo rechaza como
> inválido. Es el error más fácil de cometer acá; `scripts/token-info.sh` lo detecta y lo
> dice con esas palabras.

Que sean tres *machine users* —y no un humano y dos servicios— es a propósito: **el callout
rutea solo por rol**, no por la clase de usuario de Zitadel. Un machine user con rol
`poc-user` entra por el camino de persona y recibe identidad de persona. Eso permite probar
los tres caminos sin depender de un login de browser. En §5 está cómo usar un token humano
real si querés ejercitar también ese flujo.

### 1.4 Credenciales de cada service user

Cualquiera de las dos formas; el script las detecta sola:

- **Client secret** (más rápido): *Secrets → Generate Client Secret*. Guardá a mano un JSON
  con lo que te muestra:
  ```json
  { "clientId": "...", "clientSecret": "..." }
  ```
- **Key JSON** (el camino verificado en el POC): *Keys → New → Type: JSON*. Descarga
  directa de `{type, keyId, key, userId}`. Necesita `openssl`.

### 1.5 Las autorizaciones

*Project → Authorizations* (o *User → Authorizations*): conceder a cada service user **su**
rol en el proyecto. Sin esto el token sale sin roles y el callout rechaza la conexión.

> Si el proyecto vive en **otra organización** que los usuarios, el rol además tiene que
> estar habilitado en el **project-grant** hacia la org de los usuarios.

---

## 2. Preparar el entorno

```sh
cd auth-callout

# Las credenciales que bajaste de Zitadel (secrets/ está gitignored).
mkdir -p secrets
# -> secrets/poc-user.json  secrets/poc-admin.json  secrets/poc-service.json
```

```sh
# Configurar el callout contra Zitadel real.
cp -n nats/.env.example nats/.env
cat >> nats/.env <<'EOF'

GESTION_IDP_MODE=zitadel
GESTION_ZITADEL_ISSUER_URL=https://id.grava.io
GESTION_ZITADEL_PROJECT_ID=PONER_EL_PROJECT_ID
EOF
```

Verificá que la conexión con Zitadel funcione **antes** de levantar nada:

```sh
GESTION_ZITADEL_ISSUER_URL=https://id.grava.io make test-live
```

Tiene que decir `discovery OK — issuer=https://id.grava.io jwks=https://id.grava.io/oauth/v2/keys`.
(`id.grava.io` es self-hosted y sirve las claves en `/oauth/v2/keys`, no en el path de
Zitadel Cloud; el callout lo resuelve por OIDC discovery.)

---

## 3. Levantar NATS + el callout

```sh
make bootstrap     # genera operator, cuentas, sentinelas, XKey y la config de authcallout
make run           # NATS + callout en foreground; dejalo corriendo
```

La **primera línea del log tiene que decir `idp=zitadel`**:

```
INF iniciando auth-callout de gestión idp=zitadel instance=dev nats=nats://127.0.0.1:4322
```

Si dice `idp=mock`, no tomó la config. Y si relanzás, **matá primero lo anterior**: `make
run` solo detiene el `nats-server` que arrancó él, así que un callout viejo puede seguir
atendiendo el subject en su modo anterior mientras el `nats-server` nuevo no puede bindear
el puerto.

---

## 4. Los tokens

En **otra terminal**:

```sh
cd auth-callout
export ZITADEL_ISSUER_URL=https://id.grava.io
export ZITADEL_PROJECT_ID=PONER_EL_PROJECT_ID

T_USER=$(./scripts/zitadel-token.sh secrets/poc-user.json)
T_ADMIN=$(./scripts/zitadel-token.sh secrets/poc-admin.json)
T_DEMO=$(./scripts/zitadel-token.sh secrets/poc-service.json)
```

**Revisalos antes de tocar NATS.** Casi cualquier fallo de la prueba se explica acá:

```sh
./scripts/token-info.sh "$T_USER"
```

Tiene que decir `Es un JWT. ✓` y listar la claim de roles con `poc-user`. Si no:

| Síntoma | Causa | Arreglo |
|---|---|---|
| `NO es un JWT` | el service user está en Bearer | Access Token Type = JWT |
| `Claims de roles presentes: NINGUNA` | falta el scope o el grant | ver §1.5; el scope ya lo manda el script |
| rol distinto al esperado | credencial del service user equivocado | revisar qué JSON usaste |

Las identidades que va a derivar el callout. Son **dos valores por usuario**, y no son
intercambiables: el **user id crudo** arma los subjects, y su **hash** arma el inbox.

```sh
# user id crudo -> subjects
S_USER=$(go run ./cmd/session --token "$T_USER"  | awk '/^user-id/{print $2}')
S_ADMIN=$(go run ./cmd/session --token "$T_ADMIN" | awk '/^user-id/{print $2}')

# hash del user id -> inbox
H_USER=$(go run ./cmd/session --token "$T_USER"  | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')
H_ADMIN=$(go run ./cmd/session --token "$T_ADMIN" | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')

echo "user=$S_USER ($H_USER)  admin=$S_ADMIN ($H_ADMIN)"
```

El service user `poc_demo` también tiene user id propio y su inbox también va por hash — es
un usuario de Zitadel como cualquier otro. Lo que lo distingue es el **endpoint** que atiende
(`demo`), que sale de la regla y no del token:

```sh
S_DEMO=$(go run ./cmd/session --token "$T_DEMO" | awk '/^user-id/{print $2}')
H_DEMO=$(go run ./cmd/session --token "$T_DEMO" | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')
```

---

## 5. La prueba

```sh
NATS="nats --server nats://127.0.0.1:4322 --creds nats/out/sentinel-client.creds"
```

> **El `--inbox-prefix` no es opcional.** Los permisos acotan el inbox a
> `_INBOX.<hash(user-id)>`; por defecto el cliente genera un `_INBOX.<aleatorio>` que nadie
> autoriza. Ojo: el inbox va con el **hash**, no con el user id crudo que llevan los
> subjects. En una app real se fija con `nats.CustomInboxPrefix` (Go) o `inboxPrefix`
> (nats.js).

### 5.1 El servicio `demo` atiende y crea el bucket

Dejalo corriendo en una terminal aparte — es quien responde los requests. Atiende por su
**endpoint** (`demo`), pero su inbox va por el hash de **su** user id:

```sh
$NATS --token "$T_DEMO" --inbox-prefix "_INBOX.$H_DEMO" \
  reply 'dev.*.demo.>' 'respuesta de demo a {{Subject}}'
```

Y en otra, que cree el bucket de la prueba (es el único con `manage: true`):

```sh
$NATS --token "$T_DEMO" --inbox-prefix "_INBOX.$H_DEMO" kv add poc-kv --history=1
```

### 5.2 Mensajes: los permisos cambian por rol

```sh
U="$NATS --token $T_USER  --inbox-prefix _INBOX.$H_USER"
A="$NATS --token $T_ADMIN --inbox-prefix _INBOX.$H_ADMIN"
```

| # | Comando | Esperado |
|---|---|---|
| 1 | `$U request "dev.$S_USER.demo.ping" hola` | **responde** |
| 2 | `$U pub "dev.$S_USER.demo.admin_reset" x` | **Permissions Violation** (solo admin) |
| 3 | `$A request "dev.$S_ADMIN.demo.admin_reset" x` | **responde** |
| 4 | `$U pub "dev.$S_ADMIN.demo.ping" x` | **Permissions Violation** (user id ajeno) |
| 5 | `$U pub "prod.$S_USER.demo.ping" x` | **Permissions Violation** (otra instancia) |
| 6 | `$U sub "dev.*.demo.>"` | **Permissions Violation** (no es un servicio) |

1 y 3 prueban que el rol amplía la superficie. 2 es el corazón de "permisos variables por
rol": mismo servicio, mismo cliente, método denegado por el rol. 4 es lo que hace confiable
la identidad del subject. 6 es que una persona no puede hacerse pasar por el servicio.

> **Para los casos que deben fallar, usá `pub` y no `request`.** Una publicación denegada se
> reporta de forma **asíncrona**: `nats request` la manda, no recibe respuesta y **sale con
> código 0 sin imprimir nada** — parece que funcionó. `nats pub` sí muestra
> `permissions violation` en el momento. Verificado: con `request`, el caso 2 pasa
> desapercibido; con `pub`, dice
> `Permissions Violation for Publish to "dev.<user-id>.demo.admin_reset"`.
> Ante cualquier duda, la fuente de verdad es el log del `nats-server` (§6).

### 5.3 KV: los permisos cambian por rol y por usuario

| # | Comando | Esperado |
|---|---|---|
| 7 | `$U kv put poc-kv "$S_USER.theme" dark` | **ok** (su propia clave) |
| 8 | `$U kv get poc-kv "$S_USER.theme"` | **dark** |
| 9 | `$A kv put poc-kv "$S_ADMIN.theme" light` | **ok** |
| 10 | `$U kv get poc-kv "$S_ADMIN.theme"` | **falla** (clave de otro) |
| 11 | `$U kv put poc-kv "$S_ADMIN.theme" hackeado` | **falla** (clave de otro) |
| 12 | `$A kv get poc-kv "$S_USER.theme"` | **dark** (el admin lee todo) |
| 13 | `$A kv put poc-kv "$S_USER.theme" impuesto` | **falla** (escribe solo lo suyo) |

10–13 son el punto: **el mismo bucket, con alcances distintos según el rol**, y el scoping
por usuario dentro del rol. Lo aplica el servidor NATS, no la aplicación — el alcance entra
en el subject de la clave (`$KV.poc-kv.<user-id>.…`).

### 5.4 Rechazos

| # | Comando | Esperado |
|---|---|---|
| 14 | `$NATS pub "dev.x.demo.ping" x` | **Authorization Violation** (sin token) |
| 15 | `$NATS --token "basura" pub "dev.x.demo.ping" x` | **Authorization Violation** |
| 16 | token de un usuario **sin** rol de la PoC | **Authorization Violation** |

Para 16, un service user con cualquier otro rol de `id.grava.io` (o sin ninguno):
`config/rules.yaml` **no tiene catch-all**, así que no hay permisos por defecto.

---

## 6. Si algo falla

**Una violación de permisos sobre un subject de JetStream no se ve como tal.** El request
nunca recibe respuesta y el cliente reporta un timeout (`context deadline exceeded`). El
subject exacto que falta está en el log del `nats-server`:

```sh
# en la terminal de `make run`, o:
grep -i violation nats/data/../*.log 2>/dev/null
```

Buscá `Publish Violation` / `Subscription Violation` y el subject.

Lo que el log del **callout** dice en cada caso:

| En el log | Significa |
|---|---|
| `autenticado ... template=... pubAllow=N` | todo bien: muestra qué plantilla eligió |
| `verificación de token falló` | firma, issuer o vigencia. Corré `token-info.sh` |
| `no se pudo resolver permisos ... roles=[]` | el token no trae roles (§1.5) |
| `no se pudo resolver permisos ... roles=[otro]` | el rol no está en `rules.yaml` |

Subí el detalle con `GESTION_LOG_LEVEL=debug` en `nats/.env`.

---

## 7. Después de la prueba

```sh
make clean            # binarios y datos de JetStream
make clean-identity   # además la identidad NATS (obliga a reemitir las creds)
```

En Zitadel podés dejar los tres roles y los tres service users: son de prueba y no tocan
nada de gestión. Si el proyecto es compartido, borralos para no dejar roles sueltos.
