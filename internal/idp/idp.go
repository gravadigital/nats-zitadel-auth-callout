// Package idp verifica el access token que el cliente presenta al conectar y extrae de
// él lo único que el callout necesita: quién es (sub), cómo se llama, cuándo expira y
// qué roles tiene.
//
// El callout NO emite tokens ni habla el flujo OIDC: eso ya pasó entre el cliente y
// Zitadel. Acá solo se valida un token ya emitido.
package idp

import (
	"context"
	"errors"
	"time"
)

// Errores de verificación. El callout los traduce a un AuthorizationResponse con error;
// el cliente ve un fallo de autorización al conectar.
var (
	// ErrInvalidToken indica un token que no verifica (firma, formato, issuer, audiencia).
	ErrInvalidToken = errors.New("idp: token inválido")
	// ErrExpiredToken indica un token bien formado pero vencido.
	ErrExpiredToken = errors.New("idp: token expirado")
	// ErrNoSubject indica un token sin `sub`. Sin sub no hay identidad que derivar.
	ErrNoSubject = errors.New("idp: el token no trae `sub`")
)

// Claims es lo que el callout extrae del token, ya normalizado.
type Claims struct {
	// Subject es el `sub`: el userId de Zitadel. Identifica al usuario o al service user.
	Subject string
	// Username es el nombre legible (`preferred_username`, o el que devuelva userinfo).
	// Puede venir vacío: los tokens de machine user a menudo no lo traen.
	Username string
	// Roles son los roles de proyecto del token, ya aplanados a una lista de nombres.
	Roles []string
	// ExpiresAt es el `exp`. Acota la vigencia del User JWT que mintea el callout, para
	// que la sesión NATS no sobreviva al token que la autorizó.
	ExpiresAt time.Time
}

// Verifier verifica un access token. Está como interfaz para que el callout no dependa
// de Zitadel: en tests y en CI se usa una implementación de mentira (ver aidpmock) sin
// levantar un IdP.
type Verifier interface {
	// VerifyToken valida el token y devuelve sus claims normalizadas.
	VerifyToken(ctx context.Context, token string) (*Claims, error)
}
