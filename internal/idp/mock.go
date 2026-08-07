package idp

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// mockTokenPrefix marca los tokens que acepta el IdP de mentira.
const mockTokenPrefix = "mock:"

// mockTokenTTL es la vigencia que se le atribuye a un token mock.
const mockTokenTTL = time.Hour

// Mock es un Verifier en proceso para desarrollo y CI. Decodifica la identidad del texto
// del token en vez de verificar una firma, así que el stack completo (NATS + callout +
// clientes) se puede levantar y probar sin secretos ni red.
//
// El formato del token es:
//
//	mock:<sub>:<username>:<rol1,rol2,...>
//
// Ejemplos:
//
//	mock:u-ana:ana@grava.io:admin
//	mock:svc-api:api:svc-api
//
// NUNCA usar en producción: acepta cualquier identidad que se le escriba. El binario solo
// lo instancia con GESTION_IDP_MODE=mock y loguea el modo al arrancar, para que un deploy
// mal configurado se note en la primera línea del log.
type Mock struct{}

// NewMock construye el IdP de mentira.
func NewMock() *Mock { return &Mock{} }

// VerifyToken parsea un token mock.
func (m *Mock) VerifyToken(_ context.Context, token string) (*Claims, error) {
	if !strings.HasPrefix(token, mockTokenPrefix) {
		return nil, fmt.Errorf("%w: un token mock tiene que empezar con %q", ErrInvalidToken, mockTokenPrefix)
	}

	// SplitN con 3 deja los roles enteros en el último campo, aunque lleven comas.
	parts := strings.SplitN(strings.TrimPrefix(token, mockTokenPrefix), ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: formato mock esperado mock:<sub>:<username>:<roles>", ErrInvalidToken)
	}

	subject := strings.TrimSpace(parts[0])
	if subject == "" {
		return nil, ErrNoSubject
	}

	var roles []string
	for _, role := range strings.Split(parts[2], ",") {
		if trimmed := strings.TrimSpace(role); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}

	return &Claims{
		Subject:   subject,
		Username:  strings.TrimSpace(parts[1]),
		Roles:     roles,
		ExpiresAt: time.Now().Add(mockTokenTTL),
	}, nil
}

// Compile-time check.
var _ Verifier = (*Mock)(nil)
