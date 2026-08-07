package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims de Zitadel que nos interesan.
const (
	// claimRolesAllProjects trae los roles de TODOS los proyectos a los que el token
	// tiene acceso. Es el que ya usa la api de gestión hoy.
	claimRolesAllProjects = "urn:zitadel:iam:org:project:roles"
	// claimRolesProjectFmt trae los roles de UN proyecto. Más preciso: evita que un rol
	// homónimo de otro proyecto matchee una regla. Se usa si hay ProjectID configurado.
	claimRolesProjectFmt = "urn:zitadel:iam:org:project:%s:roles"
	// claimPreferredUsername es el nombre legible del usuario.
	claimPreferredUsername = "preferred_username"
)

// jwksRefreshInterval es cada cuánto se refresca el JWKS de Zitadel en background.
// El cache también refresca on-demand ante un `kid` desconocido (rotación de claves),
// así que este intervalo es solo el piso de frescura.
const jwksRefreshInterval = 15 * time.Minute

// userinfoTimeout acota la llamada a /oidc/v1/userinfo. Es un enriquecimiento opcional:
// si tarda o falla, la autenticación sigue sin username.
const userinfoTimeout = 3 * time.Second

// Zitadel verifica access tokens de Zitadel contra su JWKS.
//
// La verificación es local (firma + claims), sin introspección: no hay un round-trip a
// Zitadel por cada conexión. La contrapartida es que un token revocado sigue siendo
// válido hasta su `exp` — aceptable porque el User JWT que se mintea expira con el token.
type Zitadel struct {
	issuer     string
	projectID  string
	cache      *jwk.Cache
	jwksURL    string
	httpClient *http.Client
	// enrichUsername pide /oidc/v1/userinfo cuando el token no trae un nombre legible.
	// Los tokens de machine user suelen no traerlo, y el nombre es lo que hace legible
	// un `nats server report connections`.
	enrichUsername bool
}

// ZitadelOption configura un Zitadel.
type ZitadelOption func(*Zitadel)

// WithProjectID acota la extracción de roles a un proyecto. Sin esto se leen los roles
// de todos los proyectos del token.
func WithProjectID(projectID string) ZitadelOption {
	return func(z *Zitadel) { z.projectID = projectID }
}

// WithUsernameEnrichment activa la consulta a userinfo cuando el token no trae nombre.
func WithUsernameEnrichment(enabled bool) ZitadelOption {
	return func(z *Zitadel) { z.enrichUsername = enabled }
}

// WithHTTPClient reemplaza el cliente HTTP (para tests o para fijar timeouts/proxy).
func WithHTTPClient(client *http.Client) ZitadelOption {
	return func(z *Zitadel) {
		if client != nil {
			z.httpClient = client
		}
	}
}

// NewZitadel construye un verificador contra la instancia de Zitadel en issuerURL.
//
// Descubre el JWKS por OIDC discovery y arranca un cache con refresco automático, así
// que una rotación de claves en Zitadel no requiere reiniciar el callout.
func NewZitadel(ctx context.Context, issuerURL string, opts ...ZitadelOption) (*Zitadel, error) {
	if issuerURL == "" {
		return nil, errors.New("idp: falta la URL del issuer de Zitadel")
	}
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	z := &Zitadel{
		issuer:         issuerURL,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		enrichUsername: true,
	}
	for _, opt := range opts {
		opt(z)
	}

	jwksURL, err := z.discoverJWKS(ctx)
	if err != nil {
		return nil, err
	}
	z.jwksURL = jwksURL

	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURL,
		jwk.WithMinRefreshInterval(jwksRefreshInterval),
		jwk.WithHTTPClient(z.httpClient),
	); err != nil {
		return nil, fmt.Errorf("idp: registrar JWKS %q: %w", jwksURL, err)
	}
	// Primer fetch al arrancar: si el JWKS no se puede leer, es mejor fallar acá que
	// rechazar todas las conexiones una vez arriba.
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("idp: leer JWKS %q: %w", jwksURL, err)
	}
	z.cache = cache

	return z, nil
}

// discoverJWKS resuelve el jwks_uri por el well-known de OpenID Connect.
func (z *Zitadel) discoverJWKS(ctx context.Context) (string, error) {
	url := z.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("idp: armar request de discovery: %w", err)
	}
	resp, err := z.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp: OIDC discovery en %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp: OIDC discovery en %q devolvió %s", url, resp.Status)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("idp: parsear discovery de %q: %w", url, err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("idp: el discovery de %q no trae jwks_uri", url)
	}
	// El issuer declarado manda: es contra ese valor que se validan los tokens, y puede
	// diferir de la URL con la que se llegó (proxies, hosts internos).
	if doc.Issuer != "" {
		z.issuer = strings.TrimSuffix(doc.Issuer, "/")
	}
	return doc.JWKSURI, nil
}

// VerifyToken valida firma, issuer y vigencia del token, y extrae las claims.
func (z *Zitadel) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	set, err := z.cache.Get(ctx, z.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("idp: obtener JWKS: %w", err)
	}

	parsed, err := jwt.ParseString(token,
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(z.issuer),
		jwt.WithValidate(true),
	)
	if err != nil {
		// jwx no expone el vencimiento como error tipado, así que se distingue por texto.
		// Importa porque un token vencido es un caso normal (el cliente debe renovar) y
		// no un intento de acceso inválido: se auditan distinto.
		if strings.Contains(err.Error(), `"exp" not satisfied`) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	subject := parsed.Subject()
	if subject == "" {
		return nil, ErrNoSubject
	}

	claims := &Claims{
		Subject:   subject,
		ExpiresAt: parsed.Expiration(),
		Roles:     extractRoles(parsed, z.projectID),
	}

	if username, ok := stringClaim(parsed, claimPreferredUsername); ok {
		claims.Username = username
	}
	if claims.Username == "" && z.enrichUsername {
		// Best-effort: el username es para legibilidad, no para autorizar.
		if username, err := z.fetchUsername(ctx, token); err == nil {
			claims.Username = username
		}
	}

	return claims, nil
}

// extractRoles aplana los roles de proyecto del token a una lista de nombres.
//
// Zitadel los emite como un objeto anidado `{ "<rol>": { "<orgId>": "<dominio>" } }`.
// El callout solo rutea por nombre de rol, así que se queda con las claves.
func extractRoles(token jwt.Token, projectID string) []string {
	claimNames := make([]string, 0, 2)
	if projectID != "" {
		claimNames = append(claimNames, fmt.Sprintf(claimRolesProjectFmt, projectID))
	}
	claimNames = append(claimNames, claimRolesAllProjects)

	for _, name := range claimNames {
		raw, ok := token.Get(name)
		if !ok {
			continue
		}
		nested, ok := raw.(map[string]any)
		if !ok || len(nested) == 0 {
			continue
		}
		roles := make([]string, 0, len(nested))
		for role := range nested {
			roles = append(roles, role)
		}
		return roles
	}
	return nil
}

// stringClaim lee una claim de tipo string.
func stringClaim(token jwt.Token, name string) (string, bool) {
	raw, ok := token.Get(name)
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	return value, ok
}

// fetchUsername pide /oidc/v1/userinfo con el token del cliente para obtener un nombre
// legible. Solo se usa cuando el token no trae `preferred_username` — el caso típico de
// un machine user.
func (z *Zitadel) fetchUsername(ctx context.Context, token string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, userinfoTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, z.issuer+"/oidc/v1/userinfo", nil)
	if err != nil {
		return "", fmt.Errorf("idp: armar request de userinfo: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp: userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp: userinfo devolvió %s", resp.Status)
	}

	var info struct {
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("idp: parsear userinfo: %w", err)
	}
	if info.PreferredUsername != "" {
		return info.PreferredUsername, nil
	}
	return info.Name, nil
}

// Compile-time check.
var _ Verifier = (*Zitadel)(nil)
