// Package callout implementa el protocolo de auth callout de NATS.
//
// El intercambio, de punta a punta:
//
//  1. El cliente conecta con las creds del sentinel-client (que no tiene permisos
//     propios) y pasa su access token de Zitadel en el campo Token de CONNECT.
//  2. Como el sentinel-client NO está declarado en --auth-user, el servidor no lo
//     autoriza por sí mismo: publica un request en $SYS.REQ.USER.AUTH de la cuenta AUTH.
//  3. Este servicio lo atiende: desencripta (XKey), decodifica el authorization_request,
//     valida el token contra Zitadel, rutea rol -> plantilla, y expande los permisos.
//  4. Responde un authorization_response que contiene un User JWT recién firmado con la
//     signing key de la cuenta APP, con esos permisos y con la expiración del token.
//  5. El servidor acepta la conexión con exactamente esos permisos.
package callout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog"

	"github.com/grava/gestion/auth-callout/internal/authz"
	"github.com/grava/gestion/auth-callout/internal/idp"
)

// AuthSubject es el subject donde el servidor NATS publica los requests de auth callout.
// Se atiende dentro de la cuenta AUTH, con las creds del sentinel-handler.
const AuthSubject = "$SYS.REQ.USER.AUTH"

// ServerXKeyHeader es el header con la XKey pública efímera del servidor. Su presencia
// indica que el request viene encriptado y que la respuesta debe encriptarse hacia ella.
const ServerXKeyHeader = "Nats-Server-Xkey"

// maxUserJWTTTL acota la vigencia del User JWT cuando el token no declara `exp`.
// Sin esto, un token sin vencimiento produciría una sesión NATS eterna.
const maxUserJWTTTL = time.Hour

// verifyTimeout acota la validación del token (JWKS + userinfo eventual).
const verifyTimeout = 10 * time.Second

// Service atiende los requests de auth callout de una cuenta AUTH.
type Service struct {
	nc       *nats.Conn
	verifier idp.Verifier
	router   *authz.Router
	log      *zerolog.Logger

	// signingKey firma el User JWT. Es una signing key de la cuenta APP: es lo que hace
	// que el usuario aterrice en esa cuenta.
	signingKey nkeys.KeyPair
	// issuerAccount es la pubkey de la cuenta APP. Va en el claim IssuerAccount del User
	// JWT, que es cómo el servidor sabe a qué cuenta pertenece un JWT firmado con una
	// signing key en vez de con la clave de cuenta.
	issuerAccount string
	// responseSigner firma el authorization_response. Es una signing key de la cuenta
	// AUTH — la que el servidor tiene configurada como issuer del callout. Es una clave
	// DISTINTA de signingKey: una acredita la respuesta, la otra crea al usuario.
	responseSigner nkeys.KeyPair
	// xkey es el par curve25519 del callout. Desencripta los requests y encripta las
	// respuestas. Su pública es la que se pasó a `nsc edit authcallout --curve`.
	xkey nkeys.KeyPair

	sub *nats.Subscription
}

// Config son las dependencias del Service.
type Config struct {
	Conn           *nats.Conn
	Verifier       idp.Verifier
	Router         *authz.Router
	Logger         *zerolog.Logger
	SigningKey     nkeys.KeyPair
	IssuerAccount  string
	ResponseSigner nkeys.KeyPair
	XKey           nkeys.KeyPair
}

// New construye el servicio. Valida las dependencias por adelantado: cada una de estas
// faltas produciría, si no, un fallo por request y no al arrancar.
func New(cfg Config) (*Service, error) {
	switch {
	case cfg.Conn == nil:
		return nil, errors.New("callout: falta la conexión NATS")
	case cfg.Verifier == nil:
		return nil, errors.New("callout: falta el verificador de tokens")
	case cfg.Router == nil:
		return nil, errors.New("callout: falta el router de permisos")
	case cfg.SigningKey == nil:
		return nil, errors.New("callout: falta la signing key de la cuenta APP")
	case cfg.IssuerAccount == "":
		return nil, errors.New("callout: falta la pubkey de la cuenta APP (issuer account)")
	case cfg.ResponseSigner == nil:
		return nil, errors.New("callout: falta la signing key de la cuenta AUTH (response signer)")
	}

	log := cfg.Logger
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &Service{
		nc:             cfg.Conn,
		verifier:       cfg.Verifier,
		router:         cfg.Router,
		log:            log,
		signingKey:     cfg.SigningKey,
		issuerAccount:  cfg.IssuerAccount,
		responseSigner: cfg.ResponseSigner,
		xkey:           cfg.XKey,
	}, nil
}

// Start se suscribe al subject de auth callout y empieza a atender.
func (s *Service) Start() error {
	sub, err := s.nc.Subscribe(AuthSubject, s.handle)
	if err != nil {
		return fmt.Errorf("callout: suscribir a %s: %w", AuthSubject, err)
	}
	s.sub = sub
	s.log.Info().Str("subject", AuthSubject).Msg("auth callout escuchando")
	return nil
}

// Stop desuscribe el servicio.
func (s *Service) Stop() error {
	if s.sub == nil {
		return nil
	}
	if err := s.sub.Unsubscribe(); err != nil {
		return fmt.Errorf("callout: desuscribir: %w", err)
	}
	s.sub = nil
	return nil
}

// handle procesa un request de auth callout.
//
// Ante cualquier fallo se responde un authorization_response CON error, nunca se deja el
// request sin respuesta: el servidor esperaría hasta el timeout y el cliente recibiría
// un error genérico en vez del motivo real.
func (s *Service) handle(msg *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()

	// El serverXKey se necesita tanto para desencriptar el request como para encriptar
	// la respuesta, así que se resuelve una sola vez, antes de todo.
	serverXKey := ""
	if msg.Header != nil {
		serverXKey = msg.Header.Get(ServerXKeyHeader)
	}

	data, err := s.decrypt(msg.Data, serverXKey)
	if err != nil {
		// Sin poder desencriptar no hay UserNkey ni ServerID que poner en la respuesta:
		// se responde con los campos vacíos para que el servidor al menos no espere.
		s.log.Error().Err(err).Msg("desencriptar el request de callout falló")
		s.respondError(msg, serverXKey, "", "", err)
		return
	}

	req, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		s.log.Error().Err(err).Msg("authorization_request inválido")
		s.respondError(msg, serverXKey, "", "", err)
		return
	}

	clientIP := req.ClientInformation.Host

	// El token viaja en Token o en Password según cómo conecte el cliente: nats.Token()
	// usa el primero, nats.UserInfo() el segundo. Se aceptan los dos.
	token := req.ConnectOptions.Token
	if token == "" {
		token = req.ConnectOptions.Password
	}
	if token == "" {
		s.log.Warn().Str("clientIp", clientIP).Msg("conexión sin token")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, errors.New("falta el access token"))
		return
	}

	claims, err := s.verifier.VerifyToken(ctx, token)
	if err != nil {
		// Nunca se loguea el token.
		s.log.Warn().Err(err).Str("clientIp", clientIP).Msg("verificación de token falló")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, err)
		return
	}

	identity, perms, decision, err := s.router.Resolve(claims.Roles, claims.Subject, claims.Username)
	if err != nil {
		s.log.Warn().
			Err(err).
			Str("sub", claims.Subject).
			Strs("roles", claims.Roles).
			Str("clientIp", clientIP).
			Msg("no se pudo resolver permisos")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, err)
		return
	}

	userJWT, err := s.mintUserJWT(req.UserNkey, identity, perms, claims.ExpiresAt)
	if err != nil {
		s.log.Error().Err(err).Str("sub", claims.Subject).Msg("firmar el User JWT falló")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, err)
		return
	}

	if err := s.respondJWT(msg, serverXKey, req.UserNkey, req.Server.ID, userJWT); err != nil {
		s.log.Error().Err(err).Msg("enviar la respuesta de callout falló")
		return
	}

	// El log tiene que dejar claro POR QUÉ esta conexión recibió estos permisos:
	//   roles      lo que traía el token
	//   matchedBy  el rol que ganó (con varios roles, sin esto el log es ambiguo)
	//   identity   el MODELO de identidad que aplicó la regla (person/service), que NO es la
	//              clase de usuario en Zitadel: un machine user con un rol declarado
	//              `type: person` aparece como person, y es correcto.
	s.log.Info().
		Str("sub", claims.Subject).
		Str("username", identity.Username).
		Strs("roles", claims.Roles).
		Str("matchedBy", decision.Rule).
		Str("identity", string(decision.IdentityModel)).
		// userId es el `sub`, así que no se repite. Se loguea el hash porque es el
		// prefijo de inbox del cliente y no se deduce a ojo del resto del log.
		Str("inboxHash", authz.HashUserID(identity.UserID)).
		Str("template", decision.Template).
		Int("pubAllow", len(perms.PubAllow)).
		Int("subAllow", len(perms.SubAllow)).
		Str("clientIp", clientIP).
		Msg("autenticado")
}

// mintUserJWT arma y firma el User JWT con los permisos ya expandidos.
func (s *Service) mintUserJWT(
	userNkey string,
	identity authz.Identity,
	perms *authz.Permissions,
	tokenExpiry time.Time,
) (string, error) {
	// El Subject del User JWT tiene que ser la nkey que presentó el cliente: es cómo el
	// servidor liga el JWT emitido a esa conexión concreta.
	claims := jwt.NewUserClaims(userNkey)
	if claims == nil {
		return "", errors.New("callout: jwt.NewUserClaims devolvió nil")
	}

	claims.Name = identity.Username
	if claims.Name == "" {
		// Sin nombre legible queda el user id, que es el `sub` del token: menos lindo en
		// `nats server report connections`, pero identifica igual.
		claims.Name = identity.UserID
	}
	// IssuerAccount es obligatorio cuando se firma con una signing key: sin él el
	// servidor no puede saber a qué cuenta pertenece el usuario.
	claims.IssuerAccount = s.issuerAccount

	claims.Pub.Allow = perms.PubAllow
	claims.Pub.Deny = perms.PubDeny
	claims.Sub.Allow = perms.SubAllow
	claims.Sub.Deny = perms.SubDeny

	if perms.RespMax > 0 {
		claims.Resp = &jwt.ResponsePermission{
			MaxMsgs: perms.RespMax,
			Expires: perms.RespTTL,
		}
	}

	// La sesión NATS no debe sobrevivir al token que la autorizó.
	if !tokenExpiry.IsZero() {
		claims.Expires = tokenExpiry.Unix()
	} else {
		claims.Expires = time.Now().Add(maxUserJWTTTL).Unix()
	}

	userJWT, err := claims.Encode(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("callout: firmar User JWT: %w", err)
	}
	return userJWT, nil
}

// respondJWT responde con el User JWT minteado.
func (s *Service) respondJWT(msg *nats.Msg, serverXKey, userNkey, serverID, userJWT string) error {
	resp := jwt.NewAuthorizationResponseClaims(userNkey)
	if resp == nil {
		return errors.New("callout: jwt.NewAuthorizationResponseClaims devolvió nil")
	}
	resp.Audience = serverID
	resp.Jwt = userJWT
	return s.encodeAndSend(msg, serverXKey, resp)
}

// respondError responde con el motivo del rechazo. El servidor lo propaga al cliente,
// así que el mensaje llega al que intentó conectar: sirve para diagnosticar, y por eso
// no debe llevar nada sensible.
func (s *Service) respondError(msg *nats.Msg, serverXKey, userNkey, serverID string, cause error) {
	resp := jwt.NewAuthorizationResponseClaims(userNkey)
	if resp == nil {
		s.log.Error().Str("userNkey", userNkey).Msg("no se pudo armar la respuesta de error")
		return
	}
	resp.Audience = serverID
	resp.Error = cause.Error()
	if err := s.encodeAndSend(msg, serverXKey, resp); err != nil {
		s.log.Error().Err(err).Msg("enviar la respuesta de error falló")
	}
}

// encodeAndSend firma la respuesta con la signing key de la cuenta AUTH, la encripta si
// hay XKey, y la publica en el reply del request.
func (s *Service) encodeAndSend(msg *nats.Msg, serverXKey string, resp *jwt.AuthorizationResponseClaims) error {
	encoded, err := resp.Encode(s.responseSigner)
	if err != nil {
		return fmt.Errorf("callout: firmar authorization_response: %w", err)
	}

	payload, err := s.encrypt([]byte(encoded), serverXKey)
	if err != nil {
		return err
	}

	if err := msg.Respond(payload); err != nil {
		return fmt.Errorf("callout: responder: %w", err)
	}
	return nil
}

// decrypt abre el request si viene encriptado con XKey.
//
// Si el callout tiene XKey configurada, el servidor DEBE mandar la suya: un request sin
// el header significa que el servidor no tiene el callout configurado con --curve. Se
// rechaza en vez de procesarlo en claro — aceptarlo dejaría pasar un request que
// cualquiera con acceso al subject podría haber falsificado.
func (s *Service) decrypt(data []byte, serverXKey string) ([]byte, error) {
	if s.xkey == nil {
		return data, nil
	}
	if serverXKey == "" {
		return nil, fmt.Errorf("callout: el callout tiene XKey pero el request no trae el header %s", ServerXKeyHeader)
	}
	opened, err := s.xkey.Open(data, serverXKey)
	if err != nil {
		return nil, fmt.Errorf("callout: desencriptar con XKey: %w", err)
	}
	return opened, nil
}

// encrypt sella la respuesta hacia la XKey del servidor cuando la encriptación está activa.
func (s *Service) encrypt(data []byte, serverXKey string) ([]byte, error) {
	if s.xkey == nil || serverXKey == "" {
		return data, nil
	}
	sealed, err := s.xkey.Seal(data, serverXKey)
	if err != nil {
		return nil, fmt.Errorf("callout: encriptar con XKey: %w", err)
	}
	return sealed, nil
}
