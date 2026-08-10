// Package callout implements the NATS auth callout protocol.
//
// The exchange, end to end:
//
//  1. The client connects with the sentinel-client creds (which grant no permissions of
//     their own) and passes its Zitadel access token in the CONNECT Token field.
//  2. Because the sentinel-client is NOT declared in --auth-user, the server does not
//     authorize it by itself: it publishes a request on $SYS.REQ.USER.AUTH of the AUTH
//     account.
//  3. This service handles it: it decrypts (XKey), decodes the authorization_request,
//     validates the token against Zitadel, routes role -> template, and expands the
//     permissions.
//  4. It answers with an authorization_response containing a freshly signed User JWT, signed
//     with the APP account's signing key, carrying those permissions and the token's expiry.
//  5. The server accepts the connection with exactly those permissions.
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

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// AuthSubject is the subject where the NATS server publishes auth callout requests. It is
// served inside the AUTH account, with the sentinel-handler creds.
const AuthSubject = "$SYS.REQ.USER.AUTH"

// ServerXKeyHeader is the header carrying the server's ephemeral public XKey. Its presence
// signals that the request is encrypted and that the response must be encrypted toward it.
const ServerXKeyHeader = "Nats-Server-Xkey"

// maxUserJWTTTL bounds the User JWT's lifetime when the token declares no `exp`. Without
// this, a token with no expiry would produce an eternal NATS session.
const maxUserJWTTTL = time.Hour

// verifyTimeout bounds token validation (JWKS + eventual userinfo).
const verifyTimeout = 10 * time.Second

// Service handles the auth callout requests of an AUTH account.
type Service struct {
	nc       *nats.Conn
	verifier idp.Verifier
	router   *authz.Router
	log      *zerolog.Logger

	// signingKey signs the User JWT. It is a signing key of the APP account: it is what makes
	// the user land in that account.
	signingKey nkeys.KeyPair
	// issuerAccount is the APP account's public key. It goes into the User JWT's
	// IssuerAccount claim, which is how the server knows which account a JWT signed with a
	// signing key rather than the account key belongs to.
	issuerAccount string
	// responseSigner signs the authorization_response. It is a signing key of the AUTH
	// account — the one the server has configured as the callout's issuer. It is a DIFFERENT
	// key from signingKey: one vouches for the response, the other creates the user.
	responseSigner nkeys.KeyPair
	// xkey is the callout's curve25519 pair. It decrypts requests and encrypts responses. Its
	// public half is the one passed to `nsc edit authcallout --curve`.
	xkey nkeys.KeyPair

	sub *nats.Subscription
}

// Config holds the Service's dependencies.
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

// New builds the service. It validates the dependencies up front: otherwise each of these
// omissions would produce a per-request failure rather than a startup one.
func New(cfg Config) (*Service, error) {
	switch {
	case cfg.Conn == nil:
		return nil, errors.New("callout: missing the NATS connection")
	case cfg.Verifier == nil:
		return nil, errors.New("callout: missing the token verifier")
	case cfg.Router == nil:
		return nil, errors.New("callout: missing the permission router")
	case cfg.SigningKey == nil:
		return nil, errors.New("callout: missing the APP account signing key")
	case cfg.IssuerAccount == "":
		return nil, errors.New("callout: missing the APP account public key (issuer account)")
	case cfg.ResponseSigner == nil:
		return nil, errors.New("callout: missing the AUTH account signing key (response signer)")
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

// Start subscribes to the auth callout subject and begins serving.
func (s *Service) Start() error {
	sub, err := s.nc.Subscribe(AuthSubject, s.handle)
	if err != nil {
		return fmt.Errorf("callout: subscribe to %s: %w", AuthSubject, err)
	}
	s.sub = sub
	s.log.Info().Str("subject", AuthSubject).Msg("auth callout listening")
	return nil
}

// Stop unsubscribes the service.
func (s *Service) Stop() error {
	if s.sub == nil {
		return nil
	}
	if err := s.sub.Unsubscribe(); err != nil {
		return fmt.Errorf("callout: unsubscribe: %w", err)
	}
	s.sub = nil
	return nil
}

// handle processes an auth callout request.
//
// On any failure it answers with an authorization_response CARRYING an error; a request is
// never left unanswered: the server would wait until its timeout and the client would receive
// a generic error instead of the real reason.
func (s *Service) handle(msg *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()

	// The serverXKey is needed both to decrypt the request and to encrypt the response, so it
	// is resolved once, before anything else.
	serverXKey := ""
	if msg.Header != nil {
		serverXKey = msg.Header.Get(ServerXKeyHeader)
	}

	data, err := s.decrypt(msg.Data, serverXKey)
	if err != nil {
		// Without being able to decrypt there is no UserNkey or ServerID to put in the
		// response: it answers with empty fields so that at least the server does not wait.
		s.log.Error().Err(err).Msg("decrypting the callout request failed")
		s.respondError(msg, serverXKey, "", "", err)
		return
	}

	req, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		s.log.Error().Err(err).Msg("invalid authorization_request")
		s.respondError(msg, serverXKey, "", "", err)
		return
	}

	clientIP := req.ClientInformation.Host

	// The token travels in Token or in Password depending on how the client connects:
	// nats.Token() uses the former, nats.UserInfo() the latter. Both are accepted.
	token := req.ConnectOptions.Token
	if token == "" {
		token = req.ConnectOptions.Password
	}
	if token == "" {
		s.log.Warn().Str("clientIp", clientIP).Msg("connection without a token")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, errors.New("missing access token"))
		return
	}

	claims, err := s.verifier.VerifyToken(ctx, token)
	if err != nil {
		// The token is never logged.
		s.log.Warn().Err(err).Str("clientIp", clientIP).Msg("token verification failed")
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
			Msg("could not resolve permissions")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, err)
		return
	}

	userJWT, err := s.mintUserJWT(req.UserNkey, identity, perms, claims.ExpiresAt)
	if err != nil {
		s.log.Error().Err(err).Str("sub", claims.Subject).Msg("signing the User JWT failed")
		s.respondError(msg, serverXKey, req.UserNkey, req.Server.ID, err)
		return
	}

	if err := s.respondJWT(msg, serverXKey, req.UserNkey, req.Server.ID, userJWT); err != nil {
		s.log.Error().Err(err).Msg("sending the callout response failed")
		return
	}

	// The log has to make clear WHY this connection received these permissions:
	//   roles      what the token carried
	//   matchedBy  the winning role (with several roles, the log is ambiguous without it)
	//   identity   the identity MODEL the rule applied (person/service), which is NOT the
	//              class of user in Zitadel: a machine user with a role declared
	//              `type: person` shows up as person, and that is correct.
	s.log.Info().
		Str("sub", claims.Subject).
		Str("username", identity.Username).
		Strs("roles", claims.Roles).
		Str("matchedBy", decision.Rule).
		Str("identity", string(decision.IdentityModel)).
		// userId is the `sub`, so it is not repeated. The hash is logged because it is the
		// client's inbox prefix and cannot be eyeballed from the rest of the log.
		Str("inboxHash", authz.HashUserID(identity.UserID)).
		Str("template", decision.Template).
		Int("pubAllow", len(perms.PubAllow)).
		Int("subAllow", len(perms.SubAllow)).
		Str("clientIp", clientIP).
		Msg("authenticated")
}

// mintUserJWT assembles and signs the User JWT with the already-expanded permissions.
func (s *Service) mintUserJWT(
	userNkey string,
	identity authz.Identity,
	perms *authz.Permissions,
	tokenExpiry time.Time,
) (string, error) {
	// The User JWT's Subject has to be the nkey the client presented: it is how the server
	// ties the issued JWT to that specific connection.
	claims := jwt.NewUserClaims(userNkey)
	if claims == nil {
		return "", errors.New("callout: jwt.NewUserClaims returned nil")
	}

	claims.Name = identity.Username
	if claims.Name == "" {
		// With no human-readable name what remains is the user id, which is the token's `sub`:
		// less pretty in `nats server report connections`, but it identifies just as well.
		claims.Name = identity.UserID
	}
	// IssuerAccount is mandatory when signing with a signing key: without it the server
	// cannot know which account the user belongs to.
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

	// The NATS session must not outlive the token that authorized it.
	if !tokenExpiry.IsZero() {
		claims.Expires = tokenExpiry.Unix()
	} else {
		claims.Expires = time.Now().Add(maxUserJWTTTL).Unix()
	}

	userJWT, err := claims.Encode(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("callout: sign User JWT: %w", err)
	}
	return userJWT, nil
}

// respondJWT answers with the minted User JWT.
func (s *Service) respondJWT(msg *nats.Msg, serverXKey, userNkey, serverID, userJWT string) error {
	resp := jwt.NewAuthorizationResponseClaims(userNkey)
	if resp == nil {
		return errors.New("callout: jwt.NewAuthorizationResponseClaims returned nil")
	}
	resp.Audience = serverID
	resp.Jwt = userJWT
	return s.encodeAndSend(msg, serverXKey, resp)
}

// respondError answers with the reason for the rejection. The server propagates it to the
// client, so the message reaches whoever tried to connect: it is useful for diagnosis, and
// for that reason it must not carry anything sensitive.
func (s *Service) respondError(msg *nats.Msg, serverXKey, userNkey, serverID string, cause error) {
	resp := jwt.NewAuthorizationResponseClaims(userNkey)
	if resp == nil {
		s.log.Error().Str("userNkey", userNkey).Msg("could not assemble the error response")
		return
	}
	resp.Audience = serverID
	resp.Error = cause.Error()
	if err := s.encodeAndSend(msg, serverXKey, resp); err != nil {
		s.log.Error().Err(err).Msg("sending the error response failed")
	}
}

// encodeAndSend signs the response with the AUTH account's signing key, encrypts it if there
// is an XKey, and publishes it to the request's reply subject.
func (s *Service) encodeAndSend(msg *nats.Msg, serverXKey string, resp *jwt.AuthorizationResponseClaims) error {
	encoded, err := resp.Encode(s.responseSigner)
	if err != nil {
		return fmt.Errorf("callout: sign authorization_response: %w", err)
	}

	payload, err := s.encrypt([]byte(encoded), serverXKey)
	if err != nil {
		return err
	}

	if err := msg.Respond(payload); err != nil {
		return fmt.Errorf("callout: respond: %w", err)
	}
	return nil
}

// decrypt opens the request if it arrived encrypted with an XKey.
//
// If the callout has an XKey configured, the server MUST send its own: a request without the
// header means the server does not have the callout configured with --curve. It is rejected
// rather than processed in the clear — accepting it would let through a request that anyone
// with access to the subject could have forged.
func (s *Service) decrypt(data []byte, serverXKey string) ([]byte, error) {
	if s.xkey == nil {
		return data, nil
	}
	if serverXKey == "" {
		return nil, fmt.Errorf("callout: the callout has an XKey but the request carries no %s header", ServerXKeyHeader)
	}
	opened, err := s.xkey.Open(data, serverXKey)
	if err != nil {
		return nil, fmt.Errorf("callout: decrypt with XKey: %w", err)
	}
	return opened, nil
}

// encrypt seals the response toward the server's XKey when encryption is enabled.
func (s *Service) encrypt(data []byte, serverXKey string) ([]byte, error) {
	if s.xkey == nil || serverXKey == "" {
		return data, nil
	}
	sealed, err := s.xkey.Seal(data, serverXKey)
	if err != nil {
		return nil, fmt.Errorf("callout: encrypt with XKey: %w", err)
	}
	return sealed, nil
}
