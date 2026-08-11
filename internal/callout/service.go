// Package callout implements the NATS auth callout protocol.
//
// The exchange, end to end:
//
//  1. The client connects with the sentinel-client credentials (which grant no permissions of
//     their own) and passes its access token in the CONNECT Token field.
//  2. Because the sentinel-client is NOT declared in --auth-user, the server does not
//     authorize it by itself: it publishes a request on $SYS.REQ.USER.AUTH of the AUTH
//     account.
//  3. This service handles it: it decrypts (XKey), decodes the authorization_request,
//     validates the token against the identity provider, routes role -> template, and expands
//     the permissions.
//  4. It answers with an authorization_response containing a freshly signed User JWT carrying
//     those permissions and the token's expiry.
//  5. The server accepts the connection with exactly those permissions.
//
// # Server modes
//
// The service works against both NATS authorization models (see Mode). The protocol above is
// identical in both; they differ only in how the minted User JWT names the account the
// connection lands in:
//
//	operator   IssuerAccount = APP account PUBKEY, signed by an APP account signing key
//	config     Audience      = target account NAME, signed by the `auth_callout.issuer` key
//
// Sending the wrong one is not a subtle failure: a config-mode server rejects any User JWT
// carrying issuer_account outright.
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

// Mode is the authorization mode of the NATS server the callout serves. It is the one thing
// about the server that cannot be inferred safely, so it is declared.
//
// The two modes differ in exactly one respect that reaches this package: HOW the User JWT
// names the account the connection lands in. Everything else — the callout protocol, the
// XKey, token verification, role routing, template expansion — is identical.
type Mode string

const (
	// ModeOperator is a server whose authorization comes from operator-signed account JWTs
	// (`nsc edit authcallout`). The User JWT is signed with an APP account signing key and
	// carries the APP account pubkey in IssuerAccount; that claim is what binds the user to
	// the account.
	ModeOperator Mode = "operator"
	// ModeConfig is a server whose authorization lives in `nats-server.conf`
	// (`authorization { auth_callout { ... } }`). There are no account JWTs, so IssuerAccount
	// does not apply — the server REJECTS a User JWT that carries it. The target account
	// travels in the Audience claim instead, as an account NAME.
	ModeConfig Mode = "config"
)

// IsValid reports whether m is a known mode.
func (m Mode) IsValid() bool {
	return m == ModeOperator || m == ModeConfig
}

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

	// mode is the server's authorization mode. It decides how the User JWT names the target
	// account.
	mode Mode

	// signingKey signs the User JWT.
	//
	// In operator mode it is a signing key of the APP account: it is what makes the user land
	// in that account. In config mode it is the key whose pubkey the server declares in
	// `auth_callout.issuer` — the server compares the User JWT's issuer against it.
	signingKey nkeys.KeyPair
	// issuerAccount is the APP account's public key, used ONLY in operator mode. It goes into
	// the User JWT's IssuerAccount claim, which is how the server knows which account a JWT
	// signed with a signing key rather than the account key belongs to.
	//
	// In config mode it MUST stay empty: the server rejects a User JWT carrying issuer_account
	// when there is no operator ("attempted to use issuer_account").
	issuerAccount string
	// targetAccount is the account NAME connections land in, used ONLY in config mode. It
	// travels in the User JWT's Audience claim, which is what the server looks up to place the
	// connection.
	targetAccount string
	// responseSigner signs the authorization_response.
	//
	// In operator mode it is a signing key of the AUTH account — a DIFFERENT key from
	// signingKey: one vouches for the response, the other creates the user.
	//
	// In config mode there is only one key, so this is the same key as signingKey. The server
	// only verifies the response's signer when the response is NOT encrypted; with an XKey
	// configured (the recommended setup) it skips that check and relies on the encryption.
	responseSigner nkeys.KeyPair
	// xkey is the callout's curve25519 pair. It decrypts requests and encrypts responses. Its
	// public half is the one passed to `nsc edit authcallout --curve`.
	xkey nkeys.KeyPair

	sub *nats.Subscription
}

// Config holds the Service's dependencies.
type Config struct {
	Conn     *nats.Conn
	Verifier idp.Verifier
	Router   *authz.Router
	Logger   *zerolog.Logger

	// Mode is the server's authorization mode. Empty defaults to ModeOperator, which keeps
	// existing deployments working unchanged.
	Mode Mode

	// SigningKey signs the User JWT. Required in both modes.
	SigningKey nkeys.KeyPair
	// IssuerAccount is the APP account pubkey. Required in operator mode, must be empty in
	// config mode.
	IssuerAccount string
	// TargetAccount is the account name connections land in. Required in config mode, must be
	// empty in operator mode.
	TargetAccount string
	// ResponseSigner signs the authorization_response. Required in operator mode; in config
	// mode it defaults to SigningKey when omitted.
	ResponseSigner nkeys.KeyPair
	XKey           nkeys.KeyPair
}

// New builds the service. It validates the dependencies up front: otherwise each of these
// omissions would produce a per-request failure rather than a startup one.
func New(cfg Config) (*Service, error) {
	mode := cfg.Mode
	if mode == "" {
		// Defaulting to operator keeps every existing deployment working without touching its
		// configuration. The mode is never inferred from which keys are present: guessing it
		// would turn a misconfiguration into a silently different authorization model.
		mode = ModeOperator
	}
	if !mode.IsValid() {
		return nil, fmt.Errorf("callout: invalid mode %q (expected %s or %s)",
			mode, ModeOperator, ModeConfig)
	}

	switch {
	case cfg.Conn == nil:
		return nil, errors.New("callout: missing the NATS connection")
	case cfg.Verifier == nil:
		return nil, errors.New("callout: missing the token verifier")
	case cfg.Router == nil:
		return nil, errors.New("callout: missing the permission router")
	case cfg.SigningKey == nil:
		return nil, errors.New("callout: missing the User JWT signing key")
	}

	responseSigner := cfg.ResponseSigner

	// The per-mode checks reject the CROSS-mode value instead of ignoring it. A config-mode
	// deploy that still carries an issuer account is either a half-finished migration or a
	// misunderstanding of the mode; both are worth failing at startup, because the alternative
	// is a server rejecting every connection with an error that names a claim the operator
	// never knowingly set.
	switch mode {
	case ModeOperator:
		if cfg.IssuerAccount == "" {
			return nil, errors.New("callout: operator mode needs the APP account public key (issuer account)")
		}
		if cfg.TargetAccount != "" {
			return nil, errors.New("callout: operator mode does not use a target account name (the account comes from the issuer account pubkey)")
		}
		if responseSigner == nil {
			return nil, errors.New("callout: operator mode needs the AUTH account signing key (response signer)")
		}
	case ModeConfig:
		if cfg.TargetAccount == "" {
			return nil, errors.New("callout: config mode needs the target account name (it travels in the User JWT audience)")
		}
		if cfg.IssuerAccount != "" {
			return nil, errors.New("callout: config mode must not set an issuer account (the server rejects a User JWT carrying issuer_account when there is no operator)")
		}
		if responseSigner == nil {
			// In config mode a single key signs both the User JWT and the response: the one the
			// server declares in `auth_callout.issuer`.
			responseSigner = cfg.SigningKey
		}
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
		mode:           mode,
		signingKey:     cfg.SigningKey,
		issuerAccount:  cfg.IssuerAccount,
		targetAccount:  cfg.TargetAccount,
		responseSigner: responseSigner,
		xkey:           cfg.XKey,
	}, nil
}

// Mode reports the mode the service was built for.
func (s *Service) Mode() Mode { return s.mode }

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

	// Deployment-declared placeholders are read from the token's claims. A missing one is a
	// rejection, handled inside Resolve: minting a subject with an empty segment would grant
	// permissions that silently match nothing.
	extra := s.extraPlaceholders(claims)

	identity, perms, decision, err := s.router.Resolve(claims.Roles, claims.Subject, claims.Username, extra)
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

// extraPlaceholders reads the values of the deployment-declared placeholders from the token.
//
// It returns nil when nothing is declared, which is the common case and keeps the hot path
// free of allocation.
func (s *Service) extraPlaceholders(claims *idp.Claims) map[string]string {
	declared := s.router.Placeholders()
	if len(declared) == 0 {
		return nil
	}
	extra := make(map[string]string, len(declared))
	for name, claimPath := range declared {
		if value, ok := claims.ClaimString(claimPath); ok {
			extra[name] = value
		}
	}
	return extra
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
	// How the User JWT names the account is the ONE thing that differs between the two modes.
	//
	// Beware of the two Audience fields, which mean opposite things and are easy to confuse:
	//   - the INNER User JWT's Audience (here) is the target ACCOUNT NAME, in config mode;
	//   - the OUTER authorization_response's Audience is the SERVER ID (see respondJWT).
	// ADR-26 documents `aud` as the server key, which is true only of the outer claim.
	switch s.mode {
	case ModeOperator:
		// IssuerAccount is mandatory when signing with a signing key: without it the server
		// cannot know which account the user belongs to.
		claims.IssuerAccount = s.issuerAccount
	case ModeConfig:
		// There are no account JWTs, so the account is named by NAME, not by pubkey: the server
		// resolves it with a name lookup. Using the pubkey here fails with "no valid account"
		// even though the key is correct.
		//
		// IssuerAccount is deliberately left unset: a config-mode server rejects a User JWT
		// that carries it.
		claims.Audience = s.targetAccount
	}

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
