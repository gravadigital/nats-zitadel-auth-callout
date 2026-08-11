// Command callout is the NATS auth callout service: it authenticates NATS connections against
// an OIDC identity provider and mints for each one the permissions its role entitles it to.
//
// One process, one connection: it serves the callout account with the handler's credentials
// and mints User JWTs toward the account clients land in. It works against both NATS
// authorization models — operator mode and config mode — selected with CALLOUT_SERVER_MODE.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/callout"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/config"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// natsConnectTimeout bounds startup: with no NATS the service has nothing to do.
const natsConnectTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "auth-callout: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)

	// The IdP mode is logged first and prominently: it is the difference between validating
	// against Zitadel and accepting any identity the client claims to have.
	log.Info().
		Str("idp", cfg.IDPMode).
		// The server mode decides how the User JWT names the target account, so it belongs on
		// the same line as the IdP: between them they describe the whole authorization path.
		Str("serverMode", cfg.ServerMode).
		Str("targetAccount", cfg.TargetAccount).
		Str("instance", cfg.Instance).
		Str("inbox", cfg.InboxMode).
		Str("nats", cfg.NATSURL).
		Str("rules", cfg.RulesPath).
		Msg("starting nats-auth-callout")
	if cfg.IDPMode == config.IDPModeMock {
		log.Warn().Msg("IdP in MOCK mode: any well-formed token is accepted. Do not use in production.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	router, err := authz.NewRouterFromFile(cfg.RulesPath, cfg.Instance,
		authz.WithInboxMode(authz.InboxMode(cfg.InboxMode)),
	)
	if err != nil {
		return err
	}
	if cfg.InboxMode == config.InboxModePassthrough {
		log.Warn().Msg("inbox in PASSTHROUGH mode: replies are not scoped per user, so the templates must grant the inbox they need explicitly")
	}
	// Configuration that is suspicious but has a legitimate reading. Anything provably unable to
	// work already failed above, inside NewRouterFromFile.
	for _, warning := range router.Warnings() {
		log.Warn().Msg(warning)
	}

	verifier, err := buildVerifier(ctx, cfg, &log)
	if err != nil {
		return err
	}

	// The User JWT signing key is the one key both modes need.
	signingKey, err := callout.LoadKeyPair(cfg.AppAccountSigningKeySeed)
	if err != nil {
		return fmt.Errorf("User JWT signing key: %w", err)
	}

	// The remaining keys are per-mode. Config validation already guaranteed the right ones are
	// present and the wrong ones absent, so this only has to load what the mode uses.
	var (
		responseSigner nkeys.KeyPair
		appAccountPub  string
	)
	if !cfg.ServerModeIsConfig() {
		responseSigner, err = callout.LoadKeyPair(cfg.AuthAccountSigningKeySeed)
		if err != nil {
			return fmt.Errorf("AUTH account signing key: %w", err)
		}
		appAccountPub, err = callout.ReadPubKey(cfg.AppAccountPubKey)
		if err != nil {
			return fmt.Errorf("APP account pubkey: %w", err)
		}
	}

	var xkey nkeys.KeyPair
	if cfg.XKeySeed != "" {
		xkey, err = callout.LoadCurveKeyPair(cfg.XKeySeed)
		if err != nil {
			return fmt.Errorf("callout XKey: %w", err)
		}
	} else {
		log.Warn().Msg("no XKey: callout requests travel in the clear")
	}

	handlerAuth, err := handlerAuthOption(cfg)
	if err != nil {
		return err
	}

	opts := []nats.Option{
		handlerAuth,
		nats.Name("nats-auth-callout"),
		nats.Timeout(natsConnectTimeout),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn().Err(err).Msg("NATS disconnected")
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info().Str("url", c.ConnectedUrl()).Msg("NATS reconnected")
		}),
	}

	nc, err := nats.Connect(cfg.NATSURL, opts...)
	if err != nil {
		// A mode mismatch surfaces here first: an operator-mode server refuses user/password and
		// a config-mode server ignores a .creds JWT. Naming the declared mode turns an opaque
		// "Authorization Violation" into a pointer at the likely cause.
		return fmt.Errorf("connect to NATS as the callout handler (CALLOUT_SERVER_MODE=%s — check that the handler credential form matches the server's authorization mode and that the handler is declared in %s): %w",
			cfg.ServerMode, authUsersFieldFor(cfg.ServerMode), err)
	}
	defer nc.Drain() //nolint:errcheck // on the way out there is nobody to report to

	svc, err := callout.New(callout.Config{
		Conn:           nc,
		Verifier:       verifier,
		Router:         router,
		Logger:         &log,
		Mode:           callout.Mode(cfg.ServerMode),
		SigningKey:     signingKey,
		IssuerAccount:  appAccountPub,
		TargetAccount:  cfg.TargetAccount,
		ResponseSigner: responseSigner,
		XKey:           xkey,
	})
	if err != nil {
		return err
	}

	if err := svc.Start(); err != nil {
		return err
	}
	defer svc.Stop() //nolint:errcheck // ditto

	<-ctx.Done()
	log.Info().Msg("shutting down")
	return nil
}

// handlerAuthOption builds the nats.Option for the callout's OWN connection.
//
// The three forms are not interchangeable across modes: a .creds file is an operator-mode
// artifact, whereas a config-mode server authenticates its users with user/password or an
// nkey. Config validation already ensured exactly one form is set.
func handlerAuthOption(cfg *config.Config) (nats.Option, error) {
	switch {
	case cfg.HandlerCreds != "":
		return nats.UserCredentials(cfg.HandlerCreds), nil

	case cfg.HandlerUser != "":
		return nats.UserInfo(cfg.HandlerUser, cfg.HandlerPassword), nil

	case cfg.HandlerNKeySeed != "":
		kp, err := callout.LoadKeyPair(cfg.HandlerNKeySeed)
		if err != nil {
			return nil, fmt.Errorf("handler nkey: %w", err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("handler nkey pubkey: %w", err)
		}
		// The signature callback keeps the seed in memory rather than on the wire.
		return nats.Nkey(pub, kp.Sign), nil
	}

	return nil, errors.New("no handler credentials configured")
}

// authUsersFieldFor names the server-side field the handler has to be listed in, so the
// connection error can point at the right place in the right file.
func authUsersFieldFor(mode string) string {
	if mode == config.ServerModeConfig {
		return "authorization.auth_callout.auth_users (nats-server.conf)"
	}
	return "--auth-user (nsc edit authcallout)"
}

// buildVerifier builds the token verifier according to the configured mode.
func buildVerifier(ctx context.Context, cfg *config.Config, log *zerolog.Logger) (idp.Verifier, error) {
	switch cfg.IDPMode {
	case config.IDPModeMock:
		return idp.NewMock(), nil

	case config.IDPModeOIDC:
		verifier, err := idp.NewOIDC(ctx, cfg.OIDCIssuerURL, cfg.OIDCRolesClaim,
			idp.WithOIDCAudience(cfg.OIDCAudience),
			idp.WithOIDCUsernameClaim(cfg.OIDCUsernameClaim),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize OIDC: %w", err)
		}
		event := log.Info().
			Str("issuer", cfg.OIDCIssuerURL).
			Str("rolesClaim", cfg.OIDCRolesClaim)
		if cfg.OIDCAudience == "" {
			// Without an audience any token the provider issued for any of its clients verifies
			// here. That is rarely the intent, so it is surfaced rather than left implicit.
			event = event.Bool("audienceChecked", false)
		} else {
			event = event.Str("audience", cfg.OIDCAudience)
		}
		event.Msg("OIDC ready (JWKS through discovery)")
		return verifier, nil

	default:
		verifier, err := idp.NewZitadel(ctx, cfg.ZitadelIssuerURL,
			idp.WithProjectID(cfg.ZitadelProjectID),
			idp.WithUsernameEnrichment(true),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize Zitadel: %w", err)
		}
		log.Info().
			Str("issuer", cfg.ZitadelIssuerURL).
			Str("projectId", cfg.ZitadelProjectID).
			Msg("Zitadel ready (JWKS through OIDC discovery)")
		return verifier, nil
	}
}

// newLogger builds the logger. It writes to stderr in console format: the service runs in a
// container and it is the runtime that decides what to do with the stream.
func newLogger(level string) zerolog.Logger {
	parsed, err := zerolog.ParseLevel(level)
	if err != nil || parsed == zerolog.NoLevel {
		parsed = zerolog.InfoLevel
	}
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(parsed).
		With().
		Timestamp().
		Logger()
}
