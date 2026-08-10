// Command callout is the NATS auth callout service: it authenticates NATS connections
// against Zitadel and mints for each one the permissions its role entitles it to.
//
// One process, one connection: it serves the AUTH account with the sentinel-handler creds and
// mints User JWTs toward the APP account.
package main

import (
	"context"
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
		Str("instance", cfg.Instance).
		Str("nats", cfg.NATSURL).
		Str("rules", cfg.RulesPath).
		Msg("starting nats-zitadel-auth-callout")
	if cfg.IDPMode == config.IDPModeMock {
		log.Warn().Msg("IdP in MOCK mode: any well-formed token is accepted. Do not use in production.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	router, err := authz.NewRouterFromFile(cfg.RulesPath, cfg.Instance)
	if err != nil {
		return err
	}

	verifier, err := buildVerifier(ctx, cfg, &log)
	if err != nil {
		return err
	}

	appSigningKey, err := callout.LoadKeyPair(cfg.AppAccountSigningKeySeed)
	if err != nil {
		return fmt.Errorf("APP account signing key: %w", err)
	}
	authSigningKey, err := callout.LoadKeyPair(cfg.AuthAccountSigningKeySeed)
	if err != nil {
		return fmt.Errorf("AUTH account signing key: %w", err)
	}
	appAccountPub, err := callout.ReadPubKey(cfg.AppAccountPubKey)
	if err != nil {
		return fmt.Errorf("APP account pubkey: %w", err)
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

	nc, err := nats.Connect(cfg.NATSURL,
		nats.UserCredentials(cfg.HandlerCreds),
		nats.Name("nats-zitadel-auth-callout"),
		nats.Timeout(natsConnectTimeout),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn().Err(err).Msg("NATS disconnected")
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info().Str("url", c.ConnectedUrl()).Msg("NATS reconnected")
		}),
	)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	defer nc.Drain() //nolint:errcheck // on the way out there is nobody to report to

	svc, err := callout.New(callout.Config{
		Conn:           nc,
		Verifier:       verifier,
		Router:         router,
		Logger:         &log,
		SigningKey:     appSigningKey,
		IssuerAccount:  appAccountPub,
		ResponseSigner: authSigningKey,
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

// buildVerifier builds the token verifier according to the configured mode.
func buildVerifier(ctx context.Context, cfg *config.Config, log *zerolog.Logger) (idp.Verifier, error) {
	if cfg.IDPMode == config.IDPModeMock {
		return idp.NewMock(), nil
	}

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
