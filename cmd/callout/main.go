// Command callout es el servicio de auth callout de gestión: autentica las conexiones a
// NATS contra Zitadel y le mintea a cada una los permisos que le corresponden por rol.
//
// Un solo proceso, una sola conexión: atiende la cuenta AUTH con las creds del
// sentinel-handler y mintea User JWTs hacia la cuenta APP.
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

	"github.com/grava/gestion/auth-callout/internal/authz"
	"github.com/grava/gestion/auth-callout/internal/callout"
	"github.com/grava/gestion/auth-callout/internal/config"
	"github.com/grava/gestion/auth-callout/internal/idp"
)

// natsConnectTimeout acota el arranque: sin NATS el servicio no tiene nada que hacer.
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

	// El modo de IdP se loguea primero y bien visible: es la diferencia entre validar
	// contra Zitadel y aceptar cualquier identidad que el cliente diga tener.
	log.Info().
		Str("idp", cfg.IDPMode).
		Str("instance", cfg.Instance).
		Str("nats", cfg.NATSURL).
		Str("rules", cfg.RulesPath).
		Msg("iniciando auth-callout de gestión")
	if cfg.IDPMode == config.IDPModeMock {
		log.Warn().Msg("IdP en modo MOCK: cualquier token bien formado se acepta. No usar en producción.")
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
		return fmt.Errorf("signing key de la cuenta APP: %w", err)
	}
	authSigningKey, err := callout.LoadKeyPair(cfg.AuthAccountSigningKeySeed)
	if err != nil {
		return fmt.Errorf("signing key de la cuenta AUTH: %w", err)
	}
	appAccountPub, err := callout.ReadPubKey(cfg.AppAccountPubKey)
	if err != nil {
		return fmt.Errorf("pubkey de la cuenta APP: %w", err)
	}

	var xkey nkeys.KeyPair
	if cfg.XKeySeed != "" {
		xkey, err = callout.LoadCurveKeyPair(cfg.XKeySeed)
		if err != nil {
			return fmt.Errorf("XKey del callout: %w", err)
		}
	} else {
		log.Warn().Msg("sin XKey: los requests de callout viajan en claro")
	}

	nc, err := nats.Connect(cfg.NATSURL,
		nats.UserCredentials(cfg.HandlerCreds),
		nats.Name("gestion-auth-callout"),
		nats.Timeout(natsConnectTimeout),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn().Err(err).Msg("NATS desconectado")
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info().Str("url", c.ConnectedUrl()).Msg("NATS reconectado")
		}),
	)
	if err != nil {
		return fmt.Errorf("conectar a NATS: %w", err)
	}
	defer nc.Drain() //nolint:errcheck // en el camino de salida no hay a quién reportarle

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
	defer svc.Stop() //nolint:errcheck // ídem

	<-ctx.Done()
	log.Info().Msg("apagando")
	return nil
}

// buildVerifier arma el verificador de tokens según el modo configurado.
func buildVerifier(ctx context.Context, cfg *config.Config, log *zerolog.Logger) (idp.Verifier, error) {
	if cfg.IDPMode == config.IDPModeMock {
		return idp.NewMock(), nil
	}

	verifier, err := idp.NewZitadel(ctx, cfg.ZitadelIssuerURL,
		idp.WithProjectID(cfg.ZitadelProjectID),
		idp.WithUsernameEnrichment(true),
	)
	if err != nil {
		return nil, fmt.Errorf("inicializar Zitadel: %w", err)
	}
	log.Info().
		Str("issuer", cfg.ZitadelIssuerURL).
		Str("projectId", cfg.ZitadelProjectID).
		Msg("Zitadel listo (JWKS por OIDC discovery)")
	return verifier, nil
}

// newLogger arma el logger. Sale a stderr en formato consola: el servicio corre en
// contenedor y es el runtime el que decide qué hacer con el stream.
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
