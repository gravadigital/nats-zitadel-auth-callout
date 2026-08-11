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
	"flag"
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
	args := os.Args[1:]

	// One subcommand, and it is deliberately not a flag on the service: `verify` has to run
	// while the callout is NOT serving. Its most valuable check — that a client credential does
	// not bypass the callout — works by confirming the server REFUSES that client, which is only
	// observable before anything answers on the callout subject.
	if len(args) > 0 && args[0] == "verify" {
		err := runVerify(args[1:])
		if err == nil {
			return
		}
		// A failed verification has already printed its report; anything else is an error in
		// running the check at all and still needs saying.
		if !errors.Is(err, errVerifyFailed) {
			fmt.Fprintf(os.Stderr, "auth-callout verify: %v\n", err)
		}
		os.Exit(1)
	}

	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "auth-callout: unknown argument %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "auth-callout: %v\n", err)
		os.Exit(1)
	}
}

// usage prints what the binary does. It is short on purpose: everything else is environment
// variables, and those are documented where they are set rather than here.
func usage() {
	fmt.Fprint(os.Stderr, `nats-zitadel-auth-callout — authenticates NATS connections against an OIDC provider.

  auth-callout           run the service
  auth-callout verify    check a deployment's wiring without serving traffic

Configuration comes from the environment; see the README and examples/.

verify options:
  --client-creds PATH        credentials clients connect with (operator mode)
  --client-user NAME         the same, for config mode
  --client-password PASS
`)
}

func run() error {
	cfg, configFile, overridden, err := config.LoadWithSource()
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)

	if configFile != "" {
		log.Info().Str("file", configFile).Msg("configuration file loaded")
		// "I changed the file and nothing happened" is otherwise a genuinely confusing
		// afternoon: the value is there, it is just losing to a variable set somewhere else.
		for _, key := range overridden {
			log.Warn().Msg("configuration file value overridden by the environment: " + key)
		}
	}

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

// runVerify checks a deployment's wiring and reports what it found.
//
// It loads the same configuration the service would and connects the same way, so what it
// verifies is the real deployment rather than a description of it. It never starts serving:
// the bypass check depends on the callout NOT answering.
//
// Exit code 1 on any failure, so it is usable as a deployment gate.
func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	clientCreds := flags.String("client-creds", "", "credentials file clients connect with (operator mode)")
	clientUser := flags.String("client-user", "", "user clients connect with (config mode)")
	clientPassword := flags.String("client-password", "", "password for --client-user")
	if err := flags.Parse(args); err != nil {
		return err
	}

	// Loading the configuration is itself the first check: per-mode validation rejects a
	// variable the selected mode does not read, and a missing rules path, before anything
	// touches the network.
	cfg, configFile, overridden, err := config.LoadWithSource()
	if err != nil {
		return err
	}

	fmt.Printf("Verifying: serverMode=%s idp=%s nats=%s\n", cfg.ServerMode, cfg.IDPMode, cfg.NATSURL)
	if configFile != "" {
		// Which file was read matters here more than anywhere: the whole point of `verify` is to
		// confirm the deployment's real configuration, and reading a different file than the
		// service will read would make a clean report meaningless.
		fmt.Printf("Configuration file: %s\n", configFile)
		for _, key := range overridden {
			fmt.Printf("  note: %s\n", key)
		}
	}
	fmt.Println()

	// The rules and templates load exactly as the service would load them, so a broken
	// configuration is reported here rather than at the next restart.
	if _, err := authz.NewRouterFromFile(cfg.RulesPath, cfg.Instance,
		authz.WithInboxMode(authz.InboxMode(cfg.InboxMode)),
	); err != nil {
		fmt.Printf("FAIL  permission configuration\n      %v\n", err)
		fmt.Println("\n0 passed, 0 warning(s), 1 failure(s)\n\nThis deployment is not ready to serve traffic.")
		return errVerifyFailed
	}

	handlerAuth, err := handlerAuthOption(cfg)
	if err != nil {
		return err
	}

	// A short timeout and no reconnection: this is a probe, and a server that does not answer
	// promptly is itself the finding.
	nc, err := nats.Connect(cfg.NATSURL, handlerAuth,
		nats.Name("nats-auth-callout-verify"),
		nats.Timeout(natsConnectTimeout),
		nats.MaxReconnects(0),
	)
	if err != nil {
		fmt.Printf("FAIL  handler connection\n      cannot connect as the callout handler: %v\n", err)
		fmt.Printf("      fix: check CALLOUT_NATS_URL, and that the handler credential form matches CALLOUT_SERVER_MODE=%s and is declared in %s\n",
			cfg.ServerMode, authUsersFieldFor(cfg.ServerMode))
		fmt.Println("\n0 passed, 0 warning(s), 1 failure(s)\n\nThis deployment is not ready to serve traffic.")
		return errVerifyFailed
	}
	defer nc.Close()

	report := callout.Verify(callout.VerifyInput{
		Conn:           nc,
		Mode:           callout.Mode(cfg.ServerMode),
		ClientCreds:    *clientCreds,
		ClientUser:     *clientUser,
		ClientPassword: *clientPassword,
		NATSURL:        cfg.NATSURL,
		XKeyConfigured: cfg.XKeySeed != "",
		TargetAccount:  cfg.TargetAccount,
	})

	fmt.Print(report.String())
	if !report.OK() {
		return errVerifyFailed
	}
	return nil
}

// errVerifyFailed makes `verify` exit non-zero without printing a second error line: the report
// already said everything, and a trailing "error:" would only add noise.
var errVerifyFailed = errors.New("verification failed")

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
