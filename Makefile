# Makefile — nats-zitadel-auth-callout.
#
# `make` with no arguments lists the targets.

SHELL := /bin/bash
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(PATH):$(GOBIN)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the targets
	@grep -hE '^[a-z][a-z0-9_-]*:.*?##' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: bootstrap
bootstrap: ## Generate the NATS identity (operator, accounts, sentinels, authcallout)
	@cd nats && [[ -f .env ]] || cp -n .env.example .env
	@./nats/bootstrap.sh

.PHONY: run
run: bootstrap ## Bring up NATS + the callout in the foreground
	@./scripts/run.sh

.PHONY: build
build: ## Compile the binary into bin/callout
	@mkdir -p bin
	go build -o bin/callout ./cmd/callout

.PHONY: test
test: ## Unit tests (includes validating the shippable config)
	go test ./...

.PHONY: test-live
test-live: ## Verify connectivity with real Zitadel (needs CALLOUT_ZITADEL_ISSUER_URL)
	@if [[ -z "$$CALLOUT_ZITADEL_ISSUER_URL" && -f nats/.env ]]; then set -a; . ./nats/.env; set +a; fi; \
	if [[ -z "$$CALLOUT_ZITADEL_ISSUER_URL" ]]; then \
		echo "CALLOUT_ZITADEL_ISSUER_URL is not set (put it in nats/.env or in the environment)"; exit 1; \
	fi; \
	go test -tags live -count=1 -v -run TestLive ./internal/idp/

.PHONY: test-e2e
test-e2e: ## Acceptance suite: brings up NATS + callout and exercises the real flows
	go test -tags e2e -count=1 -timeout 180s ./test/e2e/...

.PHONY: fmt
fmt: ## Format
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: ci
ci: fmt-check vet test test-e2e ## Everything CI runs

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [[ -n "$$out" ]]; then echo "unformatted:"; echo "$$out"; exit 1; fi

.PHONY: clean
clean: ## Delete binaries and JetStream data (NOT the NATS identity)
	rm -rf bin nats/data

.PHONY: clean-identity
clean-identity: ## Delete the generated NATS identity — forces reissuing every cred
	rm -rf nats/out
