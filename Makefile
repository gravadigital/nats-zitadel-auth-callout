# Makefile — auth-callout de gestión.
#
# `make` sin argumentos lista los targets.

SHELL := /bin/bash
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(PATH):$(GOBIN)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Lista los targets
	@grep -hE '^[a-z][a-z0-9_-]*:.*?##' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: bootstrap
bootstrap: ## Genera la identidad NATS (operator, cuentas, sentinelas, authcallout)
	@cd nats && [[ -f .env ]] || cp -n .env.example .env
	@./nats/bootstrap.sh

.PHONY: run
run: bootstrap ## Levanta NATS + el callout en foreground
	@./scripts/run.sh

.PHONY: build
build: ## Compila el binario en bin/callout
	@mkdir -p bin
	go build -o bin/callout ./cmd/callout

.PHONY: test
test: ## Tests unitarios (incluye validar el config desplegable)
	go test ./...

.PHONY: test-live
test-live: ## Verifica la conexión con Zitadel real (necesita GESTION_ZITADEL_ISSUER_URL)
	@if [[ -z "$$GESTION_ZITADEL_ISSUER_URL" && -f nats/.env ]]; then set -a; . ./nats/.env; set +a; fi; \
	if [[ -z "$$GESTION_ZITADEL_ISSUER_URL" ]]; then \
		echo "falta GESTION_ZITADEL_ISSUER_URL (ponelo en nats/.env o en el entorno)"; exit 1; \
	fi; \
	go test -tags live -count=1 -v -run TestLive ./internal/idp/

.PHONY: test-e2e
test-e2e: ## Suite de aceptación: levanta NATS + callout y prueba los flujos reales
	go test -tags e2e -count=1 -timeout 180s ./test/e2e/...

.PHONY: fmt
fmt: ## Formatea
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: ci
ci: fmt-check vet test test-e2e ## Todo lo que corre CI

.PHONY: fmt-check
fmt-check: ## Falla si hay algo sin formatear
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [[ -n "$$out" ]]; then echo "sin formatear:"; echo "$$out"; exit 1; fi

.PHONY: clean
clean: ## Borra binarios y datos de JetStream (NO la identidad NATS)
	rm -rf bin nats/data

.PHONY: clean-identity
clean-identity: ## Borra la identidad NATS generada — obliga a reemitir todas las creds
	rm -rf nats/out
