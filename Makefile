SHELL        := /usr/bin/env bash
GO           ?= go
BIN          := bin
PKG          := github.com/aurimasniekis/go-porch
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS      := -s -w -X $(PKG)/internal/buildinfo.Version=$(VERSION)
FUZZTIME     ?= 10s
GITLEAKS     ?= $(GO) run github.com/zricethezav/gitleaks/v8@v8.30.1
GOVULNCHECK  ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0

.DEFAULT_GOAL := help
.PHONY: help build build-go test race vet custom-vet lint fmt-check tools-test fuzz-smoke vuln secrets check clean \
        sqlc sqlc-check api api-check web web-check site e2e test-oidc-interop test-fault

help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- build -------------------------------------------------------------------

build: web build-go ## Build the web UI and the porch binary

build-go: ## Build bin/porch without rebuilding the UI
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/porch ./cmd/porch

web: ## Build the web UI into internal/webui/dist
	@if [ -f web/package.json ]; then cd web && pnpm install --frozen-lockfile && pnpm build; else echo "web/: not yet scaffolded"; fi

site: ## Build the VitePress docs site and check every Mermaid diagram parses
	cd site && pnpm install --frozen-lockfile && pnpm check:mermaid && pnpm build

# ---- checks ------------------------------------------------------------------

test: ## go test
	$(GO) test ./...

race: ## go test with the race detector
	$(GO) test -race -count=1 ./...

vet: ## go vet
	$(GO) vet ./...

$(BIN)/porch-vet: $(shell find tools -name '*.go' -not -path '*/testdata/*')
	cd tools && GOWORK=off $(GO) build -o ../$(BIN)/porch-vet ./cmd/porch-vet

custom-vet: $(BIN)/porch-vet ## Custom analyzers (txscope)
	$(GO) vet -vettool=$(abspath $(BIN)/porch-vet) ./...

tools-test: ## Analyzer tests
	cd tools && GOWORK=off $(GO) test ./...

lint: ## golangci-lint
	golangci-lint run ./...

fmt-check: ## Fail if gofmt would change files
	@out=$$(find . -name '*.go' -not -path '*/node_modules/*' -not -path '*/testdata/*' -print0 | xargs -0 gofmt -l); \
	  if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

fuzz-smoke: ## Run every Fuzz* target for FUZZTIME
	@set -e; for pkg in $$($(GO) list ./...); do \
	  for fz in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
	    echo "fuzz $$pkg $$fz"; $(GO) test -run '^$$' -fuzz "^$$fz$$" -fuzztime $(FUZZTIME) $$pkg; \
	  done; \
	done

vuln: ## govulncheck
	$(GOVULNCHECK) ./...

secrets: ## gitleaks over the git history and working tree
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 $(GITLEAKS) dir --redact --config .gitleaks.toml .

web-check: ## Web lint, typecheck, unit tests, build, check-dist
	@if [ -f web/package.json ]; then cd web && pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm build; else echo "web/: not yet scaffolded"; fi

check: fmt-check vet custom-vet lint tools-test race sqlc-check api-check web-check site vuln secrets ## Everything CI runs (except e2e)

# ---- generated code ----------------------------------------------------------

$(BIN)/sqlc:
	./scripts/install-sqlc.sh

sqlc: $(BIN)/sqlc ## Regenerate typed queries
	@if [ -f sqlc.yaml ]; then $(BIN)/sqlc generate; fi

sqlc-check: $(BIN)/sqlc ## Fail if generated queries drift from SQL
	@if [ -f sqlc.yaml ]; then $(BIN)/sqlc diff; else echo "sqlc: no sqlc.yaml yet"; fi

api: ## Regenerate api/openapi.json and web types
	@if [ -d internal/mgmtapi ]; then $(GO) run ./cmd/porch openapi > api/openapi.json; fi
	@if [ -f web/package.json ]; then cd web && pnpm gen:api; fi

api-check: api ## Fail if the OpenAPI document or web types drift
	git diff --exit-code -- api web/src/api 2>/dev/null || (echo "api drift: run make api and commit"; exit 1)

# ---- integration -------------------------------------------------------------

e2e: ## Playwright against a fresh porch serve
	scripts/e2e.sh

test-oidc-interop: ## OIDC interop tests (Docker)
	$(GO) test -tags oidcinterop -count=1 -timeout 20m -v ./test/oidcinterop/...

test-fault: ## Fault-injection tests
	$(GO) test -tags fault -count=1 -timeout 20m ./test/fault/...

clean: ## Remove build output
	rm -rf $(BIN) dist
