# Contributing

## Requirements

- Go (see `go.mod`; `GOTOOLCHAIN=auto` fetches the exact version)
- Node 24 + pnpm 10 (web UI and docs site)
- Docker (integration, e2e, demo stack)

## Everyday commands

| Command | What it does |
|---|---|
| `make check` | Everything CI runs except e2e: fmt, vet, lint, race tests, drift checks, govulncheck, gitleaks, web checks |
| `make test` | `go test ./...` |
| `make race` | Race-enabled tests |
| `make sqlc` | Regenerate typed queries from `internal/store/{migrations,queries}` |
| `make api` | Regenerate `api/openapi.json` and the web client types |
| `make e2e` | Playwright against a fresh `porch serve` |
| `make site` | Build the VitePress docs site |

## Pull requests

- Conventional Commits (`feat(authz): …`, `fix(oidcop): …`).
- Security-relevant changes need an ADR and a threat-model update.
- Update `docs/IMPLEMENTATION_MATRIX.md` with evidence.
