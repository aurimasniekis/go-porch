# Reference assessment

Porch reuses ideas and code from two earlier projects by the same author. This document records what was reused,
under which license, what was deliberately **not** copied, and which gaps in the references Porch has to cover itself.

## Licenses and provenance

| Source | License | Copyright | Use in Porch |
|---|---|---|---|
| HallPass (`~/Projects/Golang/hallpass`, `github.com/aurimasniekis/go-hallpass`) | Apache-2.0 | © 2026 Aurimas Niekis | Code copied and adapted |
| Pulse (`~/Projects/Golang/pulse`, `github.com/aurimasniekis/go-pulse`) | Apache-2.0 | © 2026 Aurimas Niekis | Code copied and adapted; Go SDK `pkg/pulse` used as a dependency |
| EFF Large Wordlist for Passphrases | CC BY 3.0 US | Electronic Frontier Foundation | Embedded verbatim for recovery words |

Every adapted Go file starts with a provenance comment (`// Adapted from HallPass internal/store (Apache-2.0).`), and
`NOTICE` names both projects and the EFF wordlist. Porch itself is Apache-2.0.

## Reused from HallPass

| HallPass package | Porch package | What was kept | What changed |
|---|---|---|---|
| `internal/store` | `internal/store` | Split writer (1 conn, `BEGIN IMMEDIATE`, busy retry with jitter) / reader pools, strict pragmas, goose embedded forward-only migrations, pre-migration `VACUUM INTO` snapshot, `flock` process lock, network-filesystem refusal, error classification, storage health | Porch schema; recordings/quarantine dirs removed |
| `internal/keyring` | `internal/keyring` | KEK → versioned purpose keys (AES-256-GCM), AAD bound to table/column/row, canary, rotate/retire, KEK rotation, reseal job | Purposes are `field`, `token`, `signing`, `backup-meta`; **single sealed-column registry** (see "do not copy") |
| `internal/audit` | `internal/audit` | Transactional hash-chained append, sealed sensitive details, chain verification, JSONL sink | Schema v1 fields (tenant, reason code, auth method), ECS-aligned JSONL |
| `internal/opauth` | `internal/session`, `internal/localauth` | Argon2id PHC + param upgrade, NFKC normalisation, dummy hash for unknown users, hash semaphore, server-side hashed session tokens, Origin + HMAC CSRF, `RequireRecentAuth`, CLI-only setup token, break-glass | Split into browser sessions (all users) and the local backup credential |
| `internal/ids`, `internal/clock`, `internal/apperr`, `internal/obs/redact` | same | Prefixed UUIDv7 IDs, injectable clock, RFC 9457 error codes, secret redaction | Porch prefixes |
| `internal/jobs`, `internal/outbox` | same | Leased SQLite job queue, transactional outbox | Outbox relays to pulse instead of an in-process bus |
| `internal/config` | `internal/config` | Strict YAML (unknown keys rejected) + `PORCH_*` env overrides, production/development mode | Porch config tree |
| `internal/oidc/oidctest` | `internal/idp/fakeidp` | In-process fake OIDC provider for tests | Emits Google-style `hd`, `email_verified`, supports `prompt=none`, `max_age` |
| `web/check-dist.mjs`, embed handler, Dockerfile, systemd unit, CI workflows | same paths | SHA-pinned actions, govulncheck, gitleaks, syft, Trivy, attestations | Porch names |
| `tools/analyzers/txscope` | `tools/analyzers/txscope` | Forbids network/channel/sleep calls inside write-transaction callbacks | — |

## Reused from Pulse

| Pulse | Porch | Notes |
|---|---|---|
| Huma v2 code-first API + `openapi` command + drift check | `internal/mgmtapi`, `porch openapi` | OpenAPI 3.1 committed as `api/openapi.json`, TS types generated with `openapi-typescript` |
| `internal/backup` (age + minio-go + manifest + drill) | `internal/backup` | Porch adds s2 compression, KEK escrow to the same offline recipient, restore epoch bump |
| Web setup (Mantine 8, TanStack Router/Query/Store, Vite, Vitest, Playwright) | `web/` | Same versions and conventions |
| VitePress site | `site/` | Adds Mermaid |
| `pkg/pulse` NATS SDK | dependency | Used by the outbox relay only |

## Do not copy (known issues in the references)

| Issue in reference | Porch behaviour |
|---|---|
| HallPass serves `/metrics` on the public listener by default | `/metrics`, `/healthz`, `/readyz`, pprof live only on the private management listener (`127.0.0.1:9464`) |
| HallPass default listen `:8080` (all interfaces) | Default public listen `127.0.0.1:8080`; operators opt in to wider binds |
| Missing `WriteTimeout` | Every server sets `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `MaxHeaderBytes` |
| Rightmost-only `X-Forwarded-For` handling | Right-to-left walk skipping configured trusted proxies; first untrusted hop is the client |
| `style-src 'unsafe-inline'` | `style-src-elem 'self' 'nonce-…'` and `style-src-attr 'unsafe-inline'` only (Mantine sets style attributes) |
| Idempotency cache stored secret-bearing responses (HallPass SR-11) | Responses that contain secrets are never cached; replay returns 409 with a pointer to the resource |
| "Done but unreachable" features (SR-07/14/27) | Each feature's matrix row requires: reachable from UI and/or API, and covered by an e2e or API test |
| Keyring sealed-column registry drift (SR-36/37) | One registry (`keyring.Columns`) used by reseal, retire guard and backup; test: rotate → reseal → retire → backup → restore |

## Gaps in Pulse that Porch must handle

- **Dedupe window is 2 minutes.** Porch gives every outbox row a stable ULID used as the CloudEvents `id`
  (`pulse.WithID`); consumers must deduplicate on it. Documented for consumers.
- **No severity/tenant fields in the envelope.** Carried in the payload; event types are `porch.<area>.<event>.v1`.
- **SDK has no retry or buffer.** The outbox *is* the buffer; the relay retries with exponential backoff + jitter
  (cap 5 min) and dead-letters after 24 h or 50 attempts.
- **NATS permission denial surfaces as a ~5 s timeout.** Treated as retryable, counted, and alerted on.
- **Client credentials expire after 365 days.** Publish auth failures raise an alert.
- **go-pulse is untagged and requires go 1.27.3.** Pinned by pseudo-version; `GOTOOLCHAIN=auto`.

## No local precedent

Neither reference implements an OIDC **provider**. Porch's OP uses `github.com/zitadel/oidc/v3/pkg/op` with a SQLite
storage implementation, and is checked with its own protocol tests, interop tests and (where it can run offline) the
OpenID conformance suite.
