# Changelog

All notable changes to Porch are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow the policy in
[docs/VERSIONING.md](docs/VERSIONING.md) (Semantic Versioning for the binary, with separate compatibility rules for the
management API, the database schema and the configuration).

Entries describe what is implemented and tested in this repository. Evidence for each feature, and what has not been
checked against real external systems, is in [docs/IMPLEMENTATION_MATRIX.md](docs/IMPLEMENTATION_MATRIX.md).

## [Unreleased]

No version has been released yet. This section summarizes milestones M0–M7 ([docs/PLAN.md](docs/PLAN.md)).

> **Not externally reviewed.** The keyring, session handling, OIDC provider, backup login and backup format have had
> no external security audit. An internal review (docs/SECURITY_REVIEW-2026-10-24.md) found 3 high and 11 medium
> issues plus low-severity items, all fixed with regression tests.

### Known limitations

- Pre-1.0: interfaces may change between minor versions ([docs/VERSIONING.md](docs/VERSIONING.md)).
- The Caddy and nginx forward-auth examples strip the `__Host-porch_fa` cookie before the backend; Traefik has no
  built-in way to do so.
- Not yet available: front-channel and back-channel logout (logout is RP-initiated only, ADR-0013), passkeys, high
  availability (one instance per data directory).

### Added

- **Installation tokens without expiry (security-relevant, ADR-0046).** Installation owners can issue a token that
  never expires and does not depend on the identity provider confirming them, for Terraform and break-glass access.
- **Appearance.** Sign-in backgrounds mixed from several providers (Wikimedia Commons by category or file name,
  credited; Lorem Picsum; your own image URLs), fetched and re-encoded by Porch and served from its own origin; application icons (upload, image URL, theSVG brand logos
  or the dashboard-icons set; SVG is sanitized and kept as SVG) and launcher groups (ADR-0045).
- **Foundations (M0).** Go module `github.com/aurimasniekis/go-porch`, Makefile `check` target (gofmt, vet, a custom
  transaction-scope analyzer, golangci-lint, race tests, sqlc and OpenAPI drift checks, govulncheck, gitleaks, docs
  site), a SHA-pinned CI workflow, design documents (architecture, STRIDE threat model, schema, flows, API, ADRs) and
  a VitePress site with Mermaid diagrams.
- **Platform core (M1).** SQLite store with a single writer, reader pool, forward-only migrations with a pre-migration
  snapshot and a data-directory lock; keyring with a KEK file wrapping per-purpose keys and a sealed-column registry;
  hash-chained audit log with `porch audit verify`; transactional outbox. Public and loopback management listeners with
  `/healthz`, `/readyz` and `/metrics`. CLI: `serve`, `migrate`, `config check`, `keys`, `admin setup-token`,
  `healthcheck`, `openapi`, `version`.
- **Tenancy and bootstrap (M1).** Tenants, users and memberships behind a typed tenancy scope and composite foreign keys;
  a single-use setup token that creates the first owner exactly once; management API `/api/v1` with RFC 9457 problem
  responses, cursor pagination, ETag/If-Match and a committed OpenAPI 3.1 document (`api/openapi.json`).
- **Login (M2).** Google and generic OIDC federation (PKCE S256, nonce, state bound to a `__Host-` cookie, RS256
  allowlist, identities keyed by issuer and subject); domain rules from the validated `hd` claim or a verified email,
  with JIT or invite-only enrollment and provenance re-evaluation; hourly `prompt=none` upstream recheck; step-up;
  identity linking; an outbound SSRF guard.
- **Backup login and recovery (M2).** Backup password plus user-written titled recovery answers (ADR-0008, ADR-0009),
  Argon2id verifiers, a shared lockout reserved before hashing, per-source and installation-wide throttles,
  enumeration-resistant responses; `porch admin recover` (one-time 15-minute link and a critical alert) and
  `porch admin unlock-backup`.
- **Web UI (M2, M5).** Mantine single-page app embedded in the binary with a per-request CSP nonce: setup, login,
  recovery, launcher, account, and the admin UI for tenants, authorization and the installation. Playwright tests run
  axe (WCAG 2.1 AA) and a zero-CSP-violation check.
- **OpenID Provider (M3).** Authorization code with PKCE S256, exact redirect URIs, RFC 9207 `iss`, ES256/RS256 ID tokens,
  RFC 9068 JWT access tokens with RFC 8707 audiences, rotating refresh tokens with family reuse detection, code-replay
  revocation, client credentials, introspection, userinfo, revocation, RP-initiated logout, discovery and JWKS; signing
  keys rotated with overlap and retired. `examples/demo-app` is a go-oidc relying party used for interop tests.
- **Application access (M4).** Applications with access modes and explicit cross-tenant shares, a user launcher,
  personal session and offline-grant management, and a forward-auth outpost for Caddy, Traefik and nginx with host-bound
  single-use codes and per-host cookies.
- **Authorization (M4, M5).** Roles, bundles, nested groups, resource hierarchy scopes, `expr` conditions and deny
  policies, explain traces, a simulator and the decision API (`authz/check`, `authz/check-batch`); delegated tenant
  administration with escalation checks (ADR-0038); service accounts with the client credentials grant (ADR-0037);
  audit explorer, session administration and system health (ADR-0039).
- **Automation (M6).** Installation and tenant automation tokens (`porch_at_…`, ADR-0041) that never exceed their
  creator's current rights; `Idempotency-Key` on POST requests.
- **Backups (M6).** age-encrypted backups of the database and the escrowed KEK with Ed25519-signed manifests in
  S3-compatible storage, schedule and retention, `porch backup …` and `porch restore` (ADR-0042). A restore refuses
  unverified backups, writes only into an empty data directory, and on first start bumps the security epoch and
  replaces signing keys. `scripts/backup-drill.sh` runs the cycle against MinIO.
- **Events (M6).** Outbox relay to pulse through the go-pulse SDK with stable IDs, capped backoff and dead-lettering
  (ADR-0043).
- **Terraform (M6).** `terraform-provider-porch` (separate repository): 16 resources and 4 data sources with import,
  drift handling, ETag/If-Match and idempotent creates; acceptance tests run against a real `porch serve`, and a
  three-family example applies 69 resources.
- **Acceptance and security review (M7).** `scripts/acceptance.sh` runs every suite and an API scenario against real
  binaries and prints PASS/FAIL/SKIPPED/NOT VERIFIED per item; integration matrix; fixes for the internal security
  review (ADR-0044).
- **Deployment and operations (M4, M6).** Distroless non-root container image, production Compose file with a read-only
  root filesystem, systemd unit, a Caddy demo stack, Grafana dashboard, Prometheus alert rules with promtool tests, and
  runbooks.
- **Release pipeline.** Release workflow for `v*` tags: race-test gate, reproducible static archives for linux/amd64,
  linux/arm64 and darwin/arm64 with `SHA256SUMS` and SPDX SBOMs, per-architecture image builds with Trivy and a
  container smoke test, multi-arch image on GHCR (and Docker Hub when configured), build provenance attestations and a
  draft GitHub release ([docs/RELEASING.md](docs/RELEASING.md)). Not yet run on GitHub.
