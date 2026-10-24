# Plan

Porch is built in verified vertical slices. Each milestone ends with: implementation → tests → docs →
[IMPLEMENTATION_MATRIX.md](IMPLEMENTATION_MATRIX.md) and [BACKLOG.md](BACKLOG.md) updated → one local conventional commit.
Nothing is pushed without an explicit instruction. Nothing is reported as verified unless the command ran and passed.

## Definition of done (per feature)

1. Implemented behind the documented interface (service + API and/or UI).
2. **Reachable**: an operator or user can reach it from the UI and/or `/api/v1` (no "done but unreachable").
3. Tested: unit/integration tests for the security properties, plus an API or e2e test of the reachable path.
4. Documented: ADR if a decision was made, site/operator docs, matrix row updated with evidence.

## Milestones and acceptance criteria

### M0 — Foundations and design docs
- GitHub repos `aurimasniekis/go-porch` and `aurimasniekis/terraform-provider-porch` exist, empty, public.
- Repo scaffold: go.mod, LICENSE, NOTICE, README with status matrix, AGENTS.md, CONTRIBUTING, SECURITY, Makefile,
  `.golangci.yml`, `.gitleaks.toml`, CI workflows (SHA-pinned).
- Docs: REFERENCES, ARCHITECTURE, THREAT_MODEL, SCHEMA, FLOWS (Mermaid), API, DECISIONS (ADRs), this PLAN.
- **Accept:** `make check` passes on the skeleton; `site/` builds with VitePress and renders Mermaid.

### M1 — Bootstrap, store, keyring, tenancy, audit
- Store/keyring/audit/ids/config/obs ported; `porch serve` with public + management listeners, health/readiness,
  metrics; setup token → first operator; tenants, users, memberships (services + API).
- **Accept:** race tests; migration test (fresh + forward from fixture, downgrade refused); cross-tenant composite-FK
  tests; setup-token race test (exactly one winner); audit chain verify/tamper test; header and proxy spoofing tests.

### M2 — Google login, sessions, local recovery
- Fake Google provider; upstream OIDC login; domain rules + JIT/invite + provenance re-evaluation; sessions, step-up,
  epochs, hourly recheck; backup credential (password + titled recovery answers) enroll/rotate/two-step login with
  lockout; `porch admin recover` / `unlock-backup`; minimal login + setup UI.
- **Accept:** `hd` validation tests (missing / mismatch / hint-only); email-link-attack test; enumeration
  response/timing tests; concurrent lockout test (N parallel attempts → exactly threshold reserved); password-correct
  step grants no extra answer attempts; DoS test (Google login works during backup lockout); restart persistence.

### M3 — OIDC provider + demo app
- zitadel Storage, clients, keys/rotation, claims mapper, refresh families, revocation, introspection, client
  credentials, logout; `examples/demo-app`.
- **Accept:** redirect/PKCE/replay/code-reuse/refresh-reuse tests; key rotation overlap test; OpenID conformance suite
  (Basic/Config OP) if it can run locally, else documented; interop with demo-app and go-oidc RP.

### M4 — Application access + user portal
- Applications (OIDC & forward-auth), shares, `app:access`, launcher, personal sessions/recovery pages, forward-auth
  outpost + Caddy/whoami demo.
- **Accept:** header-spoof tests, open-redirect tests, Playwright login → launcher → app flows.

### M5 — Admin workflows + policy tooling
- Groups, roles, bundles, resources, assignments, expr policies, effective permissions, explain, simulator, service
  accounts, audit explorer, sessions admin, identity provider/domain UI, system health; full Mantine UI (light/dark, a11y).
- **Accept:** escalation/cycle/depth property tests, policy fuzzing, UI e2e per surface, axe clean.

### M6 — Terraform, pulse, backups, hardening
- Automation tokens; Terraform provider (plugin framework); outbox → pulse with local pulsed in Compose; backup/restore
  with MinIO + restore drill; Grafana dashboard + alert rules; Docker image, Compose (read-only rootfs), systemd; runbooks.
- **Accept:** `TF_ACC=1` acceptance tests against real `porch serve`; pulse integration test; restore drill into a clean
  instance.

### M7 — Interop and release prep
- `scripts/acceptance.sh` covering every demonstration item; release workflow (binaries, SHA256SUMS, SBOM, Trivy,
  attestations); integration matrix; final security review + regression tests; honest status matrix.

## Deviations from the original brief

| Item | Brief | Porch | Record |
|---|---|---|---|
| Recovery material | Prefer one-time, generated codes | User-chosen titled answers (security-question style), shown after a correct password, reusable until rotated | ADR-0008, ADR-0009 (security-relevant) |
| Logout | — | RP-initiated only; no front/back-channel in v1 | ADR-0013 |
