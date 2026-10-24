# Implementation matrix

Status legend:

| Status | Meaning |
|---|---|
| planned | Designed (docs/ADR), no code |
| implemented | Code exists, not yet covered by automated tests for its security properties |
| tested | Automated tests exist and passed in the recorded session |
| verified-external | Checked against the real external system (Google, S3 provider, Cloudflare, …) |
| not verified | Explicitly not checked against the real external system |

"Reachable" = usable from UI and/or `/api/v1`, required before a row may be marked tested.

| Area | Feature | Status | Reachable | Evidence |
|---|---|---|---|---|
| Foundations | GitHub repos created (empty) | done | — | `gh repo view` (M0) |
| Foundations | Repo scaffold, `make check` | tested | — | `make check` exit 0 locally (M0); GitHub CI not run (nothing pushed) |
| Foundations | Design docs + Mermaid site | tested | — | `make site`: 15 Mermaid diagrams parse in Chromium, VitePress build OK (M0) |
| Platform | Store (writer/readers, migrations, snapshot, lock), keyring (+ sealed-column registry), audit chain, ids, config | tested | — | `go test -race ./internal/{store,keyring,audit,ids,config}`: forward migration from v1 fixture, downgrade refused, tamper detection (incl. tenant/auth-method fields), registry completeness (M1) |
| Platform | Public + private management listeners, `/healthz` `/readyz` `/metrics`, all server timeouts, optional TLS + client-cert CA | tested (client-cert path implemented, not tested) | API | `internal/app` tests: listener separation, timeouts, serve/shutdown; binary smoke (M1) |
| Bootstrap | CLI setup token → first owner + 1 h setup session | tested | API `POST /api/v1/setup`, CLI | 32 concurrent consumers → exactly 1 owner; expiry; binary smoke (M1) |
| Tenancy | Tenants, users, memberships (operator-managed), typed `tenancy.Scope`, composite FKs | tested | API `/api/v1/{tenants,users,tenants/{t}/members}` | cross-tenant composite-FK tests, scope tests, API flow with ETag/If-Match, CSRF/Origin, non-operator 403 (M1) |
| Login | Google federation (fake IdP) | planned | — | M2 |
| Login | Google federation (real Google) | not verified | — | — |
| Login | Domain rules / JIT / invites | planned | — | M2 |
| Login | Backup login (password + titled answers) | planned | — | M2 |
| Sessions | Server-side sessions: idle/absolute (+ tenant override), user + installation epochs, CSRF, step-up window, rotation | tested (core) | API cookie auth | `internal/session` tests (M1); login methods arrive in M2 |
| Sessions | Federated hourly `prompt=none` recheck flow | planned | — | M2 |
| OIDC OP | Code + PKCE, tokens, refresh families | planned | — | M3 |
| OIDC OP | OpenID conformance suite | planned | — | M3 |
| Apps | Applications, shares, launcher | planned | — | M4 |
| Apps | Forward-auth outpost | planned | — | M4 |
| AuthZ | RBAC + expr policies + explain | planned | — | M5 |
| Admin | Full admin UI | planned | — | M5 |
| Automation | Automation tokens, Terraform provider | planned | — | M6 |
| Events | Outbox → pulse | planned | — | M6 |
| Backups | age + MinIO backup/restore | planned | — | M6 |
| Backups | Real S3 providers | not verified | — | — |
| Edge | Trusted-proxy client IP (right-to-left XFF), Cloudflare `CF-Connecting-IP` only from CF ranges, security headers + CSP nonce | tested | — | `internal/httpx` spoofing table (16 cases), audit records trusted IP (M1) |
| Edge | Real Cloudflare | not verified | — | — |
| Release | Acceptance script, release workflow | planned | — | M7 |
| API | Management API conventions: RFC 9457 problems with stable codes, cursor pagination, ETag/If-Match, provenance headers, OpenAPI 3.1 committed | tested | `/api/v1` | path-param binding + auth-required spec tests (M1) |
| API | `Idempotency-Key` on creates | planned | — | M6 (with automation tokens) |
