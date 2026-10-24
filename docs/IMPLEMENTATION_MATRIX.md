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
| Login | Google/OIDC federation: PKCE S256, nonce, state bound to `__Host-porch_oidc`, RS256 allowlist, SSRF-guarded discovery | tested | UI `/login`, portal `/login/{provider}` | `internal/app/login_test.go` (fake IdP: forged aud/nonce/iss, expired, login CSRF, replay); Playwright `m2-login.spec.ts` (M2) |
| Login | Google federation (real Google) | not verified | — | Fake provider only; see site/operators/identity-providers |
| Recovery | `porch admin recover` one-time 15-min link + persistent critical alert; `porch admin unlock-backup`; owner unlock via API (step-up) | tested | CLI, UI `/recovery`, API | `TestRecoveryLink`, `TestEscalationAndUnlock` (M2) |
| UI | Login, setup, recovery, home, account (backup enrollment, linked identities) — Mantine, CSP nonce, light/dark | tested | `/login` `/setup` `/recovery` `/` `/account` | Playwright + axe (WCAG 2.1 AA) + zero CSP violations (M2) |
| Edge | SSRF guard for outbound HTTP (deny loopback/private/link-local/CGNAT/NAT64 unless allowlisted) | tested | — | `internal/netguard` (M2) |
| Login | Domain rules (validated `hd` / verified email), JIT + invite-only, invites, provenance re-evaluation, email-link-attack resistance | tested | API `/tenants/{t}/domain-rules`, `/invites` | hd missing/mismatch/hint-only/allowlist tests, email-link attack, invite-only, evidence loss on recheck (M2) |
| Login | Backup login: password → titles → answers; shared reserve-before-hash lockout (1 → 6 h, ×2 to 48 h), per-source + circuit throttles, enumeration resistance, strength gate, random-word suggestion | tested | UI `/login`, `/account`; API `/auth/backup/*`, `/me/backup-credential` | `internal/localauth` (24 parallel → exactly threshold, no extra answer guesses, escalation, throttles), DoS isolation + restart persistence (`internal/app`), Playwright (M2) |
| Account | Personal sessions list/revoke, app offline grants list/revoke | tested | `/me/sessions`, `/me/grants`; UI account | Playwright `m4-launcher.spec.ts` (M4) |
| Sessions | Server-side sessions: idle/absolute (+ tenant override), user + installation epochs, CSRF, step-up window, rotation | tested (core) | API cookie auth | `internal/session` tests (M1); login methods arrive in M2 |
| Sessions | Federated hourly `prompt=none` recheck (API 401 `upstream_recheck_required`, page redirect), Workspace removal ends session; step-up via Google `prompt=login max_age=0` or backup credential; identity linking | tested | portal + API | `TestUpstreamRecheck`, `TestGoogleStepUp`, `TestStepUpRotatesSession` (M2) |
| OIDC OP | Authorization code + PKCE S256 (required for public clients, default for all), exact redirect URIs, RFC 9207 `iss`, ES256/RS256 ID tokens, RFC 9068 access tokens (`at+jwt`, RFC 8707 audiences), rotating refresh tokens with family reuse detection, code-replay revocation, client credentials, introspection, userinfo, revocation, RP-initiated logout, CORS for registered origins only | tested | `/oauth2/*`, `/.well-known/openid-configuration`, `/jwks`; API `/tenants/{t}/applications` | `internal/app/oidc_test.go` (go-oidc RP; 11 protocol tests) (M3) |
| OIDC OP | Signing keys: ES256 + RS256 sealed in keyring, rotation with overlap, retirement | tested | API `/installation/signing-keys` | `TestSigningKeyRotationOverlap` (M3) |
| OIDC OP | prompt=none / prompt=login / max_age, cross-tenant denial | tested | — | `TestPromptAndMaxAge`, `TestCrossTenantAccessDenied` (M3) |
| OIDC OP | Interop: in-repo demo RP (go-oidc) against a real `porch serve` | tested | `examples/demo-app` | Playwright `m3-demo-app.spec.ts`: sign-in, verified ID + RFC 9068 access token, refresh rotation, RP-initiated logout (M3) |
| OIDC OP | OpenID conformance suite (Basic/Config OP), local Docker run | tested | — | `test/conformance/run.sh`: Basic 21 passed / 6 warning (diagnosed) / 3 review / 4 skipped / 1 failed → fixed and re-run as REVIEW; Config 1 passed. Not an official certification (M4) |
| Apps | Applications (OIDC, forward-auth), access modes, explicit cross-tenant shares, launcher | tested | API `/tenants/{t}/applications{,/shares}`, `/me/apps`; UI home | `internal/authz` share tests, `TestAuthzCheckAndSharesAPI`, Playwright `m4-launcher.spec.ts` (M4) |
| Apps | Forward-auth outpost (Caddy/Traefik/nginx contract, per-host cookies, host-bound single-use codes, trusted peers) | tested | `/outpost/*`, `/.porch/*` | `internal/app/forwardauth_test.go` (spoofing, open redirect, host binding, logout), Playwright via `test/fwdproxy` (M4); real Caddy 2.11.7 in `deploy/demo`: curl sign-in, header-spoof stripping, 302/401 (M4) |
| AuthZ | Engine: roles, bundles, nested groups (DAG ≤ 5), resource hierarchy scopes, expiry, expr conditions + deny policies (sandboxed, fuzzed), tenant gate, explain trace, epoch cache; decision API | tested | API `/tenants/{t}/authz/check{,-batch}` | `internal/authz` (decisions, cycles/depth, random-DAG property, stale-policy fail-closed, fuzz) (M4) |
| AuthZ | Admin API: roles, bundles, groups (members, nesting), resources, policies (+ validate), assignments (users, groups, service accounts), effective permissions, permission catalogue | tested | API `/tenants/{t}/{roles,groups,resources,policies,assignments,permissions,authz/effective}` | `TestDelegatedTenantAdministration`, `TestServiceAccounts` (M5) |
| AuthZ | Delegated tenant administration with escalation checks (ADR-0038) | tested | API (all tenant management endpoints), `/me/admin` | `TestDelegatedTenantAdministration`, `TestDelegatedTenantSettings`, property `TestEscalationCheckProperty`, `TestNonOperatorForbidden` (M5) |
| Identity | Service accounts with client credentials (ADR-0037) | tested | API `/tenants/{t}/service-accounts`, `/oauth2/token` | `TestServiceAccounts` (M5) |
| Ops | Audit explorer (installation + tenant), sessions admin, system health (ADR-0039) | tested | API `/audit`, `/tenants/{t}/audit`, `/sessions`, `/users/{u}/revoke-sessions`, `/installation/health` | `TestAuditExplorerSessionsAndHealth` (M5) |
| UI | Admin UI: tenant (members, invitations, applications + one-time secrets, service accounts, settings, domain rules), authorization (roles, groups + nesting, assignments, resources tree, policies with live validation, access explorer: effective permissions + simulator with trace), installation (health, tenants, users + search, identity providers, sessions, audit explorer, alerts, keys, operators + role grants); delegated navigation from `/me/admin`; light/dark | tested | UI `/admin/*` | Playwright `m5-tenant-admin`, `m5-authz-admin` (incl. Dave delegation + escalation refusal), `m5-installation`: 34/34 with axe WCAG 2.1 AA on every page and dialog and zero CSP violations; vitest 61 (M5) |
| Admin | Installation role grant/revoke (owner, step-up, last owner kept), user substring search, backup-login lockout status | tested | API `/installation/operators`, `/users?q=`, `/users/{u}` | `TestOperatorRoleManagement`, `TestBackupLoginAndDoSIsolation` (M5) |
| Automation | Automation tokens, Terraform provider | planned | — | M6 |
| Events | Outbox → pulse | planned | — | M6 |
| Backups | age + MinIO backup/restore | planned | — | M6 |
| Backups | Real S3 providers | not verified | — | — |
| Edge | Trusted-proxy client IP (right-to-left XFF), Cloudflare `CF-Connecting-IP` only from CF ranges, security headers + CSP nonce | tested | — | `internal/httpx` spoofing table (16 cases), audit records trusted IP (M1) |
| Edge | Real Cloudflare | not verified | — | — |
| Deploy | Container image (distroless, nonroot, 29 MB), production compose (read-only rootfs, cap_drop ALL), systemd unit, demo stack (Caddy + fake Google + demo-app + whoami) | tested (manual) | `deploy/` | `docker build`, compose `up --wait` healthy, demo `up.sh` sign-in via curl, systemd 257 in a container (`systemd-analyze security` 1.4) (M4); not on a bare Linux host |
| Release | Acceptance script, release workflow | planned | — | M7 |
| API | Management API conventions: RFC 9457 problems with stable codes, cursor pagination, ETag/If-Match, provenance headers, OpenAPI 3.1 committed | tested | `/api/v1` | path-param binding + auth-required spec tests (M1) |
| API | `Idempotency-Key` on creates | planned | — | M6 (with automation tokens) |
