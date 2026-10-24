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
| Platform | Store, keyring, audit, ids, config | planned | — | M1 |
| Platform | Listeners, health, metrics | planned | — | M1 |
| Bootstrap | Setup token → first operator | planned | — | M1 |
| Tenancy | Tenants, users, memberships | planned | — | M1 |
| Login | Google federation (fake IdP) | planned | — | M2 |
| Login | Google federation (real Google) | not verified | — | — |
| Login | Domain rules / JIT / invites | planned | — | M2 |
| Login | Backup login (password + titled answers) | planned | — | M2 |
| Sessions | Sessions, step-up, epochs, recheck | planned | — | M2 |
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
| Edge | Cloudflare AOP / CF-IP trust | planned | — | M1/M6 |
| Edge | Real Cloudflare | not verified | — | — |
| Release | Acceptance script, release workflow | planned | — | M7 |
