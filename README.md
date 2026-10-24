# Porch

Self-hosted identity and single sign-on for families, friend groups and homelabs — a deliberately smaller
"simplified Authentik" in one Go binary with SQLite.

- **OIDC provider** for your apps (authorization code + PKCE, RFC 9068 JWT access tokens, rotating refresh tokens).
- **Google / Google Workspace federation** with domain-based enrollment from the validated `hd` claim.
- **Strict local backup login** (password + your own titled recovery answers) with aggressive lockout.
- **Multi-tenant**: one installation hosts several families/groups with database-enforced isolation and explicit app sharing.
- **RBAC + ABAC** (roles, bundles, nested groups, `expr` conditions, deny policies, explain + simulator).
- **Forward-auth** outpost for Caddy / Traefik / nginx.
- **Terraform provider**, management API (OpenAPI 3.1), encrypted S3 backups, audit log, events to
  [pulse](https://github.com/aurimasniekis/go-pulse).

> **Status: under construction (pre-alpha).** Nothing here is production-ready yet. The table below is the honest state;
> see [docs/IMPLEMENTATION_MATRIX.md](docs/IMPLEMENTATION_MATRIX.md) for evidence per feature.

| Milestone | Scope | Status |
|---|---|---|
| M0 | Foundations, design docs | done |
| M1 | Store, keyring, tenancy, audit, bootstrap | planned |
| M2 | Google login, sessions, backup login | planned |
| M3 | OIDC provider, demo app | planned |
| M4 | Applications, portal, forward-auth | planned |
| M5 | Admin UI, policy tooling | planned |
| M6 | Terraform, pulse, backups, hardening | planned |
| M7 | Interop, release prep | planned |

Not verified against real external systems: Google, S3 providers other than MinIO, Cloudflare.

## Documentation

- Engineering: [docs/](docs/) — [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md),
  [decisions](docs/DECISIONS.md), [flows](docs/FLOWS.md), [schema](docs/SCHEMA.md), [plan](docs/PLAN.md).
- User/operator site: [site/](site/) (VitePress; `make site`).

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
