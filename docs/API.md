# API boundaries

Porch exposes four HTTP surfaces on the public listener and one on the management listener. Each has its own
authentication, CSRF and caching rules.

| Surface | Paths | Authenticates with | CSRF | Caching | CORS |
|---|---|---|---|---|---|
| Portal (HTML/SPA) | `/`, `/login/*`, `/consent`, `/apps`, `/account/*`, `/admin/*` | Session cookie `__Host-porch_session` | Origin check + HMAC token on POST forms | `no-store` on auth pages | none |
| Management API | `/api/v1/*` | Session cookie (+ `X-Porch-CSRF`) **or** `Authorization: Bearer porch_at_…` | Cookie requests: Origin + `X-Porch-CSRF`; bearer requests: none (no ambient credential) | `no-store` | none |
| OIDC provider | `/.well-known/openid-configuration`, `/jwks`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/revoke`, `/oauth2/introspect`, `/oauth2/end_session` | Client auth (secret / none+PKCE), access tokens, session for authorize | `state` / PKCE | `no-store` on token/userinfo | discovery, JWKS, token, userinfo, revoke for registered SPA origins only |
| Forward-auth outpost | `/outpost/auth`, `/outpost/start`, `<app-host>/.porch/callback` | Host-only `__Host-porch_fa` cookie per app host | one-time code bound to host | `no-store` | none |
| Management listener | `/metrics`, `/healthz`, `/readyz`, `/debug/pprof/*` (opt-in) | network position (loopback) | n/a | n/a | none |

## Management API conventions (`/api/v1`)

- OpenAPI 3.1 generated from code (`porch openapi > api/openapi.json`), committed and drift-checked.
- Errors: RFC 9457 `application/problem+json` with stable `code` (`validation_failed`, `not_found`, `conflict`,
  `forbidden`, `precondition_failed`, `reauth_required`, `rate_limited`, …) and `fields[]` for validation.
- Pagination: `?limit=` (≤ 200) and opaque `?cursor=`; responses `{ items, next_cursor }`.
- Concurrency: every mutable resource returns `ETag: "<version>"`; `PUT`/`PATCH`/`DELETE` honour `If-Match`
  (Terraform always sends it).
- Idempotency: `Idempotency-Key` on `POST` creates (24 h). A replay of a response that contained a secret returns
  `409 idempotent_secret_withheld` with the resource location instead of the secret.
- Provenance: `managed_by`, `last_changed_by`, `updated_at` on every resource; requests may send `X-Porch-Managed-By:
  terraform`.
- Tenant-scoped paths: `/api/v1/tenants/{tenant}/…` where `{tenant}` is id or slug. Installation paths:
  `/api/v1/installation/…`.
- Step-up: operations listed in ADR-0010 return `403 reauth_required` when `auth_time` is older than 5 minutes.
- Authorization decision API: `POST /api/v1/tenants/{tenant}/authz/check` and `/authz/check-batch`, returning
  `{allowed, reason, trace}`.
- Delegated administration (ADR-0038): each tenant-scoped operation needs one tenant permission; callers without it
  get `404` (same as a missing tenant). Granting more than you hold returns `403 privilege_escalation` with the missing
  permissions in `fields`. `GET /api/v1/me/admin` lists what the caller can administer.
- Authorization model: `/tenants/{t}/roles`, `/groups` (+ `/members/{user}`, `/parents/{parent}`), `/resources`,
  `/policies` (+ `/validate`), `/assignments`, `/permissions`, `/authz/effective`.
- Service accounts (ADR-0037): `/tenants/{t}/service-accounts` (+ `/rotate-secret`); tokens from `/oauth2/token` with
  `grant_type=client_credentials`.
- Operations (ADR-0039): `/audit`, `/tenants/{t}/audit`, `/sessions`, `/users/{u}/revoke-sessions`,
  `/installation/health`.

## What is deliberately not exposed

- No endpoint that returns secrets after creation (client secrets, automation tokens, recovery answers).
- No remote "lock user's backup login" endpoint (ADR-0008).
- No CORS on the management API.
- No implicit or password grants on the OIDC provider.
