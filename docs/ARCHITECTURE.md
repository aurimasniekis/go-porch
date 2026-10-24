# Architecture

Porch is a **modular monolith**: one Go binary (`porch`), one SQLite database, one key-encryption key (KEK) file.
Modules are Go packages under `internal/` with explicit dependencies; there is no network hop between them.

## Context

```mermaid
flowchart LR
  subgraph Users
    U[Family / friends / homelab users]
    A[Admins]
  end
  subgraph Edge
    CF["Cloudflare (optional)"]
    RP[Reverse proxy<br/>Caddy / Traefik / nginx]
  end
  subgraph Porch host
    P[porch serve]
    DB["(SQLite)"]
    K[[KEK file 0400]]
  end
  G[Google OIDC / Workspace]
  APPS[OIDC apps<br/>Grafana, demo-app, …]
  FA[Forward-auth apps<br/>whoami, dashboards]
  PL[pulsed + NATS]
  S3["(S3 / MinIO)"]
  TF[Terraform]
  OS[OpenSearch / log shipper]
  PR[Prometheus]

  U --> CF --> RP --> P
  A --> RP
  P --> DB
  P --> K
  P -- upstream OIDC --> G
  APPS -- OIDC code + PKCE --> P
  RP -- forward_auth --> P
  RP --> FA
  P -- outbox relay --> PL
  P -- age-encrypted backups --> S3
  TF -- /api/v1 automation token --> P
  P -- JSONL logs + audit --> OS
  PR -- 127.0.0.1:9464/metrics --> P
```

## Listeners

| Listener | Default | Serves |
|---|---|---|
| Public | `127.0.0.1:8080` (TLS optional, client-cert CA for Cloudflare Authenticated Origin Pulls) | Login/consent portal, user portal, admin UI, `/api/v1`, OIDC provider (`/.well-known/openid-configuration`, `/oauth2/*`, `/jwks`), forward-auth outpost (`/outpost/*`), per-app callbacks |
| Management | `127.0.0.1:9464` | `/metrics`, `/healthz`, `/readyz`, optional pprof (off by default) |

## Packages

```mermaid
flowchart TB
  subgraph edges[Edges]
    mgmtapi[mgmtapi<br/>Huma /api/v1]
    portal[portal<br/>login, consent, launcher]
    oidcop[oidcop<br/>zitadel op.Storage]
    forwardauth[forwardauth<br/>/outpost]
    webui[webui<br/>embedded SPA]
  end
  subgraph domain[Domain]
    tenancy
    identity
    idp[idp<br/>upstream providers, google, domain rules, dirsync]
    localauth[localauth<br/>backup credential, lockout, wordlist]
    session[session<br/>browser sessions, step-up, epochs]
    authz[authz<br/>graph, expr policies, evaluator, explain, cache]
    serviceacct
  end
  subgraph platform[Platform]
    store[store + migrations + sqlc db]
    keyring
    audit
    outbox
    jobs
    backup
    httpx[httpx<br/>client IP, headers, CSRF, limits]
    obs[obs<br/>log, metrics, health, redact]
    config
  end
  mgmtapi --> domain
  portal --> domain
  oidcop --> domain
  forwardauth --> domain
  domain --> platform
  outbox --> pulse["(pulse NATS)"]
  backup --> s3["(S3)"]
```

Rules:

- Domain packages never import edge packages. Edges never touch `store/db` directly for writes; they call domain services.
- Every write goes through `store.Writer.Tx` (single writer, `BEGIN IMMEDIATE`). Audit events and outbox rows are appended
  **inside the same transaction** as the change they describe.
- Transaction callbacks perform no network I/O, sleeps or channel operations (enforced by the `txscope` analyzer).
- Tenant-scoped repository functions take a `tenancy.Scope`, which can only be constructed after a membership/share check.

## Data flow of a write

```mermaid
sequenceDiagram
  participant C as Client (UI / Terraform)
  participant H as httpx middleware
  participant A as mgmtapi handler
  participant Z as authz evaluator
  participant S as domain service
  participant W as store.Writer (BEGIN IMMEDIATE)
  C->>H: POST /api/v1/... (cookie + CSRF or automation token)
  H->>H: client IP, body limit, Origin + CSRF, rate limit
  H->>A: request + principal
  A->>Z: check(principal, permission, resource)
  Z-->>A: allow + explain trace
  A->>S: command
  S->>W: Tx(fn)
  W->>W: mutate rows, bump version / authz_epoch
  W->>W: audit.Append (hash chain)
  W->>W: outbox.Enqueue (ULID)
  W-->>S: commit
  S-->>A: result
  A-->>C: 201 + ETag
  Note over W: after commit: relay wakes and publishes to pulse
```

## Persistence

- SQLite via `modernc.org/sqlite` (pure Go, `CGO_ENABLED=0`), WAL, `synchronous=FULL`, `foreign_keys=ON`, `trusted_schema=OFF`.
- Times are stored as UTC Unix microseconds (`INTEGER`). IDs are `<prefix>_<26 Crockford base32>` encoding UUIDv7.
- Secrets at rest are sealed with keyring purpose keys (AES-256-GCM, AAD = `table|column|row-id`); token lookups use
  HMAC-SHA-256 under the `token` purpose key, never plain SHA-256 of a low-entropy value.
- Schema: see [SCHEMA.md](SCHEMA.md).

## Tenancy model

One **installation** contains many **tenants** (a family, a friend group, a homelab). Users are installation-wide
identities; they join tenants through **memberships**. Applications, groups, roles, resources, policies and assignments
are tenant-scoped. Installation **operators** are a separate concept (table `installation_role_assignments`): tenant
roles never confer installation capabilities, and installation roles do not silently grant tenant data access
(operators act on tenants through explicit, audited operations).

Isolation is **logical** (same process, same database, same KEK) and enforced in the schema with composite foreign keys
`(tenant_id, id)`. It protects tenants from each other's admins and from application bugs that pass a wrong ID; it is
not a boundary against host compromise or a bug in Porch's own authorization code. See ADR-0004.

## Time and background work

- `jobs` (leased SQLite queue) runs: session cleanup, domain-rule re-evaluation, federated `prompt=none` recheck
  scheduling, directory sync, signing-key rotation, keyring reseal, audit retention, backup schedule, outbox relay wakeups.
- The outbox relay is a single goroutine; it never blocks request handling.

## Failure behaviour

| Dependency down | Effect |
|---|---|
| Google | New federated logins fail; existing sessions continue until their next upstream recheck (≤ 1 h), then end. Local backup login works. |
| pulsed / NATS | Events queue in the outbox; alert after backlog age threshold. Logins unaffected. |
| S3 | Backup runs fail and alert; nothing else affected. |
| Disk full | Storage health degrades, `readyz` fails, new sessions/tokens refused (fail closed). |
| KEK missing / wrong | Startup refused (canary mismatch). |
