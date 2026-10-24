# Flows

Sequence diagrams for every security-relevant flow. They describe the **intended** design; the implementation status of
each flow is tracked in [IMPLEMENTATION_MATRIX.md](IMPLEMENTATION_MATRIX.md).

## 1. Browser login (entry point)

```mermaid
flowchart TD
  start([GET /login?return_to=…]) --> sess{Valid session?}
  sess -- yes --> ret[Redirect to validated return_to]
  sess -- no --> choose{Method}
  choose -- Google --> g[Upstream OIDC flow §2]
  choose -- Backup login --> b[Backup credential flow §3]
  g --> ok[Create session: rotate token,<br/>record auth_method, auth_time]
  b --> ok
  ok --> tenant{Tenant needed?}
  tenant -- one membership --> ret
  tenant -- several --> chooser[Tenant chooser] --> ret
```

`return_to` must be a same-origin path (`/…`, not `//…`) or a URL on a registered application host.

## 2. Google (upstream OIDC) login and enrollment

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant P as Porch
  participant G as Google
  B->>P: GET /login/google?return_to=/apps
  P->>P: create auth state: state, nonce, PKCE verifier (sealed, 10 min TTL)
  P-->>B: Set-Cookie __Host-porch_oidc=<state-handle>, 302 to Google (code, S256, nonce, hd hint for UX only)
  B->>G: authorize
  G-->>B: 302 /login/google/callback?code&state
  B->>P: callback (cookie + state)
  P->>P: state matches cookie-bound server state? (single use)
  P->>G: token exchange (code + verifier)
  G-->>P: ID token
  P->>P: verify iss, aud, RS256, exp, nonce, email_verified
  P->>P: identity = (provider, iss, sub) — never email
  alt identity known
    P->>P: load user
  else unknown identity
    P->>P: domain rule for validated hd claim? (workspace_hd) or verified email domain (verified_email, opt-in)
    alt rule mode = jit
      P->>P: create user + external identity + membership (source=domain_rule:<id>) + baseline roles
    else invite_only and pending invite matches
      P->>P: consume invite, create user
    else
      P-->>B: generic "not enrolled" page (audited)
    end
  end
  P->>P: re-evaluate domain-derived grants (evidence present?)
  P->>P: session (method=google, auth_time, upstream_checked_at)
  P-->>B: Set-Cookie __Host-porch_session, 302 return_to
  Note over P,G: Hourly: next request after upstream_checked_at+1h triggers prompt=none re-auth, failure ends session
```

## 3. Backup (local) login: password, then titled recovery answers

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant P as Porch
  participant DB as SQLite
  B->>P: POST /login/backup {handle, password}
  P->>P: per-source throttle (IPv4 / IPv6 /64) and installation circuit — reject early if exceeded
  P->>DB: BEGIN IMMEDIATE: reserve attempt (refuse if locked or failures ≥ threshold, else failures += 1) COMMIT
  P->>P: Argon2id(NFKC password) vs sealed PHC (dummy hash for unknown handle)
  alt wrong password / unknown / locked
    P->>DB: failures ≥ threshold → locked_until = now + 6h·2^level (cap 48 h), level++, audit failure
    P-->>B: generic "invalid credentials or temporarily unavailable"
  else password correct
    P->>DB: release this reservation (failures -= 1, level unchanged), create single-use challenge (5 min)
    P-->>B: Set-Cookie __Host-porch_bchal, page with the user's titles (unsealed) and N answer fields
    B->>P: POST /login/backup/answers {answers[]}
    P->>DB: BEGIN IMMEDIATE: consume challenge, reserve attempt (same rules) COMMIT
    P->>P: Argon2id(len-prefixed canonical answers) vs sealed PHC
    alt answers correct
      P->>DB: failures = 0, decay level, session (method=backup), audit success
      P-->>B: 302 return_to
    else wrong
      P->>DB: lock as above, audit failure
      P-->>B: generic failure (back to step 1)
    end
  end
```

Both steps spend from the same attempt budget: a correct password never resets the counter, so it buys no extra answer
guesses. Lockout affects only the backup mechanism; Google login and existing sessions continue.

## 4. OIDC authorize (Porch as provider)

```mermaid
sequenceDiagram
  autonumber
  participant RP as Downstream app
  participant B as Browser
  participant P as Porch OP
  RP-->>B: 302 /oauth2/authorize?client_id&redirect_uri&code_challenge(S256)&scope&state&nonce[&resource]
  B->>P: authorize
  P->>P: client exists, enabled, redirect_uri exact match (loopback port exception for native)
  P->>P: PKCE S256 present (required by default), response_type=code only
  P->>P: store auth request (10 min)
  P-->>B: 302 /login?authRequest=… (if no session or max_age/prompt=login)
  B->>P: login (§1) then resume
  P->>P: choose tenant (client owner tenant or shared tenants where user is a member)
  P->>P: authz: app:access on application in tenant (explain trace audited)
  alt denied
    P-->>B: redirect_uri?error=access_denied&state
  else allowed
    P->>P: issue code (single use, 60 s, bound to tenant + session)
    P-->>B: 302 redirect_uri?code&state&iss
  end
  RP->>P: POST /oauth2/token (code, verifier, client auth)
  P->>P: verify PKCE, client, redirect_uri, mark code used
  P-->>RP: id_token (ES256), access_token (RFC 9068 JWT, aud), refresh_token (opaque, family F)
```

## 5. Refresh token rotation and reuse detection

```mermaid
sequenceDiagram
  participant RP as App
  participant P as Porch
  RP->>P: grant_type=refresh_token (R1)
  P->>P: lookup HMAC(R1): active, family F, not expired, session/security epoch valid, user still allowed
  P-->>RP: new access token + R2, R1 marked rotated
  Note over RP,P: attacker replays stolen R1
  RP->>P: grant_type=refresh_token (R1 again)
  P->>P: R1 already rotated → reuse detected
  P->>P: revoke whole family F (R2 dead), audit porch.oidc.refresh_reuse
  P-->>RP: invalid_grant
```

## 6. Forward-auth (proxy outpost)

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant C as Caddy
  participant P as Porch /outpost
  participant W as whoami (backend)
  B->>C: GET https://app.example.com/
  C->>P: forward_auth GET /outpost/auth (X-Forwarded-Host/Uri/Method, cookie)
  P->>P: app for host? app session cookie (__Host-porch_fa, host-only) valid?
  alt no app session
    P-->>C: 302 https://auth.example.com/outpost/start?rd=https://app.example.com/
    C-->>B: 302
    B->>P: start: login (§1), authz app:access
    P-->>B: 302 https://app.example.com/.porch/callback?code=c1 (one-time, 60 s, bound to host + Porch session)
    B->>C: GET /.porch/callback?code=c1
    C->>P: proxied to Porch
    P-->>B: Set-Cookie __Host-porch_fa_nonce=n (app host) + 302 https://auth.example.com/outpost/confirm?code=c1&n=n
    B->>P: confirm (Porch session cookie must be the one c1 was issued to)
    P-->>B: 302 https://app.example.com/.porch/finish?code=c2 (c2 bound to n)
    B->>C: GET /.porch/finish?code=c2 (nonce cookie)
    C->>P: proxied to Porch
    P->>P: c2 host + nonce must match, set host-only cookie, 302 to original path
  else valid
    P->>P: re-check app:access (authz epoch cache)
    P-->>C: 200 + X-Porch-User, X-Porch-Email, X-Porch-Groups (configured)
    C->>W: request with identity headers (incoming X-Porch-* stripped by Caddy)
  end
```

## 7. Authorization evaluation

```mermaid
flowchart TD
  r([check principal, action, resource, tenant]) --> a{Authenticated?}
  a -- no --> deny1[DENY unauthenticated]
  a -- yes --> t{Tenant gate:<br/>active membership<br/>or explicit share?}
  t -- no --> deny2[DENY tenant_gate]
  t -- yes --> c["Collect grants: direct + groups (nested ≤5)<br/>roles + bundles (≤5), scopes covering resource,<br/>not expired"]
  c --> d{Any deny policy matches<br/>or errors?}
  d -- yes --> deny3[DENY policy]
  d -- no --> g{Any grant with permission<br/>whose condition passes?}
  g -- yes --> allow[ALLOW + matched grant]
  g -- no --> deny4[DENY default]
```

Every decision returns an explain trace (tenant gate result, candidate grants, condition results, deny policies).

## 8. Backup and restore

```mermaid
sequenceDiagram
  participant J as Backup job
  participant S as SQLite
  participant A as age (offline recipient)
  participant M as S3 / MinIO
  J->>S: VACUUM INTO tmp snapshot
  J->>J: manifest {sha256, schema version, key ids, created_at}
  J->>J: s2 compress → age encrypt (recipient only, Porch has no identity)
  J->>J: KEK escrow: age-encrypt KEK to same recipient (toggle)
  J->>M: PUT objects (+ object lock retention if enabled)
  J->>S: backup_runs row, metrics, alert on failure/staleness
```

```mermaid
flowchart LR
  f[Fresh host] --> v[porch backup verify<br/>download + checksum]
  v --> d[porch restore --identity offline.key<br/>decrypt DB + KEK]
  d --> p[place DB + KEK in empty data dir]
  p --> e[bump security_epoch:<br/>all sessions + refresh tokens invalid]
  e --> k[rotate signing keys]
  k --> a[audit restore event]
  a --> o{--invalidate-backup-credentials?}
  o -- yes --> x[require re-enrollment of recovery words]
  o -- no --> done([serve])
  x --> done
```
