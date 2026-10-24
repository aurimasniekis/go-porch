# Connect an application (OpenID Connect)

Most self-hosted apps can sign users in with "generic OAuth2 / OpenID Connect". Register the app in Porch, then copy
three values into the app.

```mermaid
sequenceDiagram
  participant U as Browser
  participant A as App
  participant P as Porch
  U->>A: open app
  A-->>U: redirect to Porch /oauth2/authorize (PKCE)
  U->>P: sign in (Google or backup login)
  P-->>U: redirect back with code (+ iss)
  A->>P: POST /oauth2/token (code + verifier + secret)
  P-->>A: ID token, access token, refresh token
```

## 1. Register

As an installation admin (UI coming in M5; API today):

```http
POST /api/v1/tenants/smith/applications
Content-Type: application/json

{
  "slug": "grafana",
  "name": "Grafana",
  "kind": "oidc",
  "client": {
    "redirect_uris": ["https://grafana.example.com/login/generic_oauth"],
    "post_logout_redirect_uris": ["https://grafana.example.com/login"],
    "grant_types": ["authorization_code", "refresh_token"]
  },
  "disclosure": { "email": true, "groups": true, "roles": true, "entitlements": false }
}
```

The response contains `client.client_id` and — **only this once** — `client_secret`.

## 2. Configure the app

| Setting | Value |
|---|---|
| Issuer / discovery | `https://auth.example.com` (`/.well-known/openid-configuration`) |
| Client ID / secret | from step 1 |
| Scopes | `openid profile email` (+ `offline_access` for refresh tokens, `groups` for group slugs) |
| PKCE | S256 (required by default) |
| Signing algorithm | ES256 (set `signing_alg: RS256` on the client for apps that only support RSA) |

## What the app receives

- `sub`: a stable Porch user ID (`u_…`) — never an email.
- `email`, `email_verified`, `name` per scopes and the app's disclosure settings.
- `porch`: `{ "v": 1, "tenant": { "id": "ten_…", "slug": "smith" }, "roles": [ … ], "groups": [ … ] }`.
- Access tokens are JWTs with `typ: at+jwt` (RFC 9068) whose `aud` is the API you asked for with `resource`, or the
  client ID. Validate them against `/jwks`.

Rules worth knowing: redirect URIs match exactly; codes are single-use (reusing one revokes the tokens it produced);
refresh tokens rotate and reusing an old one revokes the whole chain; users must be members of the app's tenant.

A runnable demo app lives in `examples/demo-app`.
