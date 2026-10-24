# Porch demo app

A small OpenID Connect relying party that signs you in through Porch and shows exactly what Porch issued. It is used
for interop testing, the demo Docker stack and the acceptance demo. It is an example, not a production session layer:
sessions are kept in memory and are lost on restart.

## What it shows

After signing in, the start page shows:

- **Summary**: name, `sub`, email and tenant (from the namespaced `porch.tenant` claim), token expiry, and whether a
  refresh token was issued (the refresh token itself is never displayed).
- **ID token claims**, pretty-printed after full verification: signature against Porch's JWKS (ES256 or RS256), `iss`,
  `aud`, `exp`, `nonce` and, when present, `at_hash`.
- **Access token**: Porch issues RFC 9068 JWT access tokens. The demo decodes the header and claims and labels them
  "decoded, verified by signature against Porch JWKS" only when every check passes: signature (ES256/RS256 only), header
  `typ` is `at+jwt`, `iss` is the issuer, `aud` contains the expected audience (`DEMO_RESOURCE` if set, otherwise the
  client ID) and the token is not expired. Each check is listed with pass/FAIL. A non-JWT access token is shown as
  "opaque" instead of failing.
- **UserInfo response** from the `userinfo_endpoint`, discarded if its `sub` differs from the ID token's.
- **Refresh tokens** (button): uses the refresh token, shows the new tokens and says whether Porch rotated the refresh
  token. A rejected refresh token (`invalid_grant`, for example after a rotated token was reused and Porch revoked the
  family) is dropped.
- **Sign out** (button): clears the local session and redirects to Porch's `end_session_endpoint` with `id_token_hint`,
  `client_id` and, when `DEMO_POST_LOGOUT_URL` is set, `post_logout_redirect_uri` and `state`.

## Security behaviour

- Authorization code flow with PKCE S256, a `nonce` and a `state`, all generated per sign-in and kept server-side
  (keyed by a random session cookie, valid for 10 minutes and single use).
- The callback checks `state` (constant time), the RFC 9207 `iss` parameter (must equal `PORCH_ISSUER`; a missing `iss`
  is refused when discovery advertises `authorization_response_iss_parameter_supported`), and reports `error` responses.
- The code is exchanged with `client_secret_basic`; the ID token is verified with go-oidc and its nonce compared in
  constant time. The session ID is rotated after sign-in.
- Cookies are `HttpOnly`, `SameSite=Lax` and `Secure` (named `__Host-porch_demo`) unless `DEMO_INSECURE_COOKIES=true`
  (then `porch_demo`, for plain-http localhost only).
- POST forms carry a per-session CSRF token checked in constant time; a cross-origin `Origin` header is refused.
- Strict CSP (`default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' <issuer origin>`), no
  inline styles or scripts, no external assets, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- Tokens are never logged. Logs are JSON (`log/slog`) on stderr.

## Configuration

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `PORCH_ISSUER` | yes | | Porch issuer URL, exactly as in the discovery document (e.g. `https://porch.example.com`). |
| `DEMO_CLIENT_ID` | yes | | The application's `client_id`. |
| `DEMO_CLIENT_SECRET` | yes | | The application's `client_secret` (shown once at registration). |
| `DEMO_REDIRECT_URL` | no | `http://localhost:9090/callback` | Registered redirect URI; the path must be `/callback`. |
| `DEMO_POST_LOGOUT_URL` | no | | Registered post-logout redirect URI (e.g. `http://localhost:9090/`). Without it Porch shows its own signed-out page. |
| `DEMO_RESOURCE` | no | | RFC 8707 `resource` sent on the authorization and token requests; becomes the access token `aud`. Must be one of the application's registered audiences. |
| `DEMO_SCOPES` | no | `openid profile email offline_access groups` | Space-separated scopes; must include `openid`. `offline_access` requests a refresh token. |
| `DEMO_LISTEN` | no | `127.0.0.1:9090` | Listen address. |
| `DEMO_CA_FILE` | no | | PEM file trusted in addition to the system roots when talking to Porch (self-signed test setups). |
| `DEMO_INSECURE_COOKIES` | no | `false` | Allow non-`Secure` cookies, for plain-http localhost. |

The app fails fast with a list of every configuration problem. At startup it retries OIDC discovery for about a minute,
so it can start before Porch in a Docker stack.

Routes: `/`, `GET /login`, `GET /callback`, `POST /refresh`, `POST /logout`, `GET /healthz`, `GET /static/app.css`.

## Register the demo app in Porch

Create an OIDC application in a tenant through the management API, authenticated as a tenant admin (in the current
milestone: the browser session cookie `__Host-porch_session` plus the session's CSRF token in `X-Porch-CSRF`; bearer
tokens for automation arrive in M6):

```sh
curl -sS -X POST "https://porch.example.com/api/v1/tenants/acme/applications" \
  -H 'Content-Type: application/json' \
  -H "Cookie: __Host-porch_session=$PORCH_SESSION" \
  -H "X-Porch-CSRF: $PORCH_CSRF" \
  -d '{
    "slug": "demo-app",
    "name": "Demo app",
    "kind": "oidc",
    "client": {
      "client_type": "confidential",
      "redirect_uris": ["http://localhost:9090/callback"],
      "post_logout_redirect_uris": ["http://localhost:9090/"],
      "grant_types": ["authorization_code", "refresh_token"],
      "audiences": ["https://api.example.com"]
    },
    "disclosure": {"email": true, "groups": true, "roles": true, "entitlements": false}
  }'
```

The response contains `client_id` and, **only this once**, `client_secret`. Store the secret now.

## Run it

From the repository root:

```sh
PORCH_ISSUER=https://porch.example.com \
DEMO_CLIENT_ID=<client_id from the response> \
DEMO_CLIENT_SECRET=<client_secret from the response> \
DEMO_REDIRECT_URL=http://localhost:9090/callback \
DEMO_POST_LOGOUT_URL=http://localhost:9090/ \
DEMO_RESOURCE=https://api.example.com \
DEMO_INSECURE_COOKIES=true \
go run ./examples/demo-app
```

Open <http://localhost:9090/> and choose **Sign in with Porch**. Use `localhost` (not `127.0.0.1`) in the browser so
the host matches the registered redirect URI and the session cookie is sent back on the callback.

If Porch uses a self-signed certificate, add `DEMO_CA_FILE=/path/to/porch-ca.pem`.

## Tests

```sh
go test -race ./examples/demo-app
```

The tests run the whole flow against `internal/idp/fakeidp`, wrapped to add the Porch features it lacks (userinfo,
end_session, RFC 9207 metadata, rotating refresh tokens and optional RFC 9068 JWT access tokens). They cover sign-in,
opaque and JWT access tokens, state, `iss`, nonce and audience mismatches, authorization errors, single-use callbacks,
refresh rotation and rejected refresh tokens, CSRF, logout, security headers, secure cookies, configuration and `DEMO_CA_FILE`.
