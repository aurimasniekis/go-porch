# Integration matrix

How common self-hosted applications connect to Porch. **Only the rows marked _tested_ were exercised against Porch**
by its automated suites; every other row is a configuration sketch based on the application's own documentation and
has **not been verified** with Porch. Check the application's current documentation before relying on it.

| Application | How | Porch application | Status |
|---|---|---|---|
| `examples/demo-app` (Go, go-oidc) | OpenID Connect, code + PKCE, RFC 9068 access token for an API | `kind: oidc`, confidential, `audiences` | **tested** (Playwright `m3-demo-app`, conformance-style checks) |
| `whoami` behind Caddy `forward_auth` | Forward-auth, identity headers | `kind: forward_auth`, `hosts` | **tested** (`deploy/demo` via curl; Playwright through `test/fwdproxy`) |
| Any OIDC client library | OpenID Connect Basic/Config OP | `kind: oidc` | **tested** against the OpenID conformance suite (local run, not certification; see `test/conformance`) |
| Traefik `ForwardAuth`, nginx `auth_request` | Forward-auth | `kind: forward_auth` | not tested (same `/outpost/auth` contract as Caddy) |
| Grafana | Generic OAuth (OIDC) | `kind: oidc`, redirect `https://grafana.example.com/login/generic_oauth`; map roles from the `porch.roles` claim | not tested |
| Nextcloud | `user_oidc` app | `kind: oidc` | not tested |
| Forgejo / Gitea | OpenID Connect authentication source | `kind: oidc`, discovery URL | not tested |
| Immich | OAuth settings (OIDC) | `kind: oidc`, mobile redirect `app.immich:///oauth-callback` needs a native client | not tested |
| Proxmox VE | OpenID Connect realm | `kind: oidc` | not tested |
| Home Assistant | No built-in OIDC; protect with forward-auth (the app still has its own login) | `kind: forward_auth` | not tested |
| Jellyfin | Third-party SSO plugin (not maintained by Jellyfin); native TV and mobile clients do not support OIDC — use Quick Connect from a browser session | `kind: oidc` for the plugin | not tested |

## Patterns

- **Prefer OpenID Connect** when the application supports it: it gets a verified identity and optional claims
  (`email`, `porch.roles`, `porch.groups` per the application's disclosure settings).
- **Forward-auth** protects applications without OIDC, but the application cannot tell who the user is unless it reads
  the identity headers, and anything that reaches the backend without passing through the proxy is unprotected
  ([forward-auth guide](/operators/forward-auth)).
- **Shared services** (one Jellyfin for several families): register the application in the owning tenant and share it
  with the other tenants; tokens and headers name the tenant through which access was granted (`porch.tenant`).
