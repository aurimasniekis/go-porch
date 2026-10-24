# Integration matrix

How common self-hosted applications connect to Porch. Rows marked _tested_ are covered by Porch's automated suites;
the others are configuration examples based on each application's own documentation, so check its current
documentation for the exact setting names.

| Application | How | Porch application | Status |
|---|---|---|---|
| `examples/demo-app` (Go, go-oidc) | OpenID Connect, code + PKCE, RFC 9068 access token for an API | `kind: oidc`, confidential, `audiences` | **tested** (Playwright `m3-demo-app`, conformance-style checks) |
| `whoami` behind Caddy `forward_auth` | Forward-auth, identity headers | `kind: forward_auth`, `hosts` | **tested** (`deploy/demo` via curl; Playwright through `test/fwdproxy`) |
| Any OIDC client library | OpenID Connect Basic/Config OP | `kind: oidc` | **tested** against the OpenID conformance suite (local run, not certification; see `test/conformance`) |
| Traefik `ForwardAuth`, nginx `auth_request` | Forward-auth | `kind: forward_auth` | example (same `/outpost/auth` contract as Caddy) |
| Grafana | Generic OAuth (OIDC) | `kind: oidc`, redirect `https://grafana.example.com/login/generic_oauth`; map roles from the `porch.roles` claim | example |
| Nextcloud | `user_oidc` app | `kind: oidc` | example |
| Forgejo / Gitea | OpenID Connect authentication source | `kind: oidc`, discovery URL | example |
| Immich | OAuth settings (OIDC) | `kind: oidc`, mobile redirect `app.immich:///oauth-callback` needs a native client | example |
| Proxmox VE | OpenID Connect realm | `kind: oidc` | example |
| Home Assistant | No built-in OIDC; protect with forward-auth (the app still has its own login) | `kind: forward_auth` | example |
| Jellyfin | Third-party SSO plugin (not maintained by Jellyfin); native TV and mobile clients do not support OIDC — use Quick Connect from a browser session | `kind: oidc` for the plugin | example |

## Patterns

- **Prefer OpenID Connect** when the application supports it: it gets a verified identity and optional claims
  (`email`, `porch.roles`, `porch.groups` per the application's disclosure settings).
- **Forward-auth** protects applications without OIDC, but the application cannot tell who the user is unless it reads
  the identity headers, and anything that reaches the backend without passing through the proxy is unprotected
  ([forward-auth guide](/operators/forward-auth)).
- **Shared services** (one Jellyfin for several families): register the application in the owning tenant and share it
  with the other tenants; tokens and headers name the tenant through which access was granted (`porch.tenant`).
