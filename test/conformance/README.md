# OpenID conformance suite for Porch

Runs the OpenID Foundation conformance suite (OP tests) locally in Docker against a freshly started Porch:

- `oidcc-basic-certification-test-plan` — server metadata from discovery, static clients, `client_secret_basic`
  (plus the plan's own `client_secret_post` module)
- `oidcc-config-certification-test-plan` — discovery document checks

```sh
test/conformance/run.sh                       # build, start, bootstrap, run both plans, tear down
CONF_SKIP_BUILD=1 test/conformance/run.sh     # reuse test/conformance/.build/{porch,fakegoogle}
CONF_ONLY=oidcc-prompt-login,oidcc-max-age-1 test/conformance/run.sh   # selected modules
CONF_KEEP=1 test/conformance/run.sh           # leave the stack up to inspect logs in the suite UI
```

`run.sh` exits non-zero when any module FAILED or did not finish. Each run writes a work dir
`test/conformance/.work/<timestamp>/` (git-ignored; contains the throwaway TLS key and client secrets) with
`results.json`, `results.md` (the same format as [results-2026-10-24.md](results-2026-10-24.md)), the rendered plan config
and `compose.log`. With `CONF_KEEP=1` the suite UI is at `https://127.0.0.1:<port>/` (printed at the end; self-signed
certificate); stop it with `docker compose -p porch-conformance down -v`.

Requirements: Docker (Desktop or Engine with compose v2), Go, pnpm (web UI build), Python 3 (stdlib only), openssl, curl.
Ports are picked at random on 127.0.0.1; nothing else on the host is touched.

## How it works

| Piece | What |
|---|---|
| `docker-compose.yml` | Suite (`registry.gitlab.com/openid/conformance-suite`, its `nginx` image, `mongo:6.0.13`) and the system under test: `porch-backend` (linux build of `cmd/porch`, development mode, native TLS), `porch` (nginx TLS front, see below), `fakegoogle` (`test/fakegoogle`). All share one compose network, so Porch's issuer `https://porch:8443` is the same URL for the suite's back channel and its headless browser. |
| `run.sh` | Builds `porch`/`fakegoogle` for the Docker VM's architecture, writes `porch.yaml`, a throwaway self-signed cert and the front config, starts the stack, waits for readiness, bootstraps Porch, renders the plan config, runs the plans and writes the summary. |
| `bootstrap.py` | Management API, as an operator would: first-time setup with the setup token (issued by `porch admin setup-token` before `porch serve`), the fake Google provider, tenant `smith` with a `workspace_hd`/`jit` rule for `smith.example`, and three confidential OIDC applications (`client`, `client2`, `client_secret_post` in the suite's config) with the suite's redirect URI and `require_pkce: false`. |
| `config/porch-oidcc.json` | Suite plan configuration (alias `porch`) incl. the browser automation. |
| `run_plans.py` | Stdlib-only stand-in for the suite's `scripts/run-test-plan.py`: creates the plans through the REST API, runs every module sequentially, collects results and FAILURE/WARNING log entries. |
| `summarize.py` | Renders the results as Markdown. |

### TLS

Porch runs with `http.tls_cert_file`/`tls_key_file` and a self-signed certificate for `porch`. The suite does not verify
OP certificates: its back-channel client uses a trust-all trust manager and HtmlUnit accepts self-signed certificates;
no truststore changes are needed. `public_url` is `https://porch:8443`, accepted by development mode.

### Login automation

Users sign in to Porch only through an upstream provider. The suite's browser is HtmlUnit, driven by the `browser`
section of the plan config, and it has to get through Porch's sign-in without a human:

1. An unauthenticated authorize request ends at the SPA page `/login?return_to=/oauth2/continue?ar=…`. **HtmlUnit does
   not run Porch's SPA** (Vite ES-module bundle; observed: waiting 15 s for the "Continue with Google" link times out on
   an empty `<div id="root">`, `CONF_LOGIN_SHIM=0` reproduces it). The browser commands can only click/type/wait, not
   navigate.
2. So the `porch` service is an nginx TLS front that proxies everything to Porch unchanged except one thing (the "login
   shim", `front.conf.tmpl`): `GET /login?return_to=<path>` without `stepup`/`error` gets a `302` to
   `/login/google?return_to=<path>` — the exact href of the SPA's "Continue with Google" button. Everything after that
   is Porch's own server-side flow (state cookie, upstream PKCE, callback, session, step-up, consent-free code issue).
3. Fake Google shows its plain-HTML account picker; the browser clicks "Ada Smith" (`//button[@value='ada']`). Ada has
   `hd=smith.example`, so Porch's domain rule enrolls her on first sign-in.
   `test/fakegoogle` also has `-auto-login <subject>` (sets the fake IdP's `Current`) to skip the picker; the
   conformance stack does not use it because `oidcc-prompt-login` and `oidcc-max-age-1` need a sign-in page during the
   second authorization to upload as their screenshot.
4. Tests whose correct outcome is an error page shown by Porch (`oidcc-ensure-registered-redirect-uri`,
   `oidcc-ensure-request-object-with-redirect-uri`) have per-test browser overrides that upload Porch's error response
   as the screenshot; the suite then marks them REVIEW (a human must look at the image — that is expected for
   certification too).

### Pacing

Porch rate-limits sign-in starts (`GET /login/{provider}`) per source IP: burst 10, 30/min
(`internal/app/http.go`, portal `Limiter`). Every browser request of the suite comes from one container IP and every
module starts with a fresh browser, so back-to-back modules exhaust the bucket and Porch answers
`429 too many login attempts` (in the first, unpaced full run 12 consecutive modules were interrupted within ~0.1 s;
the ones inspected had hit this 429). `run_plans.py` waits 4 s
before each module (`--pace`). This is the limiter working as designed, not a protocol problem.

## What Porch supports (and how the suite treats the rest)

Supported: authorization code flow (`response_type=code`, `response_mode=query`), discovery, JWKS, `client_secret_basic`
and `client_secret_post`, userinfo (GET/POST, header/body token), nonce, state, `iss` in the authorization response
(RFC 9207), PKCE S256, `prompt=none|login`, `max_age`, refresh tokens with rotation, code replay revocation.

Not supported (by design): request objects (`request`, `request_uri`), the `claims` request parameter, implicit and
hybrid flows, dynamic client registration, `address`/`phone` scopes. The suite skips or tolerates these:
`oidcc-scope-address`, `-phone`, `-all` are SKIPPED (not in `scopes_supported`);
`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` is SKIPPED (Porch answers
`request_not_supported`, which the test accepts); `oidcc-claims-essential` passes with a WARNING (`name` not in userinfo,
because the `claims` parameter is ignored and only `openid` was requested); `oidcc-idtoken-signature`, `oidcc-idtoken-unsigned` and the
`request_uri` test are not part of the plan with static clients (the suite marks them not applicable; they need dynamic
registration). Implicit/hybrid/dynamic plans are not run.

## Latest full run (M7, after the security-review fixes)

[results-2026-10-24-m7.md](results-2026-10-24-m7.md): Basic plan 21 PASSED, 6 WARNING, 4 REVIEW, 4 SKIPPED, **0 FAILED**;
Config plan 1 PASSED. The warnings and REVIEW items are the ones diagnosed below (REVIEW = protocol checks passed, a
human must look at the screenshot).

## Results (2026-10-24)

Porch `1d9ea3c` (M3, development mode) + this directory; conformance suite 5.3.3 (`f237360`, image `latest` pulled
2026-10-24); zitadel/oidc v3.51.16. Full output: [results-2026-10-24.md](results-2026-10-24.md).

| Plan | Variant | PASSED | WARNING | REVIEW | SKIPPED | FAILED |
|---|---|---|---|---|---|---|
| oidcc-basic-certification-test-plan | discovery, static_client (client_secret_basic) | 21 | 6 | 3 | 4 | 1 |
| oidcc-config-certification-test-plan | discovery, static_client | 1 | 0 | 0 | 0 | 0 |

The one FAILED module was a Porch bug (below). It is **fixed** and the affected modules were re-run against the fixed
build the same day (`CONF_ONLY=oidcc-prompt-login,oidcc-max-age-1,oidcc-max-age-10000`):

| Module | Before | After fix |
|---|---|---|
| `oidcc-prompt-login` | FAILED | REVIEW (protocol checks passed; screenshot of the second sign-in awaits a human) |
| `oidcc-max-age-1` | REVIEW | REVIEW (same) |
| `oidcc-max-age-10000` | PASSED | PASSED |

Effective basic-plan totals with the fix: 22 PASSED-or-REVIEW-pending, 0 FAILED. The `preferred_username` gap below is
also fixed (dropped from `claims_supported`); the full plan has not been re-run since, so that warning's removal is not
yet recorded by the suite.

### Failures and warnings, diagnosed

**FAILED — `oidcc-prompt-login`: Porch bug (endless step-up loop) — fixed.** The suite's message is only
"WebRunner unexpected url for task: Verify Complete": after the second authorization (`prompt=login`) the browser ends
on the upstream sign-in page again instead of the client callback. Reproduced with curl inside the network: the
step-up callback rotates the session (new session ID, fresh `auth_time`), then `/oauth2/continue` immediately
redirects to `/login/google?intent=stepup` again, forever.
Cause: zitadel/oidc's `op.Server` HTTP layer (`pkg/op/server_http.go:270`, `ValidateAuthReqPrompt`) rewrites
`max_age` to `0` whenever `prompt` contains `login`. `Provider.Authorize` (`internal/oidcop/provider.go`) stores that
as `auth_requests.max_age = 0`, and `needsReauth` (`internal/oidcop/continue.go`) then requires
`now - auth_time <= 0s`, which can never hold after a real round trip (`auth_time` has 1 s granularity and time
passes). The same loop hits any client sending `max_age=0`, and small `max_age` values are timing-dependent
(`oidcc-max-age-1` passed here only because the re-login finished within the same second boundary).
`TestPromptAndMaxAge` (`internal/app/oidc_test.go`) does not catch it because the fake clock does not move between
the upstream login and `/oauth2/continue`.
Fix applied (`needsReauth`, `internal/oidcop/continue.go`): a session created at or after the authorization request
satisfies `prompt=login` and any `max_age`; otherwise `max_age` is checked as `auth_time >= request_created - max_age`.
Original suggestion: evaluate `max_age` against the time of the authorization request, at second granularity:
`needsReauth` returns true for max_age only if `sess.AuthTime.Unix() < domain.FromMicros(ar.CreatedAt).Unix() - max_age`
(OIDC Core 3.1.2.1: "the allowable elapsed time … since the last time the End-User was actively authenticated" —
a login that happened after the request satisfies any `max_age`, including 0). Keep the existing
`ReauthSessionID`/freshness logic for `prompt=login`. Add a test step that advances the fake clock by ≥ 1 s before
returning to `/oauth2/continue`.

**WARNING — `oidcc-server`: intentional extension.** "id_token contains non-requested claim 'porch'". The namespaced
`porch` claim (tenant, roles) is Porch's documented ID-token extension; the suite warns about any unrequested claim.
Not a spec violation.

**WARNING — `oidcc-scope-profile`: minor Porch gap.** "'claims' in userinfo doesn't contain all scope items" — for
`scope=profile` userinfo returns only `name` (missing e.g. `preferred_username`, `given_name`, `family_name`,
`updated_at`). OIDC Core 5.4 returns these only when available, so this is allowed. But discovery advertises
`preferred_username` in `claims_supported` (`Provider.Discovery`, `internal/oidcop/provider.go`) and neither the ID token
(`internal/oidcop/tokens.go`) nor `UserInfo` (`internal/oidcop/endpoints.go`) ever emits it: either emit it for the
`profile` scope or drop it from `claims_supported`.

**WARNING — `oidcc-scope-email`, `oidcc-alternate-happy-flow`: design choice.** "Unexpectedly found email in id_token":
with `scope=email` Porch puts `email`/`email_verified` in the ID token as well as userinfo (`tokens.go`). Allowed by the
spec (the suite says so); change only if you want scope claims in userinfo only for the code flow (OIDC Core 5.4).

**WARNING — `oidcc-ensure-request-with-acr-values-succeeds`: optional feature.** "An acr value was requested using
acr_values, so the server 'SHOULD' return an acr claim, but it did not." `acr_values` is voluntary (OIDC Core
3.1.2.1/2.); to silence it, emit an `acr` claim (and `acr_values_supported` in discovery).

**WARNING — `oidcc-claims-essential`: unsupported feature (intended).** "name not found in userinfo": the test asks
for `name` via the `claims` request parameter with only `scope=openid`; Porch ignores `claims`
(`claims_parameter_supported` absent = false).

**REVIEW (3) — need a human to look at the uploaded screenshot; protocol checks passed.**
`oidcc-max-age-1` (fake Google sign-in page shown for the second authorization),
`oidcc-ensure-registered-redirect-uri` and `oidcc-ensure-request-object-with-redirect-uri` (Porch correctly refuses an
unregistered `redirect_uri` with HTTP 400 and does not redirect). Note for certification: the error page is zitadel's
raw JSON body (`{"error":"invalid_request","error_description":"The requested redirect_uri is missing …"}`), not a
human-readable page; acceptable, but a small HTML error page would read better to reviewers.

**SKIPPED (4) — unsupported by design.** `oidcc-scope-address`, `oidcc-scope-phone`, `oidcc-scope-all` (scopes not in
`scopes_supported`); `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` (Porch answers
`request_not_supported`, which the test accepts).

**Harness issues found and fixed in this directory (not Porch bugs):** HtmlUnit cannot run the SPA (login shim);
Porch's login rate limit vs. one suite IP (pacing); `oidcc-server-client-secret-post` needs a separate
`client_secret_post` client in the config (third application).
