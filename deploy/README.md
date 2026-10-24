# Deploying Porch

| Piece | Path | Use it for |
| --- | --- | --- |
| Container image | `Dockerfile`, `.dockerignore` (repository root) | every container deployment |
| Production-style Compose | `deploy/compose.yaml`, `deploy/porch.container.yaml`, `deploy/.env.example` | one Porch behind your own TLS reverse proxy |
| Demo stack | `deploy/demo/` | trying Porch locally: Caddy + fake Google + demo OIDC app + forward-auth |
| systemd | `deploy/systemd/porch.service`, `deploy/systemd/README.md` | bare-metal / VM installs |

Porch is a single binary with SQLite: run **exactly one** instance per data directory (it takes a lock), no replicas.
The KEK (master key-encryption key) must live **outside** the data directory and be backed up separately: without it
the database is unreadable. Host-side admin commands (`admin setup-token`, `admin recover`, `migrate`, `keys rotate`)
take the data-directory lock, so run them while `porch serve` is stopped.

## Container image

```sh
docker build --build-arg VERSION=$(git describe --tags --always --dirty) --build-arg COMMIT=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t porch:local .
docker run --rm porch:local version
```

- Stages: `node:24.22.0-trixie-slim` builds the SPA (`pnpm install --frozen-lockfile && pnpm build`, pnpm 10.11.0 through
  corepack) into `internal/webui/dist`. `golang:1.27.3-trixie` (`GOTOOLCHAIN=local`) builds a static `porch`
  (`CGO_ENABLED=0 -trimpath -s -w`, version/commit/date through `-X .../internal/buildinfo.*`). The runtime is
  `gcr.io/distroless/static-debian13:nonroot`. Every base image is pinned by digest; refresh one with
  `docker buildx imagetools inspect <image>:<tag>`.
- Runs as UID/GID 65532 with no shell. `ENTRYPOINT ["porch"]`, `CMD ["serve"]`, `PORCH_CONFIG=/etc/porch/porch.yaml`.
  So `docker run IMAGE <subcommand>` runs any CLI command.
- `/etc/porch/porch.yaml` is baked in from `deploy/porch.container.yaml`: production mode, `http.listen 0.0.0.0:8080`,
  management on container loopback `127.0.0.1:9464`, KEK at `/run/secrets/porch_kek`. `public_url` has no default: set
  `PORCH_PUBLIC_URL`, or mount your own config read-only over the file.
- `VOLUME /var/lib/porch` (0700, 65532). `/var/lib/porch-kek` (0700, 65532) is an optional mount point for a named volume
  holding the KEK (used by the demo).
- `EXPOSE 8080`. `HEALTHCHECK` runs `porch healthcheck --url http://127.0.0.1:9464/readyz` inside the container, so
  the management listener never needs to be published.
- The build context is an allowlist (`.dockerignore`): `go.mod`, `go.sum`, `cmd/`, `internal/`, `web/` (without
  `node_modules`, test results, `internal/webui/dist`), `LICENSE`, `NOTICE`, the container config, and the two
  demo-only sources (`examples/demo-app/`, `test/fakegoogle/`, which the porch image never copies). `.git`, `bin/`,
  `data/`, `test/conformance/` (including `.work`), `*_test.go`, `testdata/`, KEK and database files are excluded.

## Production-style Compose (`deploy/compose.yaml`)

```sh
cd deploy
cp .env.example .env && $EDITOR .env                       # PD_PUBLIC_URL=https://auth.example.com
install -d -m 0700 secrets && sudo chown 65532:65532 secrets  # Linux; not needed with Docker Desktop
docker compose build                                       # or set PD_IMAGE/PD_VERSION to a published image
docker compose --profile init run --rm keygen              # porch keys init -> secrets/porch.kek (0400, UID 65532)
docker compose run --rm --no-deps porch admin setup-token  # Porch must not be running
docker compose up -d && docker compose ps                  # healthy after a few seconds
```

- Hardening: `read_only: true`, `tmpfs /tmp`, `cap_drop: [ALL]`, `no-new-privileges`, UID 65532, nofile ulimit,
  rotated json-file logs, `stop_grace_period: 30s`.
- Data in the named volume `porch-data` (local disk only: Porch refuses network file systems). The KEK is a compose
  secret bound from `secrets/porch.kek` to `/run/secrets/porch_kek`. A `file:` secret is a bind mount, so on Linux the
  host file must be owned by 65532 with mode 0400; Porch refuses anything readable by group/others.
- The public listener is published on `127.0.0.1:28080` (`PD_HTTP_BIND`, `PD_HTTP_PORT`). Put a TLS reverse proxy in
  front, or set `http.tls_cert_file`/`tls_key_file` in your config. For Cloudflare Authenticated Origin Pulls, also
  set `http.client_ca_file`.
- The network has a fixed subnet (`PD_SUBNET`, default `172.30.214.0/24`), passed to Porch as
  `PORCH_PROXY_TRUSTED_PROXIES` (`PD_TRUSTED_PROXIES`). A proxy on the Docker host reaches the published port from the
  gateway address inside that subnet. If Porch must call internal services (a LAN IdP, MinIO), add their CIDRs to
  `outbound.allow_cidrs`.
- Compose variables use the `PD_` prefix: the porch binary rejects unknown `PORCH_*` variables.

## Demo stack (`deploy/demo/`)

```sh
deploy/demo/up.sh            # build, KEK, setup token, start, bootstrap through the API, print URLs and credentials
deploy/demo/up.sh --manual   # same, but stop at the setup token and finish setup in the browser
deploy/demo/down.sh          # remove containers, network, volumes (data, KEK, Caddy CA) and deploy/demo/.state
deploy/demo/down.sh --keep   # stop only; up.sh resumes the same installation
```

**Demo only:** the fake Google provider signs in anyone who clicks a name. Needs Docker Compose v2.24+, `python3` and
`curl`. Settings come from `deploy/demo/.env` (`.env.example`): `DEMO_HTTPS_PORT` (default **28443**, because 18443 is
often taken), `DEMO_SUBNET` (`172.30.213.0/24`) and `DEMO_GOOGLE_CLIENT_SECRET`.

| URL | Service |
| --- | --- |
| `https://auth.localhost:28443` | Porch (issuer, portal, API, forward-auth outpost) |
| `https://google.localhost:28443` | fake Google (`test/fakegoogle`): Ada and Bob Smith (`smith.example`), Carol (not enrolled) |
| `https://demo.localhost:28443` | demo OIDC relying party (`examples/demo-app`) |
| `https://whoami.localhost:28443` | `traefik/whoami` behind Porch forward-auth |

How it fits together:

- **Same URLs everywhere.** Browsers and curl resolve `*.localhost` to 127.0.0.1. Inside the compose network the Caddy
  container carries the network aliases `auth.localhost`, `google.localhost`, `demo.localhost` and `whoami.localhost`.
  Caddy listens on the same port inside and outside (`https_port`, published 1:1). Porch, the demo app and the
  browser therefore use identical issuer URLs.
- **TLS:** Caddy's internal CA (`local_certs`). `up.sh` exports the root to `deploy/demo/.state/ca/root.crt` and
  mounts it read-only into Porch and the demo app. Porch has no custom-CA option for upstream providers, so it gets
  `SSL_CERT_DIR=/etc/porch/extra-ca`. On Linux, Go loads `SSL_CERT_FILE`, which distroless sets to the system bundle,
  and then adds every file in `SSL_CERT_DIR`. This trusts Caddy's root without replacing the system roots. The demo
  app uses `DEMO_CA_FILE`. To use the demo in a browser, trust `root.crt`, or click through the warning.
- **Porch config** (`porch.yaml`): `mode: development`, because production mode accepts only
  `https://accounts.google.com` for `kind: google` providers. It still uses a real KEK in the `porch-kek` volume
  (outside `data_dir`), https, and `__Host-` cookies. compose.yaml sets `PORCH_PUBLIC_URL`,
  `PORCH_PROXY_TRUSTED_PROXIES` and `PORCH_OUTBOUND_ALLOW_CIDRS` (both set to the demo subnet; the SSRF guard would
  otherwise refuse the fake Google, which sits behind Caddy on a private address).
- **One-shot commands** use the `porch-init` service (profile `init`). It has no network and mounts the data and KEK
  volumes read-write: `docker compose run --rm porch-init keys init --out /var/lib/porch-kek/porch.kek` and
  `docker compose run --rm porch-init admin setup-token` (while `porch` is stopped).
- **Bootstrap** (`bootstrap.py`, stdlib only; skipped with `--manual`): consumes the setup token as "Demo Owner". It
  enrolls a backup login for the owner (handle `owner`; the random password and answers go to `.state/owner.txt` and
  are printed). It registers the fake Google provider, tenant `smith` with a Workspace-domain JIT rule for
  `smith.example`, the demo app (confidential client; credentials in `.state/demo-app.env`) and a `forward_auth` app
  for `whoami.localhost`. `up.sh` then starts the demo app (profile `demo-app`).
- **Forward-auth** (Caddyfile, `whoami.localhost`):
  1. Client-supplied `X-Porch-*` and `Remote-*` request headers are stripped (`request_header -X-Porch-*`).
  2. `/.porch/*` is routed to Porch with the original Host.
  3. Every other request goes through `forward_auth porch:8080 { uri /outpost/auth; copy_headers X-Porch-User
     X-Porch-Email X-Porch-Name X-Porch-Groups X-Porch-Tenant }`.

  Header stripping is not applied on `auth.localhost`, because Porch's API needs the client's `X-Porch-CSRF` header.
  `forward_auth.trusted_peers` defaults to `proxy.trusted_proxies` (the demo subnet).
- **Hardening:** every container runs with a read-only root file system, `cap_drop: [ALL]` and no-new-privileges.
  Porch, fake Google, the demo app and whoami run as UID 65532. Caddy runs as the image's root user with only
  `NET_BIND_SERVICE` (its binary carries that file capability). The fake Google and demo app images
  (`tools.Dockerfile`) use Alpine so their health checks can use `wget`.
- **TODO (later milestones):** pulsed + NATS and MinIO are marked as TODO sections in `compose.yaml`.

## systemd

See [systemd/README.md](systemd/README.md).

## What was verified (2026-10-24, Docker 29.8.2 / Compose v5.6.0 on Docker Desktop arm64)

- `docker build -t porch:local .` succeeds. `docker run --rm porch:local version` prints
  `porch 1d9ea3c09a28-dirty (commit 1d9ea3c09a28, go1.27.3, linux/arm64)`. The image is 29.3 MB, `User=65532:65532`,
  with the HEALTHCHECK configured. The build context is 1.9 MB with no `_test.go` files.
- `deploy/compose.yaml`: `keygen` writes a 0400 KEK, `admin setup-token` issues a token while Porch is stopped,
  `up -d --wait` reports healthy, and discovery on `127.0.0.1:28080` returns the configured issuer. The container is
  read-only, `CapDrop=[ALL]`, `no-new-privileges`, UID 65532.
- `deploy/demo/up.sh` (fresh and re-run): all services start, and porch, fakegoogle and demo-app report healthy. The
  discovery issuer is `https://auth.localhost:28443`. A full sign-in with curl works: demo app → Porch authorize →
  Porch login → fake Google (Ada) → Porch callback (back-channel token exchange to `https://google.localhost:28443`
  through Caddy, trusting Caddy's root via `SSL_CERT_DIR`) → demo app callback. The demo app shows "Signed in as Ada
  Smith" with the ID token and JWT access token verified.
- Forward-auth on `whoami.localhost`: anonymous requests get 302 to `/outpost/start` (401 for JSON). With a Porch
  session, whoami receives `X-Porch-User/Email/Name/Tenant`. Injected `X-Porch-User: mallory` and `Remote-User`
  headers never reach the backend.
- `porch.service` on systemd 257: active, ready, `systemd-analyze security` exposure 1.4 OK.
- Not verified: Linux bind-mount ownership for the production KEK secret (tested on Docker Desktop only),
  `LoadCredential=` (see systemd/README.md), and browser flows (left to the Playwright suite).
