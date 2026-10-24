# Operators

Running Porch means looking after one process, one SQLite database and one key file. These pages cover the
installation and everything that keeps it healthy.

| Page | What it covers |
| --- | --- |
| [Install](./quickstart) | Docker Compose or a binary with systemd, the key file, the first owner |
| [Identity providers & domains](./identity-providers) | Google and Google Workspace, domain rules, just-in-time enrollment |
| [Backup login & recovery](./recovery) | the local backup login, lockout, unlocking, offline recovery with `porch admin recover` |
| [Forward-auth (proxies)](./forward-auth) | protecting apps without OIDC through Caddy, Traefik or nginx |
| [Backups and restore](./backups) | encrypted backups to S3-compatible storage, restore drills |
| [Appearance](./appearance) | sign-in backgrounds (Wikimedia Commons, Picsum, your own images), application logos and launcher groups |

## Monitoring

The private management listener (`127.0.0.1:9464`) serves Prometheus metrics, `/healthz` and `/readyz`. Never
publish it. The repository ships a Grafana dashboard and alert rules
([`deploy/monitoring`](https://github.com/aurimasniekis/go-porch/tree/main/deploy/monitoring)), and each alert links
to a runbook:

| Runbook | Alerts |
| --- | --- |
| [Porch is down or not ready](https://github.com/aurimasniekis/go-porch/blob/main/docs/runbooks/porch-down.md) | `PorchDown`, `PorchNotReady` |
| [Errors](https://github.com/aurimasniekis/go-porch/blob/main/docs/runbooks/porch-errors.md) | `PorchHighServerErrorRate`, `PorchSlowRequests` |
| [Sign-in failures](https://github.com/aurimasniekis/go-porch/blob/main/docs/runbooks/porch-login-failures.md) | `PorchLoginFailureSpike`, `PorchBackupLockouts` |
| [Storage](https://github.com/aurimasniekis/go-porch/blob/main/docs/runbooks/porch-storage.md) | `PorchStoreBusy`, `PorchSlowWrites`, `PorchWALLarge` |
| [Backups](https://github.com/aurimasniekis/go-porch/blob/main/docs/runbooks/porch-backups.md) | `PorchBackupFailed`, `PorchBackupStale`, `PorchBackupNeverSucceeded` |
| [Events](https://github.com/aurimasniekis/go-porch/blob/main/docs/runbooks/porch-events.md) | `PorchOutboxBacklog`, `PorchOutboxDeadLetters` |

In the admin UI, **System health** (`/admin/i/health`) shows the same checks, the keyring and storage use.
**Alerts** (`/admin/i/alerts`) lists security events that need attention, for example an offline recovery, until
someone acknowledges them.

## Ground rules

- Run **exactly one** Porch per data directory. Porch takes a lock, and on Linux it refuses network file
  systems.
- Keep the KEK outside the data directory, mode `0400`, and back it up offline separately from data backups.
- Host commands (`admin setup-token`, `admin recover`, `migrate`, `keys rotate`) take the data-directory lock: run
  them while `porch serve` is stopped.
- Put Porch behind TLS and set `proxy.trusted_proxies`, so client IPs (used for throttling and the audit log) come only
  from your proxy.
