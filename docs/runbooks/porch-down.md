# Runbook: Porch is down or not ready

Alerts: `PorchDown`, `PorchNotReady`.

**Impact.** Nobody can sign in to Porch or to any application that uses it; existing application sessions continue
until their own tokens expire (access tokens: ~10 minutes). Forward-auth protected apps refuse requests.

1. Is the process running? `systemctl status porch` / `docker compose ps`. Check the last log lines
   (`journalctl -u porch -n 200` / `docker compose logs --tail 200 porch`).
2. `porch healthcheck --url http://127.0.0.1:9464/readyz` prints the reason when not ready:
   - `storage degraded: disk full` → free space on the data volume; Porch recovers on its own after a write succeeds.
   - `storage failed: …corrupt…` → Porch checks database integrity whenever it opens the data directory and refuses a
     corrupt database. Stop Porch, keep the damaged files for analysis and restore the latest backup
     (`porch-backups.md`).
   - `keyring not loaded` / startup error `KEK canary mismatch` → the KEK file is missing, unreadable (must be mode 0400,
     owned by the service user) or is the wrong file. Never generate a new KEK for an existing database.
3. Startup fails with `data directory is locked` → another Porch process uses the directory. Stop it; Porch refuses to
   share a data directory.
4. After recovery, check `/admin/i/health` (System health) for remaining warnings.
