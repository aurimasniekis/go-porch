# Runbook: backups

Alerts: `PorchBackupFailed`, `PorchBackupStale`, `PorchBackupNeverSucceeded`. Health check `backups`.

## A backup failed or is stale

1. **Administration → Backups** (or `GET /api/v1/installation/backups`) shows the last runs with their error.
2. Common errors:
   - `bucket … does not exist` / `Access Denied` → check `backup.s3.bucket`, the access key and the bucket policy.
   - `dial … refused by outbound guard` → the S3 endpoint resolves to a private address; add it to
     `outbound.allow_cidrs` (only for your own MinIO).
   - `x509: certificate signed by unknown authority` → set `backup.s3.ca_file`.
   - `delete … (object lock?)` in the log is only a retention warning: the backup itself succeeded.
3. Take a backup now: **Back up now** in the UI, or `POST /api/v1/installation/backups` (owner/admin or an installation
   admin automation token). `porch backup run` works only while the server is stopped.

## Restore (disaster recovery)

You need, from offline storage: the **age identity** (`AGE-SECRET-KEY-1…`) and the **verification key**
(`porch-backup-ed25519:…`).

1. Prepare a clean host/container with the same Porch version or newer and a config whose `data_dir` is empty and whose
   `kek.file` does not exist yet (same `backup.s3` settings).
2. `porch backup list -config porch.yaml` — pick a backup (default: the newest complete one).
3. `porch backup verify -config porch.yaml -identity backup.agekey -verify-key porch-backup-ed25519:…`
4. `porch restore -config porch.yaml -identity backup.agekey -verify-key porch-backup-ed25519:… [-id bkp_…]`
   Add `-invalidate-backup-logins` if the old installation may be compromised (users re-enrol their backup login).
5. `porch serve`. On this first start Porch invalidates every session and refresh token from the backup, replaces the
   signing keys (applications fetch the new JWKS automatically) and raises a critical alert.
6. Sign in (Google, or `porch admin recover --user <owner email>`), acknowledge the alert, check
   **Administration → System health**, and confirm applications still sign in.

Never restore with `-insecure-skip-verify` unless the verification key is lost **and** you are certain the bucket was
not writable by anyone else: an unverified backup may be a forged installation.

Drill: `scripts/backup-drill.sh` runs the whole procedure against MinIO in Docker.
