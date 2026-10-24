# Runbook: sign-in failures and backup-login lockouts

Alerts: `PorchLoginFailureSpike`, `PorchBackupLockouts`.

1. Which method? The alert carries `method` (`upstream`, `backup`, `recovery_link`).
2. `upstream` failures for everyone at once: the identity provider (Google) is down or its client secret/redirect URI
   changed. Check **Administration → Identity providers** and the audit log (`action` prefix `login.`).
3. `backup` failures or lockouts: someone is guessing a backup password. Lockouts affect only the backup login of that
   account; Google sign-in keeps working. Look up the source IPs in the audit log (`login.backup` events). The owner
   can unlock from **Administration → Alerts** after confirming with the user, or on the host with
   `porch admin unlock-backup`.
4. Many sources at once trip the installation-wide circuit (throttled outcome): consider blocking the sources at the
   proxy or Cloudflare.
