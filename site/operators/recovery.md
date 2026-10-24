# Backup login, lockout and recovery

| Situation | What to do |
|---|---|
| A user locked their backup login | They can keep using Google. An owner/admin can unlock: `POST /api/v1/users/{id}/backup-lockout/unlock` (needs a recent sign-in), or on the host `porch admin unlock-backup --user ada@example.com` |
| Nobody can sign in (Google down, no backup login) | On the host: `porch admin recover --user <id or email>` prints a one-time link valid 15 minutes |
| A recovery link was used | Porch raises a **critical alert** until an operator acknowledges it (`GET/POST /api/v1/installation/alerts`) |
| Under attack (many failures) | Per-source throttles and an installation-wide circuit stop guessing before passwords are hashed |

Host commands need the data-directory lock and the KEK, so stop the service first (`systemctl stop porch`).

Configuration (`backup_login` in `porch.yaml`):

```yaml
backup_login:
  threshold: 1          # failed steps before a lock
  lock_duration: 6h     # doubles per lock …
  max_lock_duration: 48h # … up to this
  source_limit: 10      # failures per IPv4 address or IPv6 /64 per window
  source_window: 15m
  circuit_limit: 100    # failures installation-wide per window
  circuit_window: 1m
  disabled: false       # true = backup login off for everyone (startup warning)
```

There is deliberately no API to *lock* a user: locks only result from failed attempts.
