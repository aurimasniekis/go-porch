# Porch under systemd

`porch.service` runs one Porch instance as a dedicated `porch` user with a strict sandbox. Exactly one Porch per data
directory (SQLite plus a data-directory lock).

## Layout

| Path | Owner / mode | Purpose |
| --- | --- | --- |
| `/usr/local/bin/porch` | `root:root 0755` | binary (`make build`, or copy it out of the container image) |
| `/etc/porch/` | `root:porch 0750` | configuration directory |
| `/etc/porch/porch.yaml` | `root:porch 0640` | configuration, no secrets |
| `/etc/porch/kek` | `porch:porch 0400` | master key-encryption key; **never** inside `data_dir` |
| `/var/lib/porch` | `porch:porch 0700` | data directory, created by `StateDirectory=porch` |

## Install

```sh
sudo useradd --system --home-dir /var/lib/porch --shell /usr/sbin/nologin porch
sudo install -m 0755 bin/porch /usr/local/bin/porch
sudo install -d -m 0750 -o root -g porch /etc/porch
sudo install -m 0640 -o root -g porch porch.yaml /etc/porch/porch.yaml     # see the minimal config below

# KEK: written by the porch user so it is owned by it (keys init refuses to overwrite an existing file).
sudo -u porch porch keys init --out /tmp/porch.kek
sudo install -m 0400 -o porch -g porch /tmp/porch.kek /etc/porch/kek && sudo shred -u /tmp/porch.kek
# Back /etc/porch/kek up offline, separately from data backups: without it the database is unreadable.

sudo install -m 0644 deploy/systemd/porch.service /etc/systemd/system/porch.service
sudo systemctl daemon-reload

# First owner: the setup token needs the data-directory lock, so issue it BEFORE starting the service
# (or stop it first). StateDirectory= does not exist yet on a fresh host, so create it the same way systemd would.
sudo install -d -m 0700 -o porch -g porch /var/lib/porch
sudo -u porch env PORCH_CONFIG=/etc/porch/porch.yaml porch admin setup-token

sudo systemctl enable --now porch
porch healthcheck                       # probes http://127.0.0.1:9464/readyz
systemd-analyze security porch.service  # exposure score of the sandbox
```

Open `<public_url>/setup` and paste the token.

Minimal `/etc/porch/porch.yaml` (put a TLS-terminating reverse proxy in front, or set `http.tls_cert_file` /
`http.tls_key_file` and bind 443 with the capability lines in the unit):

```yaml
mode: production
data_dir: /var/lib/porch          # must match StateDirectory=porch
public_url: https://auth.example.com
kek:
  file: /etc/porch/kek
http:
  listen: 127.0.0.1:8080
management:
  listen: 127.0.0.1:9464
proxy:
  trusted_proxies: [127.0.0.1/32, ::1/128]   # the reverse proxy on this host
```

Host-side admin commands (`admin setup-token`, `admin recover`, `migrate`, `keys rotate`, ...) take the data-directory
lock: stop the service, run them as the `porch` user with `PORCH_CONFIG=/etc/porch/porch.yaml`, start it again.

## Sandbox notes

- `ProtectSystem=strict` makes the whole file system read-only except `ReadWritePaths=/var/lib/porch` (and the
  `StateDirectory`). If you set `log.audit_file` outside the data directory, add `LogsDirectory=porch` and point it at
  `/var/log/porch/audit.jsonl`.
- `CapabilityBoundingSet=` is empty: ports 8080 and 9464 need no capabilities.
- `SystemCallFilter=@system-service` minus the privileged groups, `MemoryDenyWriteExecute=yes` (Porch is a static Go
  binary; no JIT), `RestrictAddressFamilies` limited to unix/inet/netlink.

## LoadCredential (not used yet)

The unit reads the KEK from `/etc/porch/kek` with a dedicated user instead of `LoadCredential=` or `DynamicUser=yes`.
Porch refuses a KEK file whose mode has any group or other bits, and it must be owned by the service user or root.
For a non-root service, systemd puts each credential on a private tmpfs or ramfs as a **root-owned 0400 file plus a
POSIX ACL** granting the service user read access. A file with an ACL reports the ACL mask in its group bits (`0440`), so
Porch would refuse it. On file systems without ACL support, systemd chowns the file to the service user instead; Porch
accepts that `0400 porch:porch` file. Verified: the 0400 file owned by the service user is accepted. Not verifiable
here: systemd's ACL path, because the test kernel (Docker Desktop) has no tmpfs ACL support. The ACL behaviour above
comes from the systemd source and POSIX ACL semantics.

Once Porch accepts credentials (a change outside deploy/: for example, trust a KEK under `$CREDENTIALS_DIRECTORY` and
ignore the ACL mask there), switch to:

```ini
[Service]
DynamicUser=yes                      # optional; drop User=/Group=
LoadCredential=kek:/etc/porch/kek    # source can then be root:root 0400
Environment=PORCH_KEK_FILE=%d/kek    # %d = $CREDENTIALS_DIRECTORY
```

The source file `/etc/porch/kek` can then be `root:root 0400`, readable by nobody but root and systemd.

## Verified

`porch.service` as shipped, on systemd 257 (Debian trixie in a privileged container): `systemctl start porch` makes it
active, `porch healthcheck` returns `ready`, discovery is served on 127.0.0.1:8080, `/var/lib/porch` is created as
`porch:porch 0700`, and `systemd-analyze security porch.service` reports overall exposure **1.4 OK**.
