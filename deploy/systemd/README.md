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

## LoadCredential (alternative)

Instead of a `porch`-owned `/etc/porch/kek`, systemd can hand the KEK to the service as a credential. For a non-root
service, systemd places credentials in a private directory as root-owned files with a POSIX ACL for the service user;
the ACL mask shows as group bits (`0440`). Porch accepts that mode **only** for `kek.source: credential`, which reads
`$CREDENTIALS_DIRECTORY/<kek.file>`; world-readable or group-writable files are still refused.

```ini
[Service]
LoadCredential=porch-kek:/etc/credstore/porch.kek   # root:root 0400 on disk
```

```yaml
kek:
  source: credential
  file: porch-kek          # the credential name, not a path
```

Remove `AssertPathExists=/etc/porch/kek` from the unit when you switch. Unit-tested in Porch (`TestKEKFromSystemdCredential`:
0440 accepted in the credentials directory, refused elsewhere, 0444 refused). Not verified under a real systemd with ACL
support (the test environment's kernel had no tmpfs ACLs).

## Verified

`porch.service` as shipped, on systemd 257 (Debian trixie in a privileged container): `systemctl start porch` makes it
active, `porch healthcheck` returns `ready`, discovery is served on 127.0.0.1:8080, `/var/lib/porch` is created as
`porch:porch 0700`, and `systemd-analyze security porch.service` reports overall exposure **1.4 OK**.
