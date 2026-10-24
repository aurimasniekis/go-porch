-- 0007_automation: management-API bearer tokens for automation (Terraform) and Idempotency-Key replays (ADR-0041).

-- +goose Up
CREATE TABLE automation_tokens (
  id           TEXT NOT NULL PRIMARY KEY,
  mac          BLOB NOT NULL UNIQUE,
  hint         TEXT NOT NULL,
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind         TEXT NOT NULL CHECK (kind IN ('installation', 'tenant')),
  tenant_id    TEXT REFERENCES tenants (id) ON DELETE CASCADE,
  role         TEXT CHECK (role IN ('admin', 'auditor')),
  permissions  TEXT NOT NULL DEFAULT '[]',
  created_by   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  last_used_ip TEXT NOT NULL DEFAULT '',
  revoked_at   INTEGER,
  CHECK ((kind = 'installation') = (tenant_id IS NULL)),
  CHECK ((kind = 'installation') = (role IS NOT NULL)),
  CHECK (expires_at > created_at)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_automation_tokens_tenant ON automation_tokens (tenant_id);

CREATE TABLE idempotency_keys (
  key_mac         BLOB NOT NULL PRIMARY KEY, -- MAC(principal, Idempotency-Key)
  request_hash    BLOB NOT NULL,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  state           TEXT NOT NULL CHECK (state IN ('pending', 'done')),
  status          INTEGER NOT NULL DEFAULT 0,
  content_type    TEXT NOT NULL DEFAULT '',
  body            BLOB,
  secret_withheld INTEGER NOT NULL DEFAULT 0 CHECK (secret_withheld IN (0, 1)),
  location        TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_idempotency_expiry ON idempotency_keys (expires_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
