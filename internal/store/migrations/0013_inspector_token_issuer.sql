-- 0013_inspector_token_issuer (ADR-0048, security-relevant): the installation role "inspector" reads configuration
-- inside every tenant, for people and automation tokens; automation tokens record the token that issued them, so
-- revoking a token revokes everything it issued. SQLite cannot change a CHECK constraint in place, so both tables are
-- rebuilt; nothing references them, and their rows are copied unchanged.

-- +goose Up
CREATE TABLE installation_role_assignments_new (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'auditor', 'inspector')),
  source     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT,
  UNIQUE (user_id, role)
) STRICT, WITHOUT ROWID;

INSERT INTO installation_role_assignments_new (id, user_id, role, source, created_at, created_by)
SELECT id, user_id, role, source, created_at, created_by FROM installation_role_assignments;

DROP TABLE installation_role_assignments;
ALTER TABLE installation_role_assignments_new RENAME TO installation_role_assignments;

CREATE TABLE automation_tokens_new (
  id            TEXT NOT NULL PRIMARY KEY,
  mac           BLOB NOT NULL UNIQUE,
  hint          TEXT NOT NULL,
  name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind          TEXT NOT NULL CHECK (kind IN ('installation', 'tenant')),
  tenant_id     TEXT REFERENCES tenants (id) ON DELETE CASCADE,
  role          TEXT CHECK (role IN ('admin', 'auditor', 'inspector')),
  permissions   TEXT NOT NULL DEFAULT '[]',
  created_by    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  last_used_at  INTEGER,
  last_used_ip  TEXT NOT NULL DEFAULT '',
  revoked_at    INTEGER,
  never_expires INTEGER NOT NULL DEFAULT 0 CHECK (never_expires IN (0, 1) AND (never_expires = 0 OR kind = 'installation')),
  -- The token that issued this one (NULL when a person issued it). Not a foreign key: revocation, not deletion, ends
  -- tokens, and the issuer's row may be gone with its tenant.
  issued_by     TEXT,
  CHECK ((kind = 'installation') = (tenant_id IS NULL)),
  CHECK ((kind = 'installation') = (role IS NOT NULL)),
  CHECK (expires_at > created_at)
) STRICT, WITHOUT ROWID;

INSERT INTO automation_tokens_new (id, mac, hint, name, kind, tenant_id, role, permissions, created_by, created_at, expires_at,
  last_used_at, last_used_ip, revoked_at, never_expires)
SELECT id, mac, hint, name, kind, tenant_id, role, permissions, created_by, created_at, expires_at, last_used_at, last_used_ip,
  revoked_at, never_expires
FROM automation_tokens;

DROP TABLE automation_tokens;
ALTER TABLE automation_tokens_new RENAME TO automation_tokens;

CREATE INDEX ix_automation_tokens_tenant ON automation_tokens (tenant_id);
CREATE INDEX ix_automation_tokens_issued_by ON automation_tokens (issued_by);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
