-- 0002_tenancy_identity: tenants, users, operators, memberships, groups, setup tokens and browser sessions (ADR-0004,
-- ADR-0021). Tenant-scoped tables expose UNIQUE (tenant_id, id) and reference each other with composite foreign keys,
-- so a row can never point at another tenant's row.

-- +goose Up
CREATE TABLE tenants (
  id                    TEXT PRIMARY KEY,
  slug                  TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 2 AND 63),
  name                  TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  status                TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  session_idle_secs     INTEGER CHECK (session_idle_secs IS NULL OR session_idle_secs > 0),
  session_absolute_secs INTEGER CHECK (session_absolute_secs IS NULL OR session_absolute_secs > 0),
  version               INTEGER NOT NULL DEFAULT 1,
  managed_by            TEXT NOT NULL DEFAULT 'api',
  last_changed_by       TEXT,
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE users (
  id              TEXT PRIMARY KEY,
  public_id       TEXT NOT NULL UNIQUE,
  display_name    TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  primary_email   TEXT,
  status          TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  backup_handle   TEXT UNIQUE,
  security_epoch  INTEGER NOT NULL DEFAULT 1 CHECK (security_epoch > 0),
  last_login_at   INTEGER,
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_users_email ON users (primary_email);

-- Email addresses are attributes, never identity (ADR-0005).
CREATE TABLE user_emails (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  email      TEXT NOT NULL CHECK (email = lower(email)),
  verified   INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
  source     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (user_id, email)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_user_emails_email ON user_emails (email);

-- Installation operators: separate from tenant roles (ADR-0004).
CREATE TABLE installation_role_assignments (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'auditor')),
  source     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT,
  UNIQUE (user_id, role)
) STRICT, WITHOUT ROWID;

CREATE TABLE memberships (
  id              TEXT NOT NULL PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  status          TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
  source          TEXT NOT NULL,
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, user_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_memberships_user ON memberships (user_id);

CREATE TABLE groups (
  id              TEXT NOT NULL PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  slug            TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 63),
  name            TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description     TEXT NOT NULL DEFAULT '',
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug)
) STRICT, WITHOUT ROWID;

-- A group member must be a member of the group's tenant: the composite FK to memberships (tenant_id, user_id)
-- enforces it, and removing the membership removes the group memberships.
CREATE TABLE group_members (
  tenant_id  TEXT NOT NULL,
  group_id   TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  source     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_group_members_user ON group_members (tenant_id, user_id);

-- CLI-issued single-use setup tokens (ADR-0003 token MACs). Consumed only while no operator exists.
CREATE TABLE setup_tokens (
  id          TEXT PRIMARY KEY,
  mac         BLOB NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  consumed_by TEXT
) STRICT, WITHOUT ROWID;

-- Browser sessions (ADR-0021). The cookie value is never stored; mac = HMAC(token key, cookie value).
CREATE TABLE sessions (
  id                  TEXT PRIMARY KEY,
  mac                 BLOB NOT NULL UNIQUE,
  user_id             TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  tenant_id           TEXT REFERENCES tenants (id) ON DELETE SET NULL,
  method              TEXT NOT NULL CHECK (method IN ('setup', 'google', 'oidc', 'backup', 'recovery_link')),
  provider_id         TEXT,
  auth_time           INTEGER NOT NULL,
  upstream_checked_at INTEGER,
  csrf_secret         BLOB NOT NULL,
  install_epoch       INTEGER NOT NULL,
  user_epoch          INTEGER NOT NULL,
  idle_secs           INTEGER NOT NULL CHECK (idle_secs > 0),
  absolute_expires_at INTEGER NOT NULL,
  created_at          INTEGER NOT NULL,
  last_seen_at        INTEGER NOT NULL,
  ip                  TEXT NOT NULL DEFAULT '',
  user_agent          TEXT NOT NULL DEFAULT '',
  revoked_at          INTEGER,
  revoke_reason       TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_sessions_user ON sessions (user_id, revoked_at);
CREATE INDEX ix_sessions_expiry ON sessions (absolute_expires_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
