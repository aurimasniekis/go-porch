-- 0005_authz_apps: authorization model (ADR-0011, ADR-0012), application access modes, hosts, cross-tenant shares and
-- forward-auth sessions (ADR-0015). Every tenant-scoped reference is a composite foreign key.

-- +goose Up
CREATE TABLE roles (
  id              TEXT NOT NULL PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  slug            TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 63),
  name            TEXT NOT NULL,
  description     TEXT NOT NULL DEFAULT '',
  built_in        INTEGER NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug)
) STRICT, WITHOUT ROWID;

CREATE TABLE role_permissions (
  tenant_id  TEXT NOT NULL,
  role_id    TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission GLOB '[a-z*]*:[a-z*]*'),
  PRIMARY KEY (role_id, permission),
  FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Role bundles: parent includes child (DAG, depth ≤ 5, enforced on write and re-checked by the evaluator).
CREATE TABLE role_edges (
  tenant_id TEXT NOT NULL,
  parent_id TEXT NOT NULL,
  child_id  TEXT NOT NULL,
  PRIMARY KEY (parent_id, child_id),
  CHECK (parent_id != child_id),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, child_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Nested groups: members of child are members of parent (DAG, depth ≤ 5).
CREATE TABLE group_edges (
  tenant_id TEXT NOT NULL,
  parent_id TEXT NOT NULL,
  child_id  TEXT NOT NULL,
  PRIMARY KEY (parent_id, child_id),
  CHECK (parent_id != child_id),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, child_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE resources (
  id              TEXT NOT NULL PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  type            TEXT NOT NULL CHECK (type GLOB '[a-z]*'),
  slug            TEXT NOT NULL,
  name            TEXT NOT NULL,
  parent_id       TEXT,
  attributes_json TEXT NOT NULL DEFAULT '{}',
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, type, slug),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES resources (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE policies (
  id              TEXT NOT NULL PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  slug            TEXT NOT NULL,
  name            TEXT NOT NULL,
  effect          TEXT NOT NULL CHECK (effect IN ('condition', 'deny')),
  -- For deny policies: JSON array of actions it applies to ("*" = all).
  actions         TEXT NOT NULL DEFAULT '[]',
  expression      TEXT NOT NULL CHECK (length(expression) BETWEEN 1 AND 2048),
  env_version     INTEGER NOT NULL DEFAULT 1,
  compiled_hash   TEXT NOT NULL,
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug)
) STRICT, WITHOUT ROWID;

CREATE TABLE role_assignments (
  id                  TEXT NOT NULL PRIMARY KEY,
  tenant_id           TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  subject_type        TEXT NOT NULL CHECK (subject_type IN ('user', 'group', 'service_account')),
  subject_id          TEXT NOT NULL,
  role_id             TEXT NOT NULL,
  scope_type          TEXT NOT NULL CHECK (scope_type IN ('tenant', 'resource_type', 'resource')),
  scope_resource_type TEXT NOT NULL DEFAULT '',
  scope_resource_id   TEXT NOT NULL DEFAULT '',
  condition_policy_id TEXT,
  expires_at          INTEGER,
  source              TEXT NOT NULL,
  created_at          INTEGER NOT NULL,
  created_by          TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, condition_policy_id) REFERENCES policies (tenant_id, id) ON DELETE CASCADE,
  CHECK ((scope_type = 'tenant') = (scope_resource_type = '' AND scope_resource_id = '')),
  CHECK (scope_type != 'resource' OR scope_resource_id != '')
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_assignments_subject ON role_assignments (tenant_id, subject_type, subject_id);

CREATE TABLE authz_epochs (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
  epoch     INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Application access: all_members = every active member may access (built-in rule); assigned = only explicit app:access
-- grants (roles on the app, the app type or the tenant via a custom role).
ALTER TABLE applications ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'all_members' CHECK (access_mode IN ('all_members', 'assigned'));
-- Forward-auth identity headers: JSON object header-name → claim (sub, email, name, groups, tenant, roles).
ALTER TABLE applications ADD COLUMN forward_headers TEXT NOT NULL DEFAULT '{}';

-- Hosts protected by forward-auth applications (unique installation-wide).
CREATE TABLE app_hosts (
  host      TEXT PRIMARY KEY CHECK (host = lower(host)),
  tenant_id TEXT NOT NULL,
  app_id    TEXT NOT NULL,
  FOREIGN KEY (tenant_id, app_id) REFERENCES applications (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Explicit cross-tenant sharing (ADR-0004).
CREATE TABLE app_shares (
  tenant_id        TEXT NOT NULL,
  app_id           TEXT NOT NULL,
  target_tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  granted_by       TEXT,
  created_at       INTEGER NOT NULL,
  PRIMARY KEY (app_id, target_tenant_id),
  CHECK (tenant_id != target_tenant_id),
  FOREIGN KEY (tenant_id, app_id) REFERENCES applications (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_app_shares_target ON app_shares (target_tenant_id);

-- Forward-auth handoff codes and per-host sessions (host-only cookie on the application host).
CREATE TABLE forward_auth_codes (
  mac        BLOB PRIMARY KEY,
  app_id     TEXT NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
  host       TEXT NOT NULL,
  tenant_id  TEXT NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  return_to  TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
) STRICT, WITHOUT ROWID;

CREATE TABLE forward_auth_sessions (
  id         TEXT PRIMARY KEY,
  mac        BLOB NOT NULL UNIQUE,
  app_id     TEXT NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
  host       TEXT NOT NULL,
  tenant_id  TEXT NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_fa_sessions_session ON forward_auth_sessions (session_id);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
