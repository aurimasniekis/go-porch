-- 0003_login: upstream identity providers, external identities, domain enrollment rules, invites, upstream login state,
-- the local backup credential (password + titled recovery answers), lockout, throttling, recovery links and
-- installation alerts (ADR-0005..0009).

-- +goose Up
CREATE TABLE identity_providers (
  id              TEXT PRIMARY KEY,
  slug            TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 2 AND 63),
  kind            TEXT NOT NULL CHECK (kind IN ('google', 'oidc')),
  name            TEXT NOT NULL,
  issuer          TEXT NOT NULL,
  client_id       TEXT NOT NULL,
  secret_enc      BLOB NOT NULL,
  -- JSON array of Workspace domains; non-empty = the provider only accepts tokens whose validated hd is listed.
  allowed_hds     TEXT NOT NULL DEFAULT '[]',
  scopes          TEXT NOT NULL DEFAULT 'openid email profile',
  enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Login identities: (provider, issuer, subject), never email (ADR-0005).
CREATE TABLE external_identities (
  id            TEXT PRIMARY KEY,
  provider_id   TEXT NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
  issuer        TEXT NOT NULL,
  subject       TEXT NOT NULL,
  user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  email         TEXT,
  hd            TEXT,
  linked_at     INTEGER NOT NULL,
  last_login_at INTEGER,
  UNIQUE (provider_id, issuer, subject)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_external_identities_user ON external_identities (user_id);

CREATE TABLE domain_rules (
  id                TEXT PRIMARY KEY,
  domain            TEXT NOT NULL UNIQUE CHECK (domain = lower(domain)),
  tenant_id         TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  provider_id       TEXT NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
  evidence_kind     TEXT NOT NULL CHECK (evidence_kind IN ('workspace_hd', 'verified_email')),
  mode              TEXT NOT NULL CHECK (mode IN ('invite_only', 'jit')),
  baseline_role_ids TEXT NOT NULL DEFAULT '[]',
  version           INTEGER NOT NULL DEFAULT 1,
  managed_by        TEXT NOT NULL DEFAULT 'api',
  last_changed_by   TEXT,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE invites (
  id          TEXT NOT NULL PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  email       TEXT NOT NULL CHECK (email = lower(email)),
  created_by  TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  consumed_by TEXT,
  UNIQUE (tenant_id, id)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_invites_email ON invites (email, consumed_at);

-- Pending upstream logins. state_mac = HMAC(token key, state); nonce and PKCE verifier are sealed.
CREATE TABLE oidc_login_states (
  id          TEXT PRIMARY KEY,
  state_mac   BLOB NOT NULL UNIQUE,
  provider_id TEXT NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
  intent      TEXT NOT NULL CHECK (intent IN ('login', 'recheck', 'stepup', 'link')),
  session_id  TEXT,
  secrets_enc BLOB NOT NULL,
  return_to   TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Backup credential (ADR-0008): sealed Argon2id PHC strings for the password and for all answers together.
CREATE TABLE backup_credentials (
  user_id      TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  password_enc BLOB NOT NULL,
  answers_enc  BLOB NOT NULL,
  pair_count   INTEGER NOT NULL CHECK (pair_count BETWEEN 3 AND 12),
  enrolled_at  INTEGER NOT NULL,
  rotated_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- User-written titles (hints) of the recovery answers; sealed. Answers exist only inside answers_enc's verifier.
CREATE TABLE recovery_pairs (
  id        TEXT PRIMARY KEY,
  user_id   TEXT NOT NULL REFERENCES backup_credentials (user_id) ON DELETE CASCADE,
  position  INTEGER NOT NULL CHECK (position BETWEEN 0 AND 11),
  title_enc BLOB NOT NULL,
  UNIQUE (user_id, position)
) STRICT, WITHOUT ROWID;

CREATE TABLE backup_lockouts (
  user_id      TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  failures     INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
  locked_until INTEGER NOT NULL DEFAULT 0,
  level        INTEGER NOT NULL DEFAULT 0 CHECK (level >= 0),
  updated_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Step-2 challenges issued after a correct password.
CREATE TABLE backup_challenges (
  id          TEXT PRIMARY KEY,
  mac         BLOB NOT NULL UNIQUE,
  user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  source_key  TEXT NOT NULL,
  session_id  TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
) STRICT, WITHOUT ROWID;

-- Fixed-window throttle counters that survive restarts (per source, installation circuit).
CREATE TABLE throttle_buckets (
  key          TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- One-time offline recovery links issued by `porch admin recover`.
CREATE TABLE recovery_links (
  id          TEXT PRIMARY KEY,
  mac         BLOB NOT NULL UNIQUE,
  user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
) STRICT, WITHOUT ROWID;

-- Persistent operator alerts (e.g. a recovery link was used) shown until acknowledged.
CREATE TABLE alerts (
  id              TEXT PRIMARY KEY,
  kind            TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  message         TEXT NOT NULL,
  target_id       TEXT,
  created_at      INTEGER NOT NULL,
  acknowledged_at INTEGER,
  acknowledged_by TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_alerts_open ON alerts (acknowledged_at, created_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
