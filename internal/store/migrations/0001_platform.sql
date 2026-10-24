-- 0001_platform: installation singleton, settings, keyring, audit chain, outbox, jobs (ADR-0002, ADR-0003, ADR-0019).
-- Forward-only: rollback = restore the pre-migration snapshot.

-- +goose Up
CREATE TABLE installation (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  installation_id    TEXT NOT NULL,
  security_epoch     INTEGER NOT NULL DEFAULT 1 CHECK (security_epoch > 0),
  setup_completed_at INTEGER,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
) STRICT;

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
) STRICT, WITHOUT ROWID;

CREATE TABLE keyring_keys (
  id          TEXT PRIMARY KEY,
  purpose     TEXT NOT NULL CHECK (purpose IN ('field', 'token', 'signing', 'backup-meta')),
  version     INTEGER NOT NULL CHECK (version > 0),
  wrapped     BLOB NOT NULL,
  wrap_kek_id TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('active', 'decrypt_only', 'retired')),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE (purpose, version)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_keyring_active ON keyring_keys (purpose) WHERE state = 'active';

-- Audit schema v1 (ADR-0019). tenant_id is a plain column (no FK): audit rows outlive the rows they describe.
CREATE TABLE audit_events (
  id           TEXT PRIMARY KEY,
  seq          INTEGER NOT NULL UNIQUE CHECK (seq > 0),
  at           INTEGER NOT NULL,
  request_id   TEXT,
  actor_type   TEXT NOT NULL CHECK (actor_type IN ('user', 'operator', 'service_account', 'automation', 'system', 'cli', 'client')),
  actor_id     TEXT,
  tenant_id    TEXT,
  action       TEXT NOT NULL,
  target_type  TEXT,
  target_id    TEXT,
  outcome      TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  reason_code  TEXT,
  source_ip    TEXT,
  auth_method  TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  details_enc  BLOB,
  prev_hash    BLOB NOT NULL,
  hash         BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_audit_at ON audit_events (at);
CREATE INDEX ix_audit_tenant ON audit_events (tenant_id, at);
CREATE INDEX ix_audit_target ON audit_events (target_type, target_id, at);
CREATE INDEX ix_audit_actor ON audit_events (actor_type, actor_id, at);
CREATE INDEX ix_audit_action ON audit_events (action, at);

-- Transactional outbox for pulse events (ADR-0019). id is the stable event ID consumers deduplicate on.
CREATE TABLE outbox (
  id              TEXT PRIMARY KEY,
  type            TEXT NOT NULL,
  subject         TEXT NOT NULL,
  tenant_id       TEXT,
  payload_json    TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_error      TEXT,
  published_at    INTEGER,
  dead_at         INTEGER
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_outbox_due ON outbox (next_attempt_at) WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX ix_outbox_created ON outbox (created_at);

CREATE TABLE jobs (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  run_at       INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
  lease_until  INTEGER,
  state        TEXT NOT NULL CHECK (state IN ('queued', 'running', 'done', 'dead')),
  payload_json TEXT NOT NULL DEFAULT '{}',
  last_error   TEXT,
  dedup_key    TEXT,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_jobs_due ON jobs (state, run_at);
CREATE UNIQUE INDEX ux_jobs_dedup ON jobs (dedup_key) WHERE dedup_key IS NOT NULL AND state IN ('queued', 'running');

-- Disk-full recovery probe: a degraded "disk full" state clears only after a page-allocating write commits.
CREATE TABLE store_space_probe (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  data BLOB NOT NULL
) STRICT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
