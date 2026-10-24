-- 0008_backups: history of backup runs (ADR-0042). The backups themselves live in object storage.

-- +goose Up
CREATE TABLE backup_runs (
  id           TEXT NOT NULL PRIMARY KEY, -- also the object prefix backups/<id>/
  trigger      TEXT NOT NULL CHECK (trigger IN ('schedule', 'manual', 'cli')),
  started_at   INTEGER NOT NULL,
  finished_at  INTEGER,
  ok           INTEGER CHECK (ok IN (0, 1)),
  error        TEXT NOT NULL DEFAULT '',
  db_bytes     INTEGER NOT NULL DEFAULT 0,
  stored_bytes INTEGER NOT NULL DEFAULT 0,
  kek_included INTEGER NOT NULL DEFAULT 0 CHECK (kek_included IN (0, 1)),
  pruned       INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_backup_runs_started ON backup_runs (started_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
