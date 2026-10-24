-- 0006_service_accounts: tenant machine identities authenticating with the OAuth client credentials grant (ADR-0037).

-- +goose Up
CREATE TABLE service_accounts (
  id                    TEXT NOT NULL PRIMARY KEY, -- also the client_id used at the token endpoint
  tenant_id             TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  slug                  TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 63),
  name                  TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description           TEXT NOT NULL DEFAULT '',
  enabled               INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  secret_mac            BLOB NOT NULL,
  secret_hint           TEXT NOT NULL DEFAULT '',
  audiences             TEXT NOT NULL DEFAULT '[]',
  access_token_ttl_secs INTEGER NOT NULL DEFAULT 600 CHECK (access_token_ttl_secs BETWEEN 60 AND 3600),
  last_used_at          INTEGER,
  version               INTEGER NOT NULL DEFAULT 1,
  managed_by            TEXT NOT NULL DEFAULT 'api',
  last_changed_by       TEXT,
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug)
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
