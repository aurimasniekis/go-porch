-- 0004_oidc_provider: applications, OAuth/OIDC clients, signing keys, authorization requests and codes, refresh-token
-- families and revoked access-token IDs (ADR-0013, ADR-0014, ADR-0030).

-- +goose Up
CREATE TABLE applications (
  id              TEXT NOT NULL PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  slug            TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 63),
  name            TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind            TEXT NOT NULL CHECK (kind IN ('oidc', 'forward_auth')),
  description     TEXT NOT NULL DEFAULT '',
  launch_url      TEXT NOT NULL DEFAULT '',
  enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  -- Which optional claims this app may receive (ADR-0014): {"email":bool,"groups":bool,"roles":bool,"entitlements":bool}.
  disclosure_json TEXT NOT NULL DEFAULT '{"email":true,"groups":false,"roles":true,"entitlements":false}',
  version         INTEGER NOT NULL DEFAULT 1,
  managed_by      TEXT NOT NULL DEFAULT 'api',
  last_changed_by TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug)
) STRICT, WITHOUT ROWID;

CREATE TABLE oauth_clients (
  id                      TEXT NOT NULL PRIMARY KEY, -- the public client_id
  tenant_id               TEXT NOT NULL,
  app_id                  TEXT NOT NULL,
  client_type             TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
  application_type        TEXT NOT NULL CHECK (application_type IN ('web', 'native', 'user_agent')),
  secret_mac              BLOB,
  secret_hint             TEXT NOT NULL DEFAULT '',
  redirect_uris           TEXT NOT NULL DEFAULT '[]',
  post_logout_uris        TEXT NOT NULL DEFAULT '[]',
  grant_types             TEXT NOT NULL DEFAULT '["authorization_code"]',
  allowed_scopes          TEXT NOT NULL DEFAULT '["openid","profile","email","offline_access"]',
  audiences               TEXT NOT NULL DEFAULT '[]',
  allowed_origins         TEXT NOT NULL DEFAULT '[]',
  require_pkce            INTEGER NOT NULL DEFAULT 1 CHECK (require_pkce IN (0, 1)),
  signing_alg             TEXT NOT NULL DEFAULT 'ES256' CHECK (signing_alg IN ('ES256', 'RS256')),
  access_token_ttl_secs   INTEGER NOT NULL DEFAULT 600,
  id_token_ttl_secs       INTEGER NOT NULL DEFAULT 600,
  refresh_ttl_secs        INTEGER NOT NULL DEFAULT 2592000,
  refresh_idle_secs       INTEGER NOT NULL DEFAULT 1209600,
  version                 INTEGER NOT NULL DEFAULT 1,
  created_at              INTEGER NOT NULL,
  updated_at              INTEGER NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (app_id),
  FOREIGN KEY (tenant_id, app_id) REFERENCES applications (tenant_id, id) ON DELETE CASCADE,
  CHECK ((client_type = 'confidential') = (secret_mac IS NOT NULL))
) STRICT, WITHOUT ROWID;

CREATE TABLE signing_keys (
  id           TEXT PRIMARY KEY, -- kid
  alg          TEXT NOT NULL CHECK (alg IN ('ES256', 'RS256')),
  private_enc  BLOB NOT NULL,
  public_jwk   TEXT NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
  created_at   INTEGER NOT NULL,
  retire_after INTEGER,
  retired_at   INTEGER
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_signing_keys_active ON signing_keys (alg) WHERE state = 'active';

CREATE TABLE auth_requests (
  id             TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
  tenant_id      TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  redirect_uri   TEXT NOT NULL,
  scopes         TEXT NOT NULL,
  state          TEXT NOT NULL DEFAULT '',
  nonce          TEXT NOT NULL DEFAULT '',
  code_challenge TEXT NOT NULL,
  response_mode  TEXT NOT NULL DEFAULT '',
  prompt         TEXT NOT NULL DEFAULT '[]',
  max_age        INTEGER,
  login_hint     TEXT NOT NULL DEFAULT '',
  resources      TEXT NOT NULL DEFAULT '[]',
  -- Session sent to re-authenticate for prompt=login; it must come back rotated (fresh authentication).
  reauth_session_id TEXT,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE auth_codes (
  mac            BLOB PRIMARY KEY,
  id             TEXT NOT NULL UNIQUE,
  client_id      TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
  tenant_id      TEXT NOT NULL,
  user_id        TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  session_id     TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  scopes         TEXT NOT NULL,
  nonce          TEXT NOT NULL DEFAULT '',
  code_challenge TEXT NOT NULL,
  resources      TEXT NOT NULL DEFAULT '[]',
  auth_time      INTEGER NOT NULL,
  amr            TEXT NOT NULL DEFAULT '[]',
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  used_at        INTEGER,
  -- Tokens issued from this code (revoked if the code is replayed).
  family_id      TEXT,
  access_jti     TEXT
) STRICT, WITHOUT ROWID;

CREATE TABLE refresh_tokens (
  id              TEXT PRIMARY KEY,
  mac             BLOB NOT NULL UNIQUE,
  family_id       TEXT NOT NULL,
  parent_id       TEXT,
  client_id       TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
  tenant_id       TEXT NOT NULL,
  user_id         TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  scopes          TEXT NOT NULL,
  resources       TEXT NOT NULL DEFAULT '[]',
  auth_time       INTEGER NOT NULL,
  amr             TEXT NOT NULL DEFAULT '[]',
  state           TEXT NOT NULL CHECK (state IN ('active', 'rotated', 'revoked')),
  install_epoch   INTEGER NOT NULL,
  user_epoch      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  family_expires_at INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL,
  rotated_at      INTEGER,
  revoked_at      INTEGER,
  revoke_reason   TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_refresh_family ON refresh_tokens (family_id);
CREATE INDEX ix_refresh_user_client ON refresh_tokens (user_id, client_id, state);

-- Access tokens are self-contained JWTs; revoked ones are listed until they expire (introspection and userinfo).
CREATE TABLE revoked_access_tokens (
  jti        TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  reason     TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
