-- 0012_token_never_expires: installation owners may issue installation tokens that never expire (ADR-0046,
-- security-relevant). Such rows keep a far-future expires_at so every existing comparison and cleanup still holds.

-- +goose Up
ALTER TABLE automation_tokens ADD COLUMN never_expires INTEGER NOT NULL DEFAULT 0
  CHECK (never_expires IN (0, 1) AND (never_expires = 0 OR kind = 'installation'));

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
