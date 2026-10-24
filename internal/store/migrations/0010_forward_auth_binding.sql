-- 0010_forward_auth_binding (+ upstream confirmation time): forward-auth sign-in codes are bound to the browser (security review L8). The first code
-- (issued at /outpost/start) is exchanged at /outpost/confirm, on Porch's origin, only by the browser holding the Porch
-- session it was issued to; the second code is redeemable only together with a host-only nonce cookie that
-- /.porch/callback set in that same browser.

-- +goose Up
ALTER TABLE forward_auth_codes ADD COLUMN nonce_mac BLOB;
ALTER TABLE forward_auth_codes ADD COLUMN origin TEXT NOT NULL DEFAULT '';

-- When the identity provider last confirmed each user (login, hourly recheck, step-up). Automation tokens of users
-- with external identities stop working when this is too old (security review L3).
ALTER TABLE users ADD COLUMN upstream_confirmed_at INTEGER;

-- A replayed authorization code is marked, so a replay that arrives while the first exchange is still issuing tokens
-- still gets them revoked (the first exchange checks the mark when it records what it issued).
ALTER TABLE auth_codes ADD COLUMN replayed_at INTEGER;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
