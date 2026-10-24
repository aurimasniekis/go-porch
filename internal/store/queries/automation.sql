-- name: InsertAutomationToken :exec
INSERT INTO automation_tokens (id, mac, hint, name, kind, tenant_id, role, permissions, created_by, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAutomationTokenByMAC :one
SELECT * FROM automation_tokens WHERE mac = ?;

-- name: GetAutomationToken :one
SELECT * FROM automation_tokens WHERE id = ?;

-- name: ListAutomationTokens :many
SELECT t.*, u.display_name AS creator_name FROM automation_tokens t JOIN users u ON u.id = t.created_by
WHERE (sqlc.narg(tenant_id) IS NULL AND t.tenant_id IS NULL) OR t.tenant_id = sqlc.narg(tenant_id)
ORDER BY t.created_at DESC;

-- name: TouchAutomationToken :exec
UPDATE automation_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?;

-- name: RevokeAutomationToken :execrows
UPDATE automation_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeUserAutomationTokens :execrows
UPDATE automation_tokens SET revoked_at = ? WHERE created_by = ? AND revoked_at IS NULL;

-- name: PurgeAutomationTokens :execrows
DELETE FROM automation_tokens WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?);

-- name: GetIdempotencyKey :one
SELECT * FROM idempotency_keys WHERE key_mac = ? AND expires_at > ?;

-- name: InsertIdempotencyKey :execrows
INSERT INTO idempotency_keys (key_mac, request_hash, method, path, state, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)
ON CONFLICT (key_mac) DO UPDATE SET request_hash = excluded.request_hash, method = excluded.method, path = excluded.path, state = 'pending',
  status = 0, content_type = '', body = NULL, secret_withheld = 0, location = '', created_at = excluded.created_at, expires_at = excluded.expires_at
WHERE idempotency_keys.expires_at <= excluded.created_at;

-- name: CompleteIdempotencyKey :exec
UPDATE idempotency_keys SET state = 'done', status = ?, content_type = ?, body = ?, secret_withheld = ?, location = ? WHERE key_mac = ?;

-- name: DeleteIdempotencyKey :exec
DELETE FROM idempotency_keys WHERE key_mac = ?;

-- name: PurgeIdempotencyKeys :execrows
DELETE FROM idempotency_keys WHERE expires_at < ?;
