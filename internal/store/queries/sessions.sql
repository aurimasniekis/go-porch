-- name: InsertSession :exec
INSERT INTO sessions (id, mac, user_id, tenant_id, method, provider_id, auth_time, upstream_checked_at, csrf_secret,
  install_epoch, user_epoch, idle_secs, absolute_expires_at, created_at, last_seen_at, ip, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSessionByMAC :one
SELECT * FROM sessions WHERE mac = ?;

-- name: GetSession :one
SELECT * FROM sessions WHERE id = ?;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: SetSessionTenant :execrows
UPDATE sessions SET tenant_id = ? WHERE id = ? AND revoked_at IS NULL;

-- name: SetSessionAuthTime :execrows
UPDATE sessions SET auth_time = ?, upstream_checked_at = coalesce(?, upstream_checked_at) WHERE id = ? AND revoked_at IS NULL;

-- name: SetSessionUpstreamChecked :execrows
UPDATE sessions SET upstream_checked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeSession :execrows
UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeUserSessions :execrows
UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL;

-- name: ListUserSessions :many
SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND absolute_expires_at > ? ORDER BY created_at DESC;

-- name: PurgeSessions :execrows
DELETE FROM sessions WHERE absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?);
