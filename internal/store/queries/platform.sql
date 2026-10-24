-- name: GetInstallation :one
SELECT id, installation_id, security_epoch, setup_completed_at, created_at, updated_at FROM installation WHERE id = 1;

-- name: InsertInstallation :exec
INSERT INTO installation (id, installation_id, security_epoch, created_at, updated_at) VALUES (1, ?, 1, ?, ?)
ON CONFLICT (id) DO NOTHING;

-- name: MarkSetupCompleted :execrows
UPDATE installation SET setup_completed_at = ?, updated_at = ? WHERE id = 1 AND setup_completed_at IS NULL;

-- name: BumpSecurityEpoch :one
UPDATE installation SET security_epoch = security_epoch + 1, updated_at = ? WHERE id = 1 RETURNING security_epoch;

-- name: GetSetting :one
SELECT key, value, updated_at, updated_by FROM settings WHERE key = ?;

-- name: UpsertSetting :exec
INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by;

-- name: ListKeyringKeys :many
SELECT id, purpose, version, wrapped, wrap_kek_id, state, created_at, updated_at
FROM keyring_keys ORDER BY purpose, version;

-- name: InsertKeyringKey :exec
INSERT INTO keyring_keys (id, purpose, version, wrapped, wrap_kek_id, state, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateKeyringKeyState :execrows
UPDATE keyring_keys SET state = ?, updated_at = ? WHERE id = ?;

-- name: UpdateKeyringKeyWrap :execrows
UPDATE keyring_keys SET wrapped = ?, wrap_kek_id = ?, updated_at = ? WHERE id = ?;

-- name: LastAuditEvent :one
SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, seq, at, request_id, actor_type, actor_id, tenant_id, action, target_type, target_id, outcome,
  reason_code, source_ip, auth_method, details_json, details_enc, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: AuditEventsFrom :many
SELECT id, seq, at, request_id, actor_type, actor_id, tenant_id, action, target_type, target_id, outcome, reason_code,
  source_ip, auth_method, details_json, details_enc, prev_hash, hash
FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?;

-- name: CountAuditEvents :one
SELECT count(*) FROM audit_events;

-- name: InsertOutbox :exec
INSERT INTO outbox (id, type, subject, tenant_id, payload_json, created_at, attempts, next_attempt_at)
VALUES (?, ?, ?, ?, ?, ?, 0, ?);

-- name: DueOutbox :many
SELECT id, type, subject, tenant_id, payload_json, created_at, attempts, next_attempt_at, last_error, published_at, dead_at
FROM outbox WHERE published_at IS NULL AND dead_at IS NULL AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?;

-- name: MarkOutboxPublished :execrows
UPDATE outbox SET published_at = ?, attempts = attempts + 1, last_error = NULL WHERE id = ? AND published_at IS NULL;

-- name: MarkOutboxRetry :execrows
UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ? AND published_at IS NULL;

-- name: MarkOutboxDead :execrows
UPDATE outbox SET attempts = attempts + 1, dead_at = ?, last_error = ? WHERE id = ? AND published_at IS NULL;

-- name: CountOutbox :one
SELECT
  coalesce(sum(CASE WHEN published_at IS NULL AND dead_at IS NULL THEN 1 ELSE 0 END), 0) AS pending,
  coalesce(sum(CASE WHEN dead_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS dead,
  coalesce(min(CASE WHEN published_at IS NULL AND dead_at IS NULL THEN created_at END), 0) AS oldest_pending_at
FROM outbox;

-- name: PurgePublishedOutbox :execrows
DELETE FROM outbox WHERE published_at IS NOT NULL AND published_at < ?;

-- name: InsertJob :execrows
INSERT INTO jobs (id, kind, run_at, attempts, max_attempts, state, payload_json, dedup_key, created_at, updated_at)
VALUES (?, ?, ?, 0, ?, 'queued', ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: DueJobs :many
SELECT id, kind, run_at, attempts, max_attempts, lease_until, state, payload_json, last_error, dedup_key, created_at, updated_at
FROM jobs
WHERE (state = 'queued' AND run_at <= sqlc.arg(now)) OR (state = 'running' AND lease_until < sqlc.arg(now))
ORDER BY run_at LIMIT sqlc.arg(lim);

-- name: ClaimJob :execrows
UPDATE jobs SET state = 'running', attempts = attempts + 1, lease_until = sqlc.arg(lease_until), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND ((state = 'queued') OR (state = 'running' AND lease_until < sqlc.arg(now)));

-- name: FinishJob :exec
UPDATE jobs SET state = ?, run_at = ?, lease_until = NULL, last_error = ?, updated_at = ? WHERE id = ?;

-- name: GetJob :one
SELECT id, kind, run_at, attempts, max_attempts, lease_until, state, payload_json, last_error, dedup_key, created_at, updated_at
FROM jobs WHERE id = ?;

-- name: PurgeFinishedJobs :execrows
DELETE FROM jobs WHERE state IN ('done', 'dead') AND updated_at < ?;

-- name: ListSettings :many
SELECT key, value, updated_at, updated_by FROM settings ORDER BY key;
