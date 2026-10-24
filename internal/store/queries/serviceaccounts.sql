-- name: InsertServiceAccount :exec
INSERT INTO service_accounts (id, tenant_id, slug, name, description, secret_mac, secret_hint, audiences, access_token_ttl_secs,
  managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetServiceAccount :one
SELECT * FROM service_accounts WHERE tenant_id = ? AND (id = sqlc.arg(ref) OR slug = sqlc.arg(ref));

-- name: GetServiceAccountByID :one
SELECT * FROM service_accounts WHERE id = ?;

-- name: ListServiceAccounts :many
SELECT * FROM service_accounts WHERE tenant_id = ? ORDER BY slug;

-- name: UpdateServiceAccount :execrows
UPDATE service_accounts SET name = ?, description = ?, enabled = ?, audiences = ?, access_token_ttl_secs = ?, managed_by = ?,
  last_changed_by = ?, updated_at = ?, version = version + 1
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: SetServiceAccountSecret :execrows
UPDATE service_accounts SET secret_mac = ?, secret_hint = ?, updated_at = ?, version = version + 1 WHERE tenant_id = ? AND id = ?;

-- name: TouchServiceAccount :exec
UPDATE service_accounts SET last_used_at = ? WHERE id = ?;

-- name: DeleteServiceAccount :execrows
DELETE FROM service_accounts WHERE tenant_id = ? AND id = ?;

-- name: DeleteSubjectAssignments :execrows
DELETE FROM role_assignments WHERE tenant_id = ? AND subject_type = ? AND subject_id = ?;
