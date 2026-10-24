-- name: InsertTenant :exec
INSERT INTO tenants (id, slug, name, status, version, managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, 'active', 1, ?, ?, ?, ?);

-- name: GetTenant :one
SELECT * FROM tenants WHERE id = ?;

-- name: GetTenantBySlug :one
SELECT * FROM tenants WHERE slug = ?;

-- name: UpdateTenant :execrows
UPDATE tenants SET name = ?, status = ?, session_idle_secs = ?, session_absolute_secs = ?, version = version + 1,
  managed_by = ?, last_changed_by = ?, updated_at = ?
WHERE id = ? AND version = ?;

-- name: DeleteTenant :execrows
DELETE FROM tenants WHERE id = ? AND version = ?;

-- name: CountTenants :one
SELECT count(*) FROM tenants;

-- name: InsertMembership :exec
INSERT INTO memberships (id, tenant_id, user_id, status, source, version, managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetMembership :one
SELECT * FROM memberships WHERE tenant_id = ? AND id = ?;

-- name: GetMembershipByUser :one
SELECT * FROM memberships WHERE tenant_id = ? AND user_id = ?;

-- name: UpdateMembershipStatus :execrows
UPDATE memberships SET status = ?, version = version + 1, managed_by = ?, last_changed_by = ?, updated_at = ?
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: ListUserMemberships :many
SELECT m.id, m.tenant_id, m.user_id, m.status, m.source, t.slug AS tenant_slug, t.name AS tenant_name, t.status AS tenant_status
FROM memberships m JOIN tenants t ON t.id = m.tenant_id
WHERE m.user_id = ? ORDER BY t.slug;

-- name: InsertGroup :exec
INSERT INTO groups (id, tenant_id, slug, name, description, version, managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetGroup :one
SELECT * FROM groups WHERE tenant_id = ? AND id = ?;

-- name: InsertGroupMember :exec
INSERT INTO group_members (tenant_id, group_id, user_id, source, created_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: ListGroupMembers :many
SELECT * FROM group_members WHERE tenant_id = ? AND group_id = ? ORDER BY user_id;

-- name: ListTenants :many
SELECT * FROM tenants WHERE id > sqlc.arg(after) ORDER BY id LIMIT sqlc.arg(lim);

-- name: ListMembers :many
SELECT m.id, m.tenant_id, m.user_id, m.status, m.source, m.version, m.managed_by, m.last_changed_by, m.created_at, m.updated_at,
  u.display_name, u.primary_email, u.status AS user_status
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id > sqlc.arg(after) ORDER BY m.id LIMIT sqlc.arg(lim);

-- name: ListAllTenants :many
SELECT id, slug, name, status FROM tenants ORDER BY slug;
