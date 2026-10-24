-- name: InsertRole :exec
INSERT INTO roles (id, tenant_id, slug, name, description, built_in, version, managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetRole :one
SELECT * FROM roles WHERE tenant_id = ? AND id = ?;

-- name: GetRoleBySlug :one
SELECT * FROM roles WHERE tenant_id = ? AND slug = ?;

-- name: ListRoles :many
SELECT * FROM roles WHERE tenant_id = ? ORDER BY slug;

-- name: UpdateRole :execrows
UPDATE roles SET name = ?, description = ?, version = version + 1, managed_by = ?, last_changed_by = ?, updated_at = ?
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: DeleteRole :execrows
DELETE FROM roles WHERE tenant_id = ? AND id = ? AND built_in = 0;

-- name: InsertRolePermission :exec
INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES (?, ?, ?) ON CONFLICT DO NOTHING;

-- name: DeleteRolePermissions :exec
DELETE FROM role_permissions WHERE tenant_id = ? AND role_id = ?;

-- name: ListTenantRolePermissions :many
SELECT role_id, permission FROM role_permissions WHERE tenant_id = ? ORDER BY role_id, permission;

-- name: InsertRoleEdge :exec
INSERT INTO role_edges (tenant_id, parent_id, child_id) VALUES (?, ?, ?);

-- name: DeleteRoleEdges :exec
DELETE FROM role_edges WHERE tenant_id = ? AND parent_id = ?;

-- name: ListRoleEdges :many
SELECT parent_id, child_id FROM role_edges WHERE tenant_id = ?;

-- name: InsertGroupEdge :exec
INSERT INTO group_edges (tenant_id, parent_id, child_id) VALUES (?, ?, ?);

-- name: DeleteGroupEdge :execrows
DELETE FROM group_edges WHERE tenant_id = ? AND parent_id = ? AND child_id = ?;

-- name: ListGroupEdges :many
SELECT parent_id, child_id FROM group_edges WHERE tenant_id = ?;

-- name: ListGroups :many
SELECT * FROM groups WHERE tenant_id = ? ORDER BY slug;

-- name: UpdateGroup :execrows
UPDATE groups SET name = ?, description = ?, version = version + 1, managed_by = ?, last_changed_by = ?, updated_at = ?
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: DeleteGroup :execrows
DELETE FROM groups WHERE tenant_id = ? AND id = ?;

-- name: DeleteGroupMember :execrows
DELETE FROM group_members WHERE tenant_id = ? AND group_id = ? AND user_id = ?;

-- name: ListUserGroupIDs :many
SELECT group_id FROM group_members WHERE tenant_id = ? AND user_id = ?;

-- name: InsertResource :exec
INSERT INTO resources (id, tenant_id, type, slug, name, parent_id, attributes_json, version, managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetResource :one
SELECT * FROM resources WHERE tenant_id = ? AND id = ?;

-- name: ListResources :many
SELECT * FROM resources WHERE tenant_id = ? ORDER BY type, slug;

-- name: UpdateResource :execrows
UPDATE resources SET name = ?, attributes_json = ?, version = version + 1, managed_by = ?, last_changed_by = ?, updated_at = ?
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: DeleteResource :execrows
DELETE FROM resources WHERE tenant_id = ? AND id = ?;

-- name: InsertPolicy :exec
INSERT INTO policies (id, tenant_id, slug, name, effect, actions, expression, env_version, compiled_hash, version, managed_by, last_changed_by,
  created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetPolicy :one
SELECT * FROM policies WHERE tenant_id = ? AND id = ?;

-- name: ListPolicies :many
SELECT * FROM policies WHERE tenant_id = ? ORDER BY slug;

-- name: UpdatePolicy :execrows
UPDATE policies SET name = ?, actions = ?, expression = ?, compiled_hash = ?, version = version + 1, managed_by = ?, last_changed_by = ?,
  updated_at = ?
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: DeletePolicy :execrows
DELETE FROM policies WHERE tenant_id = ? AND id = ?;

-- name: InsertAssignment :exec
INSERT INTO role_assignments (id, tenant_id, subject_type, subject_id, role_id, scope_type, scope_resource_type, scope_resource_id,
  condition_policy_id, expires_at, source, created_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAssignment :one
SELECT * FROM role_assignments WHERE tenant_id = ? AND id = ?;

-- name: ListAssignments :many
SELECT * FROM role_assignments WHERE tenant_id = ? ORDER BY created_at;

-- name: ListSubjectAssignments :many
SELECT * FROM role_assignments WHERE tenant_id = ? AND subject_type = ? AND subject_id IN (sqlc.slice(subject_ids));

-- name: DeleteAssignment :execrows
DELETE FROM role_assignments WHERE tenant_id = ? AND id = ?;

-- name: DeleteAssignmentsBySource :execrows
DELETE FROM role_assignments WHERE tenant_id = ? AND source = ?;

-- name: GetAuthzEpoch :one
SELECT epoch FROM authz_epochs WHERE tenant_id = ?;

-- name: BumpAuthzEpoch :exec
INSERT INTO authz_epochs (tenant_id, epoch) VALUES (?, 1) ON CONFLICT (tenant_id) DO UPDATE SET epoch = epoch + 1;

-- name: SetApplicationAccess :execrows
UPDATE applications SET access_mode = ?, forward_headers = ?, version = version + 1, updated_at = ? WHERE tenant_id = ? AND id = ?;

-- name: InsertAppHost :exec
INSERT INTO app_hosts (host, tenant_id, app_id) VALUES (?, ?, ?);

-- name: DeleteAppHosts :exec
DELETE FROM app_hosts WHERE tenant_id = ? AND app_id = ?;

-- name: ListAppHosts :many
SELECT host FROM app_hosts WHERE app_id = ? ORDER BY host;

-- name: GetAppHost :one
SELECT * FROM app_hosts WHERE host = ?;

-- name: InsertAppShare :exec
INSERT INTO app_shares (tenant_id, app_id, target_tenant_id, granted_by, created_at) VALUES (?, ?, ?, ?, ?);

-- name: DeleteAppShare :execrows
DELETE FROM app_shares WHERE tenant_id = ? AND app_id = ? AND target_tenant_id = ?;

-- name: ListAppShares :many
SELECT s.*, t.slug AS target_slug, t.name AS target_name FROM app_shares s JOIN tenants t ON t.id = s.target_tenant_id
WHERE s.tenant_id = ? AND s.app_id = ? ORDER BY t.slug;

-- name: GetAppShare :one
SELECT * FROM app_shares WHERE app_id = ? AND target_tenant_id = ?;

-- name: ListAppsSharedTo :many
SELECT a.* FROM applications a JOIN app_shares s ON s.app_id = a.id WHERE s.target_tenant_id = ? ORDER BY a.slug;

-- name: InsertForwardAuthCode :exec
INSERT INTO forward_auth_codes (mac, app_id, host, tenant_id, user_id, session_id, return_to, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: TakeForwardAuthCode :one
UPDATE forward_auth_codes SET used_at = ? WHERE mac = ? AND used_at IS NULL RETURNING *;

-- name: PurgeForwardAuthCodes :execrows
DELETE FROM forward_auth_codes WHERE expires_at < ?;

-- name: InsertForwardAuthSession :exec
INSERT INTO forward_auth_sessions (id, mac, app_id, host, tenant_id, user_id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetForwardAuthSession :one
SELECT * FROM forward_auth_sessions WHERE mac = ?;

-- name: RevokeForwardAuthSession :execrows
UPDATE forward_auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: PurgeForwardAuthSessions :execrows
DELETE FROM forward_auth_sessions WHERE expires_at < ?;
