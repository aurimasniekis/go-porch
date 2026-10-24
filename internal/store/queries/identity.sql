-- name: InsertUser :exec
INSERT INTO users (id, public_id, display_name, primary_email, status, version, managed_by, last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, 'active', 1, ?, ?, ?, ?);

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByPublicID :one
SELECT * FROM users WHERE public_id = ?;

-- name: UpdateUser :execrows
UPDATE users SET display_name = ?, primary_email = ?, status = ?, version = version + 1, managed_by = ?, last_changed_by = ?,
  updated_at = ?
WHERE id = ? AND version = ?;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = ? AND version = ?;

-- name: BumpUserEpoch :exec
UPDATE users SET security_epoch = security_epoch + 1, updated_at = ? WHERE id = ?;

-- name: TouchUserLogin :exec
UPDATE users SET last_login_at = ? WHERE id = ?;

-- name: UpsertUserEmail :exec
INSERT INTO user_emails (id, user_id, email, verified, source, created_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (user_id, email) DO UPDATE SET verified = max(verified, excluded.verified);

-- name: ListUserEmails :many
SELECT * FROM user_emails WHERE user_id = ? ORDER BY email;

-- name: InsertOperatorRole :exec
INSERT INTO installation_role_assignments (id, user_id, role, source, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListOperatorRoles :many
SELECT role FROM installation_role_assignments WHERE user_id = ? ORDER BY role;

-- name: CountOperators :one
SELECT count(*) FROM installation_role_assignments;

-- name: DeleteOperatorRole :execrows
DELETE FROM installation_role_assignments WHERE user_id = ? AND role = ?;

-- name: CountOwners :one
SELECT count(*) FROM installation_role_assignments WHERE role = 'owner';

-- name: InsertSetupToken :exec
INSERT INTO setup_tokens (id, mac, created_at, expires_at) VALUES (?, ?, ?, ?);

-- name: GetSetupTokenByMAC :one
SELECT * FROM setup_tokens WHERE mac = ?;

-- name: ConsumeSetupToken :execrows
UPDATE setup_tokens SET consumed_at = ?, consumed_by = ? WHERE id = ? AND consumed_at IS NULL;

-- name: ListUsers :many
SELECT * FROM users
WHERE id > sqlc.arg(after)
  AND (sqlc.narg(email) IS NULL OR primary_email = sqlc.narg(email))
  AND (sqlc.narg(status) IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(q) IS NULL OR instr(lower(display_name), sqlc.narg(q)) > 0 OR instr(lower(coalesce(primary_email, '')), sqlc.narg(q)) > 0)
ORDER BY id LIMIT sqlc.arg(lim);

-- name: ListOperators :many
SELECT a.user_id, a.role, a.source, a.created_at, u.display_name, u.primary_email
FROM installation_role_assignments a JOIN users u ON u.id = a.user_id ORDER BY a.user_id, a.role;

-- name: HasOperatorRole :one
SELECT count(*) FROM installation_role_assignments WHERE user_id = ? AND role IN (sqlc.slice(roles));

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: CountActiveOwnersExcept :one
SELECT count(*) FROM installation_role_assignments a JOIN users u ON u.id = a.user_id
WHERE a.role = 'owner' AND u.status = 'active' AND u.id != ?;
