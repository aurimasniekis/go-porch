-- name: InsertApplication :exec
INSERT INTO applications (id, tenant_id, slug, name, kind, description, launch_url, enabled, disclosure_json, version, managed_by,
  last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetApplication :one
SELECT * FROM applications WHERE tenant_id = ? AND id = ?;

-- name: GetApplicationByID :one
SELECT * FROM applications WHERE id = ?;

-- name: ListApplications :many
SELECT * FROM applications WHERE tenant_id = ? ORDER BY slug;

-- name: UpdateApplication :execrows
UPDATE applications SET name = ?, description = ?, launch_url = ?, enabled = ?, disclosure_json = ?, version = version + 1, managed_by = ?,
  last_changed_by = ?, updated_at = ?
WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: DeleteApplication :execrows
DELETE FROM applications WHERE tenant_id = ? AND id = ? AND version = ?;

-- name: InsertClient :exec
INSERT INTO oauth_clients (id, tenant_id, app_id, client_type, application_type, secret_mac, secret_hint, redirect_uris, post_logout_uris,
  grant_types, allowed_scopes, audiences, allowed_origins, require_pkce, signing_alg, access_token_ttl_secs, id_token_ttl_secs,
  refresh_ttl_secs, refresh_idle_secs, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: GetClient :one
SELECT * FROM oauth_clients WHERE id = ?;

-- name: GetClientByApp :one
SELECT * FROM oauth_clients WHERE app_id = ?;

-- name: UpdateClient :execrows
UPDATE oauth_clients SET redirect_uris = ?, post_logout_uris = ?, grant_types = ?, allowed_scopes = ?, audiences = ?, allowed_origins = ?,
  require_pkce = ?, signing_alg = ?, access_token_ttl_secs = ?, id_token_ttl_secs = ?, refresh_ttl_secs = ?, refresh_idle_secs = ?,
  version = version + 1, updated_at = ?
WHERE id = ? AND version = ?;

-- name: SetClientSecret :execrows
UPDATE oauth_clients SET secret_mac = ?, secret_hint = ?, version = version + 1, updated_at = ? WHERE id = ? AND client_type = 'confidential';

-- name: ListAllowedOrigins :many
SELECT allowed_origins FROM oauth_clients WHERE allowed_origins != '[]';

-- name: InsertSigningKey :exec
INSERT INTO signing_keys (id, alg, private_enc, public_jwk, state, created_at) VALUES (?, ?, ?, ?, 'active', ?);

-- name: ListSigningKeys :many
SELECT * FROM signing_keys WHERE state != 'retired' ORDER BY created_at;

-- name: ListAllSigningKeys :many
SELECT * FROM signing_keys ORDER BY created_at;

-- name: GetActiveSigningKey :one
SELECT * FROM signing_keys WHERE alg = ? AND state = 'active';

-- name: SetSigningKeyRetiring :execrows
UPDATE signing_keys SET state = 'retiring', retire_after = ? WHERE id = ? AND state = 'active';

-- name: RetireSigningKeys :execrows
UPDATE signing_keys SET state = 'retired', retired_at = ? WHERE state = 'retiring' AND retire_after <= ?;

-- name: InsertAuthRequest :exec
INSERT INTO auth_requests (id, client_id, tenant_id, redirect_uri, scopes, state, nonce, code_challenge, response_mode, prompt, max_age,
  login_hint, resources, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuthRequest :one
SELECT * FROM auth_requests WHERE id = ?;

-- name: SetAuthRequestReauth :exec
UPDATE auth_requests SET reauth_session_id = ? WHERE id = ?;

-- name: DeleteAuthRequest :exec
DELETE FROM auth_requests WHERE id = ?;

-- name: PurgeAuthRequests :execrows
DELETE FROM auth_requests WHERE expires_at < ?;

-- name: InsertAuthCode :exec
INSERT INTO auth_codes (mac, id, client_id, tenant_id, user_id, session_id, redirect_uri, scopes, nonce, code_challenge, resources, auth_time,
  amr, auth_method, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuthCode :one
SELECT * FROM auth_codes WHERE mac = ?;

-- name: UseAuthCode :execrows
UPDATE auth_codes SET used_at = ? WHERE mac = ? AND used_at IS NULL;

-- name: SetAuthCodeTokens :exec
UPDATE auth_codes SET family_id = ?, access_jti = ? WHERE mac = ?;

-- name: PurgeAuthCodes :execrows
DELETE FROM auth_codes WHERE expires_at < ?;

-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (id, mac, family_id, parent_id, client_id, tenant_id, user_id, scopes, resources, auth_time, amr, auth_method,
  state, install_epoch, user_epoch, created_at, family_expires_at, idle_expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?);

-- name: GetRefreshTokenByMAC :one
SELECT * FROM refresh_tokens WHERE mac = ?;

-- name: RotateRefreshToken :execrows
UPDATE refresh_tokens SET state = 'rotated', rotated_at = ? WHERE id = ? AND state = 'active';

-- name: RevokeRefreshFamily :execrows
UPDATE refresh_tokens SET state = 'revoked', revoked_at = ?, revoke_reason = ? WHERE family_id = ? AND state != 'revoked';

-- name: RevokeUserClientRefresh :execrows
UPDATE refresh_tokens SET state = 'revoked', revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND client_id = ? AND state != 'revoked';

-- name: RevokeUserRefresh :execrows
UPDATE refresh_tokens SET state = 'revoked', revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND state != 'revoked';

-- name: ListUserRefreshFamilies :many
SELECT family_id, client_id, min(created_at) AS created_at, max(idle_expires_at) AS idle_expires_at
FROM refresh_tokens WHERE user_id = ? AND state = 'active' GROUP BY family_id, client_id;

-- name: PurgeRefreshTokens :execrows
DELETE FROM refresh_tokens WHERE family_expires_at < ?;

-- name: RevokeAccessToken :exec
INSERT INTO revoked_access_tokens (jti, expires_at, reason) VALUES (?, ?, ?) ON CONFLICT (jti) DO NOTHING;

-- name: IsAccessTokenRevoked :one
SELECT count(*) FROM revoked_access_tokens WHERE jti = ?;

-- name: PurgeRevokedAccessTokens :execrows
DELETE FROM revoked_access_tokens WHERE expires_at < ?;

-- name: ListUserGroupSlugs :many
SELECT g.slug FROM group_members m JOIN groups g ON g.tenant_id = m.tenant_id AND g.id = m.group_id
WHERE m.tenant_id = ? AND m.user_id = ? ORDER BY g.slug;

-- name: ListUserFamiliesWithApps :many
SELECT r.family_id, r.client_id, a.id AS app_id, a.name AS app_name, min(r.created_at) AS created_at, max(r.idle_expires_at) AS idle_expires_at
FROM refresh_tokens r JOIN oauth_clients c ON c.id = r.client_id JOIN applications a ON a.id = c.app_id
WHERE r.user_id = ? AND r.state = 'active' GROUP BY r.family_id, r.client_id, a.id, a.name ORDER BY created_at DESC;

-- name: RevokeUserFamily :execrows
UPDATE refresh_tokens SET state = 'revoked', revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND family_id = ? AND state != 'revoked';

-- name: ListAudienceOwners :many
SELECT tenant_id, audiences FROM oauth_clients
UNION ALL
SELECT tenant_id, audiences FROM service_accounts;

-- name: MarkAuthCodeReplayed :exec
UPDATE auth_codes SET replayed_at = ? WHERE mac = ?;

-- name: GetApplicationIDBySlug :one
SELECT id FROM applications WHERE tenant_id = ? AND slug = ?;
