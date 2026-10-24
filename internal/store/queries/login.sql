-- name: InsertProvider :exec
INSERT INTO identity_providers (id, slug, kind, name, issuer, client_id, secret_enc, allowed_hds, scopes, enabled, version, managed_by,
  last_changed_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetProvider :one
SELECT * FROM identity_providers WHERE id = ?;

-- name: GetProviderBySlug :one
SELECT * FROM identity_providers WHERE slug = ?;

-- name: ListProviders :many
SELECT * FROM identity_providers ORDER BY slug;

-- name: UpdateProvider :execrows
UPDATE identity_providers SET name = ?, issuer = ?, client_id = ?, secret_enc = ?, allowed_hds = ?, scopes = ?, enabled = ?,
  version = version + 1, managed_by = ?, last_changed_by = ?, updated_at = ?
WHERE id = ? AND version = ?;

-- name: DeleteProvider :execrows
DELETE FROM identity_providers WHERE id = ? AND version = ?;

-- name: GetExternalIdentity :one
SELECT * FROM external_identities WHERE provider_id = ? AND issuer = ? AND subject = ?;

-- name: InsertExternalIdentity :exec
INSERT INTO external_identities (id, provider_id, issuer, subject, user_id, email, hd, linked_at, last_login_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: TouchExternalIdentity :exec
UPDATE external_identities SET email = ?, hd = ?, last_login_at = ? WHERE id = ?;

-- name: ListUserIdentities :many
SELECT e.*, p.slug AS provider_slug, p.name AS provider_name, p.kind AS provider_kind
FROM external_identities e JOIN identity_providers p ON p.id = e.provider_id WHERE e.user_id = ? ORDER BY e.linked_at;

-- name: DeleteExternalIdentity :execrows
DELETE FROM external_identities WHERE id = ? AND user_id = ?;

-- name: InsertDomainRule :exec
INSERT INTO domain_rules (id, domain, tenant_id, provider_id, evidence_kind, mode, baseline_role_ids, version, managed_by, last_changed_by,
  created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetDomainRule :one
SELECT * FROM domain_rules WHERE id = ?;

-- name: GetDomainRuleByDomain :one
SELECT * FROM domain_rules WHERE domain = ?;

-- name: ListDomainRules :many
SELECT * FROM domain_rules ORDER BY domain;

-- name: UpdateDomainRule :execrows
UPDATE domain_rules SET mode = ?, evidence_kind = ?, baseline_role_ids = ?, version = version + 1, managed_by = ?, last_changed_by = ?,
  updated_at = ?
WHERE id = ? AND version = ?;

-- name: DeleteDomainRule :execrows
DELETE FROM domain_rules WHERE id = ? AND version = ?;

-- name: ListDerivedMemberships :many
SELECT * FROM memberships WHERE user_id = ? AND source LIKE 'domain_rule:%';

-- name: ListMembershipsBySource :many
SELECT * FROM memberships WHERE source = ?;

-- name: DeleteMembershipByID :execrows
DELETE FROM memberships WHERE id = ?;

-- name: InsertInvite :exec
INSERT INTO invites (id, tenant_id, email, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: FindOpenInvite :one
SELECT * FROM invites WHERE email = ? AND consumed_at IS NULL AND expires_at > ? ORDER BY created_at LIMIT 1;

-- name: FindOpenInviteForTenant :one
SELECT * FROM invites WHERE tenant_id = ? AND email = ? AND consumed_at IS NULL AND expires_at > ? ORDER BY created_at LIMIT 1;

-- name: ConsumeInvite :execrows
UPDATE invites SET consumed_at = ?, consumed_by = ? WHERE id = ? AND consumed_at IS NULL;

-- name: ListInvites :many
SELECT * FROM invites WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 200;

-- name: DeleteInvite :execrows
DELETE FROM invites WHERE tenant_id = ? AND id = ?;

-- name: InsertLoginState :exec
INSERT INTO oidc_login_states (id, state_mac, provider_id, intent, session_id, secrets_enc, return_to, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: TakeLoginState :one
DELETE FROM oidc_login_states WHERE state_mac = ? RETURNING *;

-- name: PurgeLoginStates :execrows
DELETE FROM oidc_login_states WHERE expires_at < ?;

-- name: GetBackupCredential :one
SELECT * FROM backup_credentials WHERE user_id = ?;

-- name: UpsertBackupCredential :exec
INSERT INTO backup_credentials (user_id, password_enc, answers_enc, pair_count, enrolled_at, rotated_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET password_enc = excluded.password_enc, answers_enc = excluded.answers_enc,
  pair_count = excluded.pair_count, rotated_at = excluded.rotated_at;

-- name: UpdateBackupPassword :exec
UPDATE backup_credentials SET password_enc = ? WHERE user_id = ?;

-- name: UpdateBackupAnswers :exec
UPDATE backup_credentials SET answers_enc = ? WHERE user_id = ?;

-- name: DeleteBackupCredential :execrows
DELETE FROM backup_credentials WHERE user_id = ?;

-- name: DeleteRecoveryPairs :exec
DELETE FROM recovery_pairs WHERE user_id = ?;

-- name: InsertRecoveryPair :exec
INSERT INTO recovery_pairs (id, user_id, position, title_enc) VALUES (?, ?, ?, ?);

-- name: ListRecoveryPairs :many
SELECT * FROM recovery_pairs WHERE user_id = ? ORDER BY position;

-- name: GetUserByBackupHandle :one
SELECT * FROM users WHERE backup_handle = ?;

-- name: GetUsersByPrimaryEmail :many
SELECT * FROM users WHERE primary_email = ? LIMIT 2;

-- name: SetBackupHandle :execrows
UPDATE users SET backup_handle = ?, updated_at = ? WHERE id = ?;

-- name: GetBackupLockout :one
SELECT * FROM backup_lockouts WHERE user_id = ?;

-- name: UpsertBackupLockout :exec
INSERT INTO backup_lockouts (user_id, failures, locked_until, level, updated_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET failures = excluded.failures, locked_until = excluded.locked_until, level = excluded.level,
  updated_at = excluded.updated_at;

-- name: InsertBackupChallenge :exec
INSERT INTO backup_challenges (id, mac, user_id, source_key, session_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetBackupChallengeByMAC :one
SELECT * FROM backup_challenges WHERE mac = ?;

-- name: ConsumeBackupChallenge :execrows
UPDATE backup_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL;

-- name: PurgeBackupChallenges :execrows
DELETE FROM backup_challenges WHERE expires_at < ?;

-- name: GetThrottle :one
SELECT * FROM throttle_buckets WHERE key = ?;

-- name: UpsertThrottle :exec
INSERT INTO throttle_buckets (key, window_start, count) VALUES (?, ?, ?)
ON CONFLICT (key) DO UPDATE SET window_start = excluded.window_start, count = excluded.count;

-- name: PurgeThrottles :execrows
DELETE FROM throttle_buckets WHERE window_start < ?;

-- name: InsertRecoveryLink :exec
INSERT INTO recovery_links (id, mac, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?);

-- name: GetRecoveryLinkByMAC :one
SELECT * FROM recovery_links WHERE mac = ?;

-- name: ConsumeRecoveryLink :execrows
UPDATE recovery_links SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL;

-- name: InsertAlert :exec
INSERT INTO alerts (id, kind, severity, message, target_id, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListOpenAlerts :many
SELECT * FROM alerts WHERE acknowledged_at IS NULL ORDER BY created_at DESC;

-- name: AcknowledgeAlert :execrows
UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL;
