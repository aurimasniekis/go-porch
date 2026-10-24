-- 0009_membership_cleanup (+ idempotency ETag): a user who leaves a tenant loses their role assignments there (security review M3), on every
-- path that deletes a membership (manual removal, domain-rule evidence loss, rule deletion). Re-adding the user must
-- not resurrect old grants. The tenant's authz epoch is bumped so cached models refresh.

-- +goose Up
-- +goose StatementBegin
CREATE TRIGGER memberships_cleanup_assignments AFTER DELETE ON memberships
BEGIN
  DELETE FROM role_assignments WHERE tenant_id = OLD.tenant_id AND subject_type = 'user' AND subject_id = OLD.user_id;
  UPDATE authz_epochs SET epoch = epoch + 1 WHERE tenant_id = OLD.tenant_id;
END;
-- +goose StatementEnd

-- Assignments left behind by memberships removed before this migration.
DELETE FROM role_assignments
WHERE subject_type = 'user'
  AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id = role_assignments.tenant_id AND m.user_id = role_assignments.subject_id);

-- Idempotent replays repeat the original ETag (Terraform reads versions from it).
ALTER TABLE idempotency_keys ADD COLUMN etag TEXT NOT NULL DEFAULT '';

-- The sign-in method behind codes and refresh tokens, so deny policies on principal.auth_method also apply when a code
-- is exchanged and at every refresh (review M11).
ALTER TABLE auth_codes ADD COLUMN auth_method TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN auth_method TEXT NOT NULL DEFAULT '';

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
