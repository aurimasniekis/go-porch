-- name: InsertBackupRun :exec
INSERT INTO backup_runs (id, trigger, started_at) VALUES (?, ?, ?);

-- name: FinishBackupRun :exec
UPDATE backup_runs SET finished_at = ?, ok = ?, error = ?, db_bytes = ?, stored_bytes = ?, kek_included = ?, pruned = ? WHERE id = ?;

-- name: ListBackupRuns :many
SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT ?;

-- name: LastSuccessfulBackupRun :one
SELECT * FROM backup_runs WHERE ok = 1 ORDER BY started_at DESC LIMIT 1;

-- name: PurgeBackupRuns :execrows
DELETE FROM backup_runs WHERE started_at < ?;

-- name: DeleteBackupCredentials :execrows
DELETE FROM backup_credentials;
