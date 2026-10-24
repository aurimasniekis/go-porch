-- name: InsertMedia :exec
INSERT INTO media (id, kind, content_type, data, width, height, title, author, license, license_url, source_url, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET title = excluded.title, author = excluded.author, license = excluded.license,
  license_url = excluded.license_url, source_url = excluded.source_url;

-- name: GetMedia :one
SELECT * FROM media WHERE id = ?;

-- name: ListBackgrounds :many
SELECT id, content_type, width, height, title, author, license, license_url, source_url, created_at
FROM media WHERE kind = 'background' ORDER BY created_at, id;

-- name: DeleteBackgroundsExcept :exec
DELETE FROM media WHERE kind = 'background' AND id NOT IN (sqlc.slice('keep'));

-- name: DeleteAllBackgrounds :exec
DELETE FROM media WHERE kind = 'background';

-- name: DeleteUnusedIcons :execrows
DELETE FROM media WHERE media.kind = 'icon' AND media.created_at < sqlc.arg(before) AND media.id NOT IN (
  SELECT a.icon_media_id FROM applications a WHERE a.icon_media_id IS NOT NULL);
