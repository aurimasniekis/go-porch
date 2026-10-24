-- 0011_appearance: application icons and launcher groups, and the media store for icons and login backgrounds
-- (ADR-0045). Images are fetched or uploaded, decoded and re-encoded by Porch, and served from Porch's own origin.

-- +goose Up
CREATE TABLE media (
  id           TEXT NOT NULL PRIMARY KEY, -- hex SHA-256 of data
  kind         TEXT NOT NULL CHECK (kind IN ('icon', 'background')),
  content_type TEXT NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg', 'image/svg+xml')),
  data         BLOB NOT NULL,
  width        INTEGER NOT NULL,
  height       INTEGER NOT NULL,
  -- Backgrounds: where the image came from and how to credit it (plain text, never HTML).
  title        TEXT NOT NULL DEFAULT '',
  author       TEXT NOT NULL DEFAULT '',
  license      TEXT NOT NULL DEFAULT '',
  license_url  TEXT NOT NULL DEFAULT '',
  source_url   TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

ALTER TABLE applications ADD COLUMN group_name TEXT NOT NULL DEFAULT '' CHECK (length(group_name) <= 64);
ALTER TABLE applications ADD COLUMN icon_source TEXT NOT NULL DEFAULT ''
  CHECK (icon_source IN ('', 'url', 'dashboard_icons', 'thesvg', 'upload'));
ALTER TABLE applications ADD COLUMN icon_ref TEXT NOT NULL DEFAULT '' CHECK (length(icon_ref) <= 512);
ALTER TABLE applications ADD COLUMN icon_media_id TEXT REFERENCES media (id);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
