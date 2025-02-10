-- Create the 'blobs' table if it doesn't exist
CREATE TABLE IF NOT EXISTS blobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data BLOB NOT NULL,
    name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    username TEXT NOT NULL,
    content_length INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Trigger: update 'updated_at' on row changes
CREATE TRIGGER IF NOT EXISTS blobs_update_timestamp
AFTER UPDATE ON blobs
BEGIN
    UPDATE blobs
    SET updated_at = CURRENT_TIMESTAMP
    WHERE id = new.id;
END;

-- Table: Filesystem
CREATE TABLE IF NOT EXISTS filesystem (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    depth INTEGER,
    path TEXT NOT NULL UNIQUE,
    is_directory BOOLEAN NOT NULL,
    description TEXT,
    content TEXT,
    permissions TEXT NOT NULL,
    blob_id INTEGER REFERENCES blobs(id) ON DELETE SET NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index: Filesystem depth
CREATE INDEX IF NOT EXISTS idx_filesystem_depth ON filesystem(depth);

-- Index: Filesystem created at
CREATE INDEX IF NOT EXISTS idx_filesystem_created_at ON filesystem(created_at);

-- Index: Filesystem updated at
CREATE INDEX IF NOT EXISTS idx_filesystem_updated_at ON filesystem(updated_at);

-- Index: Filesystem directory status
CREATE INDEX IF NOT EXISTS idx_filesystem_is_directory ON filesystem(is_directory);

-- Trigger: Set filesystem depth after insert
CREATE TRIGGER IF NOT EXISTS filesystem_set_depth
AFTER INSERT ON filesystem
BEGIN
    UPDATE filesystem
    SET depth = (LENGTH(path) - LENGTH(REPLACE(path, '/', '')))
    WHERE id = new.id;
END;

-- Trigger: After filesystem update, set depth
CREATE TRIGGER IF NOT EXISTS filesystem_update_depth
AFTER UPDATE OF path ON filesystem
BEGIN
    UPDATE filesystem
    SET depth = (LENGTH(path) - LENGTH(REPLACE(path, '/', '')))
    WHERE id = new.id;
END;

-- Trigger: If a filesystem row is deleted, and no other rows reference that old.blob_id,
--          remove the blob from the "blobs" table.
CREATE TRIGGER IF NOT EXISTS filesystem_delete_blob_after_delete
AFTER DELETE ON filesystem
WHEN old.blob_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM filesystem WHERE blob_id = old.blob_id)
BEGIN
    DELETE FROM blobs WHERE id = old.blob_id;
END;

-- Trigger: If a filesystem row updates blob_id to a new value (or to NULL),
--          and the old blob_id is no longer referenced by any filesystem rows,
--          remove the blob from the "blobs" table.
CREATE TRIGGER IF NOT EXISTS filesystem_delete_blob_after_update
AFTER UPDATE OF blob_id ON filesystem
WHEN old.blob_id IS NOT NULL
  AND old.blob_id != new.blob_id
  AND NOT EXISTS (SELECT 1 FROM filesystem WHERE blob_id = old.blob_id)
BEGIN
    DELETE FROM blobs WHERE id = old.blob_id;
END;

-- Virtual table: Filesystem path FTS
CREATE VIRTUAL TABLE IF NOT EXISTS filesystem_path_fts USING fts5(
    path,
    tokenize = "unicode61 remove_diacritics 0 tokenchars '/.'"
);

-- Insert: Existing filesystem records into path FTS
INSERT INTO filesystem_path_fts(rowid, path)
SELECT id, path FROM filesystem
WHERE NOT EXISTS (SELECT 1 FROM filesystem_path_fts WHERE rowid = filesystem.id);

-- Trigger: After filesystem insert, insert into path FTS
CREATE TRIGGER IF NOT EXISTS filesystem_path_ai
AFTER INSERT ON filesystem
BEGIN
    INSERT INTO filesystem_path_fts(rowid, path) VALUES (new.id, new.path);
END;

-- Trigger: After filesystem delete, delete from path FTS
CREATE TRIGGER IF NOT EXISTS filesystem_path_ad
AFTER DELETE ON filesystem
BEGIN
    DELETE FROM filesystem_path_fts WHERE rowid = old.id;
END;

-- Trigger: After filesystem update, update path FTS
CREATE TRIGGER IF NOT EXISTS filesystem_path_au
AFTER UPDATE ON filesystem
BEGIN
    UPDATE filesystem_path_fts
    SET path = new.path
    WHERE rowid = new.id;
END;

-- Virtual table: Filesystem word FTS
CREATE VIRTUAL TABLE IF NOT EXISTS filesystem_word_fts USING fts5(
    content,
    path,
    description,
    tokenize = "unicode61"
);

-- Insert: Existing filesystem records into word FTS with normalized path
INSERT INTO filesystem_word_fts(rowid, content, path, description)
SELECT 
    id, 
    content, 
    REPLACE(REPLACE(REPLACE(path, '/', ' '), '-', ' '), '_', ' ') AS path, 
    description 
FROM filesystem
WHERE (content IS NOT NULL OR path IS NOT NULL OR description IS NOT NULL)
AND NOT EXISTS (SELECT 1 FROM filesystem_word_fts WHERE rowid = filesystem.id);

-- Trigger: After filesystem insert, insert into word FTS with normalized path
CREATE TRIGGER IF NOT EXISTS filesystem_word_ai
AFTER INSERT ON filesystem
WHEN new.content IS NOT NULL OR new.path IS NOT NULL OR new.description IS NOT NULL
BEGIN
    INSERT INTO filesystem_word_fts(rowid, content, path, description)
    VALUES (
        new.id, 
        new.content, 
        REPLACE(REPLACE(REPLACE(new.path, '/', ' '), '-', ' '), '_', ' '), 
        new.description
    );
END;

-- Trigger: After filesystem delete, delete from word FTS
CREATE TRIGGER IF NOT EXISTS filesystem_word_ad
AFTER DELETE ON filesystem
BEGIN
    DELETE FROM filesystem_word_fts WHERE rowid = old.id;
END;

-- Trigger: After filesystem update, update word FTS with normalized path
CREATE TRIGGER IF NOT EXISTS filesystem_word_au
AFTER UPDATE ON filesystem
WHEN new.content IS NOT NULL OR new.path IS NOT NULL OR new.description IS NOT NULL
BEGIN
    UPDATE filesystem_word_fts
    SET 
        content = new.content, 
        path = REPLACE(REPLACE(REPLACE(new.path, '/', ' '), '-', ' '), '_', ' '), 
        description = new.description
    WHERE rowid = new.id;
END;

-- Virtual table: Filesystem reverse path FTS
CREATE VIRTUAL TABLE IF NOT EXISTS filesystem_rev_path_fts USING fts5(
    reversed_path,
    tokenize = "unicode61 tokenchars '/.'"
);

-- Insert: Existing filesystem records into reverse path FTS
INSERT INTO filesystem_rev_path_fts(rowid, reversed_path)
SELECT id, (
    WITH RECURSIVE rev(s, r) AS (
        SELECT path, ''
        UNION ALL
        SELECT substr(s, 2), substr(s, 1, 1) || r FROM rev WHERE length(s) > 0
    ) 
    SELECT r FROM rev WHERE s = ''
) AS reversed_path
FROM filesystem
WHERE NOT EXISTS (SELECT 1 FROM filesystem_rev_path_fts WHERE rowid = filesystem.id);

-- Trigger: After filesystem insert, insert into reverse path FTS
CREATE TRIGGER IF NOT EXISTS filesystem_rev_path_ai
AFTER INSERT ON filesystem
BEGIN
    INSERT INTO filesystem_rev_path_fts(rowid, reversed_path) 
    VALUES (new.id, (
        WITH RECURSIVE rev(s, r) AS (
            SELECT new.path, ''
            UNION ALL
            SELECT substr(s, 2), substr(s, 1, 1) || r FROM rev WHERE length(s) > 0
        ) 
        SELECT r FROM rev WHERE s = ''
    ));
END;

-- Trigger: After filesystem delete, delete from reverse path FTS
CREATE TRIGGER IF NOT EXISTS filesystem_rev_path_ad
AFTER DELETE ON filesystem
BEGIN
    DELETE FROM filesystem_rev_path_fts WHERE rowid = old.id;
END;

-- Trigger: After filesystem update, update reverse path FTS
CREATE TRIGGER IF NOT EXISTS filesystem_rev_path_au
AFTER UPDATE ON filesystem
BEGIN
    UPDATE filesystem_rev_path_fts
    SET reversed_path = (
        WITH RECURSIVE rev(s, r) AS (
            SELECT new.path, ''
            UNION ALL
            SELECT substr(s, 2), substr(s, 1, 1) || r FROM rev WHERE length(s) > 0
        ) 
        SELECT r FROM rev WHERE s = ''
    )
    WHERE rowid = new.id;
END;
