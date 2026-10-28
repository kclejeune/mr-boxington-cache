-- A source manifest may advance only while D1 still holds its last imported ETag.
CREATE TABLE postgres_manifest_imports (
    source TEXT NOT NULL,
    namespace TEXT NOT NULL,
    action_key TEXT NOT NULL,
    source_updated_at INTEGER NOT NULL,
    imported_etag TEXT NOT NULL,
    PRIMARY KEY (source, namespace, action_key)
);
CREATE TABLE postgres_import_conflicts (
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    namespace TEXT NOT NULL,
    action_key TEXT NOT NULL,
    source_value TEXT NOT NULL,
    target_value TEXT NOT NULL,
    PRIMARY KEY (source, kind, namespace, action_key)
);
