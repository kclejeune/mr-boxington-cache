-- Bodies remain in R2. Only verified uploads can acquire a namespace membership.
CREATE TABLE blob_objects (
    blob_key TEXT PRIMARY KEY,
    object_key TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE namespace_blobs (
    namespace TEXT NOT NULL,
    blob_key TEXT NOT NULL REFERENCES blob_objects(blob_key),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (namespace, blob_key)
);
CREATE TABLE action_results (
    namespace TEXT NOT NULL,
    action_key TEXT NOT NULL,
    result TEXT NOT NULL CHECK(json_valid(result)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (namespace, action_key)
);
CREATE TABLE action_manifests (
    namespace TEXT NOT NULL,
    action_key TEXT NOT NULL,
    etag TEXT NOT NULL,
    object_key TEXT NOT NULL UNIQUE,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (namespace, action_key)
);
CREATE TABLE maintenance (
    name TEXT PRIMARY KEY,
    cursor TEXT
);
