CREATE INDEX IF NOT EXISTS idx_namespace_blobs_blob_key ON namespace_blobs(blob_key);
CREATE INDEX IF NOT EXISTS idx_blob_objects_retention ON blob_objects(created_at, blob_key);
CREATE INDEX IF NOT EXISTS idx_action_results_retention ON action_results(created_at);
CREATE INDEX IF NOT EXISTS idx_action_manifests_retention ON action_manifests(updated_at);
