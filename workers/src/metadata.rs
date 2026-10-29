use crate::{
    error::{Error, Result},
    model::{ActionResult, Digest},
    validation::{ValidationError, ValidationStore},
};
use serde::Deserialize;
use std::collections::HashSet;
use wasm_bindgen::JsValue;
use worker::{Bucket, D1DatabaseSession, D1PreparedStatement, send::SendFuture};

pub(crate) struct Store {
    pub db: D1DatabaseSession,
    pub primary: worker::D1Database,
    pub trusted_presence: bool,
    pub bucket: Bucket,
    pub max_blob_bytes: u64,
    pub object_prefix: String,
    pub validation_bytes: std::sync::atomic::AtomicU64,
    pub validation_queries: std::sync::atomic::AtomicUsize,
}
#[derive(Deserialize)]
struct KeyRow {
    blob_key: String,
}
#[derive(Deserialize)]
struct ResultRow {
    result: String,
}
#[derive(Deserialize)]
pub struct ManifestRow {
    pub etag: String,
    pub object_key: String,
}

impl Store {
    fn charge_validation(&self, queries: usize) -> std::result::Result<(), ValidationError> {
        use std::sync::atomic::Ordering;
        if self
            .validation_queries
            .fetch_add(queries, Ordering::Relaxed)
            + queries
            > 500
        {
            return Err(ValidationError::unprocessable(
                "action exceeds the Worker validation query budget",
            ));
        }
        Ok(())
    }

    pub fn statement(&self, sql: &str, args: &[&str]) -> Result<D1PreparedStatement> {
        Ok(self.db.prepare(sql).bind(
            &args
                .iter()
                .map(|s| JsValue::from_str(s))
                .collect::<Vec<_>>(),
        )?)
    }
    pub async fn visible_blobs(&self, namespace: &str, digests: &[Digest]) -> Result<Vec<Digest>> {
        let mut visible = HashSet::new();
        // CROSS JOIN keeps the bounded request list outermost, forcing full-key lookups.
        // Bound JSON size and result materialization independently of protocol batch size.
        for chunk in digests.chunks(1000) {
            let keys = serde_json::to_string(&chunk.iter().map(Digest::key).collect::<Vec<_>>())?;
            let rows = self.statement(
                "SELECT requested.value AS blob_key FROM json_each(?2) AS requested \
                 CROSS JOIN namespace_blobs AS blobs ON blobs.namespace=?1 AND blobs.blob_key=requested.value",
                &[namespace, &keys])?.all().await?.results::<KeyRow>()?;
            visible.extend(rows.into_iter().map(|row| row.blob_key));
        }
        Ok(digests
            .iter()
            .filter(|d| visible.contains(&d.key()))
            .cloned()
            .collect())
    }
    pub async fn visible_object(&self, namespace: &str, digest: &Digest) -> Result<Option<String>> {
        Ok(self.statement("SELECT o.object_key FROM namespace_blobs b JOIN blob_objects o ON o.blob_key=b.blob_key WHERE b.namespace=?1 AND b.blob_key=?2",&[namespace,&digest.key()])?.first(Some("object_key")).await?)
    }
    pub async fn visible_objects(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> Result<std::collections::HashMap<String, String>> {
        #[derive(Deserialize)]
        struct Object {
            blob_key: String,
            object_key: String,
        }
        let keys = serde_json::to_string(&digests.iter().map(Digest::key).collect::<Vec<_>>())?;
        let result = self.statement("SELECT o.blob_key,o.object_key FROM json_each(?2) r CROSS JOIN namespace_blobs b ON b.namespace=?1 AND b.blob_key=r.value CROSS JOIN blob_objects o ON o.blob_key=b.blob_key", &[namespace,&keys])?.all().await?;
        log_meta(&result)?;
        Ok(result
            .results::<Object>()?
            .into_iter()
            .map(|row| (row.blob_key, row.object_key))
            .collect())
    }
    pub async fn object_key(&self, digest: &Digest) -> Result<Option<String>> {
        Ok(self
            .statement(
                "SELECT object_key FROM blob_objects WHERE blob_key=?1",
                &[&digest.key()],
            )?
            .first(Some("object_key"))
            .await?)
    }
    /// Consult storage as well as membership, so lifecycle-expired imports can be uploaded again.
    pub async fn present_blobs(&self, namespace: &str, digests: &[Digest]) -> Result<Vec<Digest>> {
        if self.trusted_presence {
            let pointers = self.visible_objects(namespace, digests).await?;
            return Ok(digests
                .iter()
                .filter(|d| pointers.contains_key(&d.key()))
                .cloned()
                .collect());
        }
        use futures_util::{StreamExt, stream};
        #[derive(Deserialize)]
        struct ObjectRow {
            blob_key: String,
            object_key: String,
        }
        let keys = serde_json::to_string(&digests.iter().map(Digest::key).collect::<Vec<_>>())?;
        let rows=self.statement("SELECT o.blob_key,o.object_key FROM json_each(?2) r CROSS JOIN namespace_blobs b ON b.namespace=?1 AND b.blob_key=r.value CROSS JOIN blob_objects o ON o.blob_key=b.blob_key",&[namespace,&keys])?.all().await?.results::<ObjectRow>()?;
        let found = stream::iter(rows)
            .map(|row| async move {
                let object = self.bucket.head(&row.object_key).await?;
                Ok::<_, Error>(object.map(|object| (row.blob_key, object.size())))
            })
            .buffer_unordered(6)
            .collect::<Vec<_>>()
            .await;
        let mut present = std::collections::HashMap::new();
        for row in found {
            if let Some((key, size)) = row? {
                present.insert(key, size);
            }
        }
        Ok(digests
            .iter()
            .filter(|d| present.get(&d.key()) == Some(&d.size))
            .cloned()
            .collect())
    }

    /// Publish only fully verified objects, globally first and memberships second.
    pub async fn register_many(
        &self,
        namespace: &str,
        staged: &[(Digest, String, bool)],
    ) -> Result<()> {
        if staged.is_empty() {
            return Ok(());
        }
        let rows: Vec<_> = staged
            .iter()
            .map(|(digest, key, fresh)| serde_json::json!({"blob":digest.key(),"object":key,"fresh":fresh}))
            .collect();
        let json = serde_json::to_string(&rows)?;
        // Only repair an exact pointer confirmed absent/wrong-sized on this primary session.
        let mut repairs = Vec::new();
        #[derive(Deserialize)]
        struct Pointer {
            blob_key: String,
            object_key: String,
        }
        let pointers = self.statement("SELECT b.blob_key,b.object_key FROM json_each(?1) r CROSS JOIN blob_objects b ON b.blob_key=json_extract(r.value,'$.blob')", &[&json])?.all().await?.results::<Pointer>()?;
        for pointer in pointers {
            if let Some((digest, key, fresh)) =
                staged.iter().find(|(d, _, _)| d.key() == pointer.blob_key)
                && *fresh
                && pointer.object_key != *key
                && !self
                    .bucket
                    .head(&pointer.object_key)
                    .await?
                    .is_some_and(|o| o.size() == digest.size)
            {
                repairs.push(serde_json::json!({"blob":digest.key(),"object":key,"previous":pointer.object_key}));
            }
        }
        let repairs = serde_json::to_string(&repairs)?;
        let results = self.db.batch(vec![
            self.statement("INSERT INTO blob_objects(blob_key,object_key) SELECT json_extract(value,'$.blob'),json_extract(value,'$.object') FROM json_each(?1) WHERE json_extract(value,'$.fresh')=1 ON CONFLICT DO NOTHING", &[&json])?,
            self.statement("UPDATE blob_objects SET object_key=json_extract(r.value,'$.object'),created_at=unixepoch() FROM json_each(?1) r WHERE blob_key=json_extract(r.value,'$.blob') AND object_key=json_extract(r.value,'$.previous')", &[&repairs])?,
            self.statement("INSERT INTO namespace_blobs(namespace,blob_key) SELECT ?1,b.blob_key FROM json_each(?2) r CROSS JOIN blob_objects b ON b.blob_key=json_extract(r.value,'$.blob') WHERE true ON CONFLICT DO NOTHING", &[namespace,&json])?,
            self.statement("SELECT b.blob_key,b.object_key FROM json_each(?1) r CROSS JOIN blob_objects b ON b.blob_key=json_extract(r.value,'$.blob')", &[&json])?,
        ]).await?;
        #[derive(Deserialize)]
        struct Winner {
            blob_key: String,
            object_key: String,
        }
        let winners = results[3].results::<Winner>()?;
        for (digest, key, fresh) in staged {
            let winner = winners.iter().find(|row| row.blob_key == digest.key());
            if *fresh && winner.is_some_and(|row| row.object_key != *key) {
                self.bucket.delete(key).await?;
            }
            if winner.is_none() {
                return Err(Error::new(409, "blob changed during upload; retry"));
            }
        }
        for result in &results {
            log_meta(result)?;
        }
        Ok(())
    }
    pub async fn repair_blob(&self, digest: &Digest, pointer: &str) -> Result<()> {
        // Fresh primary-anchored session: never make a destructive decision from a stale replica.
        let db = self.primary.with_session(Some("first-primary"))?;
        db.batch(vec![
            db.prepare("DELETE FROM namespace_blobs WHERE blob_key=?1 AND EXISTS (SELECT 1 FROM blob_objects WHERE blob_key=?1 AND object_key=?2)").bind(&[JsValue::from_str(&digest.key()), JsValue::from_str(pointer)])?,
            db.prepare("DELETE FROM blob_objects WHERE blob_key=?1 AND object_key=?2").bind(&[JsValue::from_str(&digest.key()), JsValue::from_str(pointer)])?,
        ]).await?;
        Ok(())
    }
    pub async fn get_results(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> Result<Vec<ActionResult>> {
        let mut results = Vec::new();
        let mut total = 0usize;
        for chunk in digests.chunks(16) {
            let keys = serde_json::to_string(&chunk.iter().map(Digest::key).collect::<Vec<_>>())?;
            let response = self.statement(
                "SELECT results.result FROM json_each(?2) AS requested CROSS JOIN action_results AS results \
                 ON results.namespace=?1 AND results.action_key=requested.value", &[namespace,&keys])?
                .all().await?;
            log_meta(&response)?;
            let rows = response.results::<ResultRow>()?;
            for row in rows {
                total = total.saturating_add(row.result.len());
                if row.result.len() > crate::JSON_LIMIT || total > crate::ACTION_BATCH_BYTES {
                    return Err(Error::new(413, "action batch response is too large"));
                }
                results.push(serde_json::from_str(&row.result).map_err(Error::internal)?);
            }
        }
        Ok(results)
    }
    pub async fn commit(
        &self,
        namespace: &str,
        digest: &Digest,
        result: &ActionResult,
    ) -> Result<u16> {
        let json = serde_json::to_string(result)?;
        let results = self.db.batch(vec![
            self.statement("INSERT INTO action_results(namespace,action_key,result) VALUES (?1,?2,?3) ON CONFLICT DO NOTHING", &[namespace,&digest.key(),&json])?,
            self.statement("SELECT result FROM action_results WHERE namespace=?1 AND action_key=?2", &[namespace,&digest.key()])?,
        ]).await?;
        if results[0].meta()?.is_some_and(|m| m.changes == Some(1)) {
            return Ok(201);
        }
        let existing = results[1]
            .results::<ResultRow>()?
            .into_iter()
            .map(|row| serde_json::from_str::<ActionResult>(&row.result))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if existing.first() == Some(result) {
            Ok(204)
        } else {
            Err(Error::new(409, "an immutable action result already exists"))
        }
    }
    pub async fn manifest(&self, namespace: &str, key: &Digest) -> Result<Option<ManifestRow>> {
        Ok(self
            .statement(
                "SELECT etag,object_key FROM action_manifests WHERE namespace=?1 AND action_key=?2",
                &[namespace, &key.key()],
            )?
            .first(None)
            .await?)
    }
    pub async fn commit_manifest(
        &self,
        namespace: &str,
        key: &Digest,
        expected: Option<&str>,
        etag: &str,
        object_key: &str,
    ) -> Result<bool> {
        let result = if let Some(expected) = expected {
            self.statement("UPDATE action_manifests SET etag=?3,object_key=?4,updated_at=unixepoch() WHERE namespace=?1 AND action_key=?2 AND etag=?5", &[namespace,&key.key(),etag,object_key,expected])?.run().await?
        } else {
            self.statement("INSERT INTO action_manifests(namespace,action_key,etag,object_key) VALUES (?1,?2,?3,?4) ON CONFLICT DO NOTHING", &[namespace,&key.key(),etag,object_key])?.run().await?
        };
        Ok(result.meta()?.is_some_and(|m| m.changes == Some(1)))
    }
}
impl ValidationStore for Store {
    fn visible(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> impl Future<Output = std::result::Result<Vec<Digest>, ValidationError>> + Send {
        SendFuture::new(async move {
            self.charge_validation(digests.len().div_ceil(1000))?;
            self.visible_blobs(namespace, digests)
                .await
                .map_err(|e| ValidationError {
                    status: e.status,
                    message: e.message,
                })
        })
    }
    fn read_visible_many(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> impl Future<Output = std::result::Result<Vec<Option<Vec<u8>>>, ValidationError>> + Send
    {
        SendFuture::new(async move {
            self.charge_validation(1)?;
            let bytes = digests
                .iter()
                .try_fold(0u64, |n, d| n.checked_add(d.size))
                .ok_or_else(|| ValidationError::unprocessable("protocol byte budget exceeded"))?;
            if bytes > 16 * 1024 * 1024
                || self
                    .validation_bytes
                    .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(bytes)
                    > 64 * 1024 * 1024
            {
                return Err(ValidationError::unprocessable(
                    "action exceeds protocol byte budget",
                ));
            }
            let result: Result<Vec<Option<Vec<u8>>>> = async {
                use futures_util::StreamExt;
                let pointers = self.visible_objects(namespace, digests).await?;
                let objects = futures_util::stream::iter(digests)
                    .map(|digest| {
                        let key = pointers.get(&digest.key()).cloned();
                        async move {
                            let Some(key) = key else {
                                return Ok(None);
                            };
                            let Some(object) = self.bucket.get(key).execute().await? else {
                                return Ok(None);
                            };
                            if object.size() != digest.size {
                                return Err(Error::new(422, "stored object length mismatch"));
                            }
                            Ok(Some(
                                object
                                    .body()
                                    .ok_or_else(|| Error::new(500, "missing object body"))?
                                    .bytes()
                                    .await?,
                            ))
                        }
                    })
                    .buffered(6)
                    .collect::<Vec<Result<_>>>()
                    .await;
                objects.into_iter().collect()
            }
            .await;
            result.map_err(|e| ValidationError {
                status: e.status,
                message: e.message,
            })
        })
    }
    fn read_visible(
        &self,
        namespace: &str,
        digest: &Digest,
    ) -> impl Future<Output = std::result::Result<Option<Vec<u8>>, ValidationError>> + Send {
        SendFuture::new(async move {
            self.charge_validation(1)?;
            if self
                .validation_bytes
                .fetch_add(digest.size, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(digest.size)
                > 64 * 1024 * 1024
            {
                return Err(ValidationError::unprocessable(
                    "action exceeds protocol byte budget",
                ));
            }
            let result: Result<Option<Vec<u8>>> = async {
                if digest.size > 16 * 1024 * 1024 {
                    return Err(Error::new(422, "protocol object is too large"));
                }
                let Some(key) = self.visible_object(namespace, digest).await? else {
                    return Ok(None);
                };
                let Some(object) = self.bucket.get(key).execute().await? else {
                    return Ok(None);
                };
                if object.size() != digest.size {
                    return Err(Error::new(500, "stored object length mismatch"));
                }
                let body = object
                    .body()
                    .ok_or_else(|| Error::new(500, "missing object body"))?;
                Ok(Some(body.bytes().await?))
            }
            .await;
            result.map_err(|e| ValidationError {
                status: e.status,
                message: e.message,
            })
        })
    }
}

fn log_meta(result: &worker::D1Result) -> Result<()> {
    if let Some(meta) = result.meta()? {
        worker::console_log!("mbx.d1 {:?}", meta);
    }
    Ok(())
}
