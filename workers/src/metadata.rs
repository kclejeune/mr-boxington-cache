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
    pub bucket: Bucket,
    pub max_blob_bytes: u64,
    pub object_prefix: String,
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
        // Bound JSON size and result materialization independently of protocol batch size.
        for chunk in digests.chunks(1000) {
            let keys = serde_json::to_string(&chunk.iter().map(Digest::key).collect::<Vec<_>>())?;
            let rows = self.statement(
                "SELECT requested.value AS blob_key FROM json_each(?2) AS requested \
                 JOIN namespace_blobs AS blobs ON blobs.namespace=?1 AND blobs.blob_key=requested.value",
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
        use futures_util::{StreamExt, stream};
        #[derive(Deserialize)]
        struct ObjectRow {
            blob_key: String,
            object_key: String,
        }
        let keys = serde_json::to_string(&digests.iter().map(Digest::key).collect::<Vec<_>>())?;
        let rows=self.statement("SELECT o.blob_key,o.object_key FROM json_each(?2) r JOIN namespace_blobs b ON b.namespace=?1 AND b.blob_key=r.value JOIN blob_objects o ON o.blob_key=b.blob_key",&[namespace,&keys])?.all().await?.results::<ObjectRow>()?;
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

    pub async fn register(
        &self,
        namespace: &str,
        digest: &Digest,
        object_key: &str,
    ) -> Result<bool> {
        if let Some(previous) = self.object_key(digest).await?
            && self.bucket.head(&previous).await?.is_none()
        {
            let key = digest.key();
            let results=self.db.batch(vec![
                self.statement("UPDATE blob_objects SET object_key=?2,created_at=unixepoch() WHERE blob_key=?1 AND object_key=?3",&[&key,object_key,&previous])?,
                self.statement("INSERT INTO namespace_blobs(namespace,blob_key) VALUES (?1,?2) ON CONFLICT DO NOTHING",&[namespace,&key])?,
            ]).await?;
            return Ok(results[0].meta()?.is_some_and(|m| m.changes == Some(1)));
        }
        let key = digest.key();
        let results = self.db.batch(vec![
            self.statement("INSERT INTO blob_objects(blob_key,object_key) VALUES (?1,?2) ON CONFLICT DO NOTHING", &[&key,object_key])?,
            self.statement("INSERT INTO namespace_blobs(namespace,blob_key) VALUES (?1,?2) ON CONFLICT DO NOTHING", &[namespace,&key])?,
        ]).await?;
        Ok(results[0]
            .meta()?
            .is_some_and(|meta| meta.changes == Some(1)))
    }
    pub async fn get_results(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> Result<Vec<ActionResult>> {
        let mut results = Vec::new();
        for chunk in digests.chunks(1000) {
            let keys = serde_json::to_string(&chunk.iter().map(Digest::key).collect::<Vec<_>>())?;
            let rows = self.statement(
                "SELECT results.result FROM json_each(?2) AS requested JOIN action_results AS results \
                 ON results.namespace=?1 AND results.action_key=requested.value", &[namespace,&keys])?
                .all().await?.results::<ResultRow>()?;
            for row in rows {
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
        let rows = self.statement("INSERT INTO action_results(namespace,action_key,result) VALUES (?1,?2,?3) ON CONFLICT DO NOTHING", &[namespace,&digest.key(),&json])?.run().await?;
        if rows.meta()?.is_some_and(|m| m.changes == Some(1)) {
            return Ok(201);
        }
        let existing = self
            .get_results(namespace, std::slice::from_ref(digest))
            .await?;
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
    fn read(
        &self,
        digest: &Digest,
    ) -> impl Future<Output = std::result::Result<Option<Vec<u8>>, ValidationError>> + Send {
        SendFuture::new(async move {
            self.charge_validation(1)?;
            let result: Result<Option<Vec<u8>>> = async {
                if digest.size > 16 * 1024 * 1024 {
                    return Err(Error::new(422, "protocol object is too large"));
                }
                let Some(key) = self.object_key(digest).await? else {
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
