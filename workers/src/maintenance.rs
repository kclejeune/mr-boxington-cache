//! Bounded retention and orphan cleanup. R2 deletion follows metadata removal.
use crate::{
    auth,
    error::{Error, Result},
};
use wasm_bindgen::JsValue;
use worker::{D1Database, Env};

pub async fn sweep(env: &Env) -> Result<()> {
    if !auth::setting(env, "MBX_CACHE_CLEANUP_ENABLED", "false")
        .parse::<bool>()
        .map_err(Error::internal)?
    {
        return Ok(());
    }
    let db = env.d1("MBX_DB")?;
    let days: u32 = auth::setting(env, "MBX_CACHE_RETENTION_DAYS", "0")
        .parse()
        .map_err(Error::internal)?;
    if days > 0 {
        let cutoff = (js_sys::Date::now() / 1000.0) as i64 - i64::from(days) * 86400;
        let bind = [JsValue::from_f64(cutoff as f64)];
        db.batch(vec![
            db.prepare("DELETE FROM namespace_blobs WHERE blob_key IN (SELECT blob_key FROM blob_objects WHERE created_at<?1 ORDER BY blob_key LIMIT 200)").bind(&bind)?,
            db.prepare("DELETE FROM blob_objects WHERE blob_key IN (SELECT blob_key FROM blob_objects WHERE created_at<?1 ORDER BY blob_key LIMIT 200)").bind(&bind)?,
            db.prepare("DELETE FROM action_results WHERE rowid IN (SELECT rowid FROM action_results WHERE created_at<?1 LIMIT 200)").bind(&bind)?,
            db.prepare("DELETE FROM action_manifests WHERE rowid IN (SELECT rowid FROM action_manifests WHERE updated_at<?1 LIMIT 200)").bind(&bind)?,
        ]).await?;
    }
    sweep_orphans(env, &db).await
}
async fn sweep_orphans(env: &Env, db: &D1Database) -> Result<()> {
    let bucket = env.bucket("MBX_BLOBS")?;
    let cursor: Option<String> = db
        .prepare("SELECT cursor FROM maintenance WHERE name='worker-orphans-v1'")
        .first(Some("cursor"))
        .await?;
    let prefix = format!("{}/", auth::object_prefix(env)?);
    let mut list = bucket.list().prefix(&prefix).limit(100);
    if let Some(cursor) = cursor {
        list = list.cursor(cursor);
    }
    let objects = list.execute().await?;
    let cutoff = js_sys::Date::now() - 86400.0 * 1000.0;
    for object in objects.objects() {
        if object.uploaded().as_millis() as f64 >= cutoff {
            continue;
        }
        let key = object.key();
        let found: Option<u8> = db.prepare("SELECT 1 AS present FROM blob_objects WHERE object_key=?1 UNION ALL SELECT 1 FROM action_manifests WHERE object_key=?1 LIMIT 1")
            .bind(&[JsValue::from_str(&key)])?.first(Some("present")).await?;
        if found.is_none() {
            bucket.delete(key).await?;
        }
    }
    let cursor = objects.cursor().filter(|_| objects.truncated());
    db.prepare("INSERT INTO maintenance(name,cursor) VALUES ('worker-orphans-v1',?1) ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor")
        .bind(&[cursor.map(JsValue::from).unwrap_or(JsValue::NULL)])?.run().await?;
    Ok(())
}
