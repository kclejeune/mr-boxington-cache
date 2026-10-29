//! Bounded retention and orphan cleanup. R2 deletion follows metadata removal.
use crate::{
    auth,
    error::{Error, Result},
};
use wasm_bindgen::JsValue;
use worker::{D1DatabaseSession, Env};

pub async fn sweep(env: &Env) -> Result<()> {
    if !auth::setting(env, "MBX_CACHE_CLEANUP_ENABLED", "false")
        .parse::<bool>()
        .map_err(Error::internal)?
    {
        return Ok(());
    }
    let db = env.d1("MBX_DB")?.with_session(Some("first-primary"))?;
    let days: u32 = auth::setting(env, "MBX_CACHE_RETENTION_DAYS", "0")
        .parse()
        .map_err(Error::internal)?;
    if days > 0 {
        let cutoff = (js_sys::Date::now() / 1000.0) as i64 - i64::from(days) * 86400;
        let bind = [JsValue::from_f64(cutoff as f64)];
        db.batch(vec![
            db.prepare("DELETE FROM namespace_blobs WHERE blob_key IN (SELECT blob_key FROM blob_objects WHERE created_at<?1 ORDER BY created_at,blob_key LIMIT 200)").bind(&bind)?,
            db.prepare("DELETE FROM blob_objects WHERE blob_key IN (SELECT blob_key FROM blob_objects WHERE created_at<?1 ORDER BY created_at,blob_key LIMIT 200)").bind(&bind)?,
            db.prepare("DELETE FROM action_results WHERE rowid IN (SELECT rowid FROM action_results WHERE created_at<?1 ORDER BY created_at,rowid LIMIT 200)").bind(&bind)?,
            db.prepare("DELETE FROM action_manifests WHERE rowid IN (SELECT rowid FROM action_manifests WHERE updated_at<?1 ORDER BY updated_at,rowid LIMIT 200)").bind(&bind)?,
        ]).await?;
    }
    sweep_orphans(env, &db).await
}
async fn sweep_orphans(env: &Env, db: &D1DatabaseSession) -> Result<()> {
    let bucket = env.bucket("MBX_BLOBS")?;
    let mut cursor: Option<String> = db
        .prepare("SELECT cursor FROM maintenance WHERE name='worker-orphans-v1'")
        .first(Some("cursor"))
        .await?;
    let prefix = format!("{}/", auth::object_prefix(env)?);
    let cutoff = js_sys::Date::now() - 86400.0 * 1000.0;
    let mut inspected = 0;
    let mut deleted = 0;
    let mut oldest_ms = 0f64;
    // At most 1,000 inspected and 200 deleted objects per invocation.
    for _ in 0..10 {
        let mut list = bucket.list().prefix(&prefix).limit(100);
        if let Some(value) = &cursor {
            list = list.cursor(value.clone());
        }
        let objects = list.execute().await?;
        inspected += objects.objects().len();
        let keys: Vec<_> = objects.objects().iter().map(|o| o.key()).collect();
        let json = serde_json::to_string(&keys)?;
        #[derive(serde::Deserialize)]
        struct Referenced {
            object_key: String,
        }
        let rows = db.prepare("SELECT r.value AS object_key FROM json_each(?1) r LEFT JOIN blob_objects b ON b.object_key=r.value LEFT JOIN action_manifests m ON m.object_key=r.value WHERE b.object_key IS NOT NULL OR m.object_key IS NOT NULL")
            .bind(&[JsValue::from_str(&json)])?.all().await?.results::<Referenced>()?;
        let referenced: std::collections::HashSet<_> =
            rows.into_iter().map(|r| r.object_key).collect();
        for object in objects.objects() {
            let age = js_sys::Date::now() - object.uploaded().as_millis() as f64;
            if (object.uploaded().as_millis() as f64) < cutoff
                && !referenced.contains(&object.key())
                && deleted < 200
            {
                oldest_ms = oldest_ms.max(age);
                bucket.delete(object.key()).await?;
                deleted += 1;
            }
        }
        cursor = objects.cursor().filter(|_| objects.truncated());
        if cursor.is_none() || deleted >= 200 {
            break;
        }
    }
    db.prepare("INSERT INTO maintenance(name,cursor) VALUES ('worker-orphans-v1',?1) ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor")
        .bind(&[cursor.as_ref().map(JsValue::from).unwrap_or(JsValue::NULL)])?.run().await?;
    worker::console_log!(
        "mbx.cleanup inspected={} deleted={} oldest_orphan_ms={} continuing={}",
        inspected,
        deleted,
        oldest_ms,
        cursor.is_some()
    );
    Ok(())
}
