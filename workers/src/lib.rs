mod auth;
#[path = "../../src/auth_policy.rs"]
mod auth_policy;
mod compression;
mod edge;
mod error;
mod limits;
mod maintenance;
mod metadata;
#[path = "../../src/model.rs"]
mod model;
mod oidc;
mod routes;
mod upload;
#[path = "../../src/validation.rs"]
mod validation;

use error::{Error, Result};
use futures_util::StreamExt;
use mbx_cache_protocol::{
    ACTION_RESULT_BATCH_MEDIA_TYPE, ActionKindCapability, BLOB_PACK_MAGIC, BLOB_PACK_MEDIA_TYPE,
    BLOB_PACK_RECEIPT_MEDIA_TYPE, Capabilities, CapabilityFeatures, CapabilityLimits,
    CapabilityProtocol, PROTOCOL_VERSION, TASK_ACTION_MANIFEST_MEDIA_TYPE, canonical_json,
};
use metadata::Store;
use model::{ActionResult, BUILD_SCRIPT_ACTION_SCHEMAS, Digest, TaskActionManifest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use worker::{Context, Env, Method, Request, Response, event};

const WORKER_BATCH_LIMIT: usize = 16;
const JSON_LIMIT: usize = 1024 * 1024;
const ACTION_BATCH_BYTES: usize = 16 * 1024 * 1024;
const MANIFEST_LIMIT: usize = 16 * 1024 * 1024;
const DEFAULT_BLOB_LIMIT: u64 = 64 * 1024 * 1024;

#[event(fetch)]
async fn fetch(mut request: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let mut response = match handle(&mut request, &env, &ctx).await {
        Ok(response) => response,
        Err(error) => error_response(error)?,
    };
    // Every external response varies with authorization and/or namespace. Only
    // the internal immutable entrypoint may opt into shared caching.
    response
        .headers_mut()
        .set("cache-control", "private, no-store")?;
    Ok(response)
}

async fn handle(request: &mut Request, env: &Env, ctx: &Context) -> Result<Response> {
    let path = request.path();
    let method = request.method();
    let route = routes::classify(&method, &path)?;
    let max_blob_bytes: u64 = auth::setting(
        env,
        "MBX_CACHE_MAX_BLOB_BYTES",
        &DEFAULT_BLOB_LIMIT.to_string(),
    )
    .parse()
    .map_err(Error::internal)?;
    if max_blob_bytes == 0 || max_blob_bytes > u32::MAX as u64 {
        return Err(Error::internal(
            "MBX_CACHE_MAX_BLOB_BYTES must be between 1 and 4294967295",
        ));
    }
    let ingress_limit: u64 =
        auth::setting(env, "MBX_CACHE_WORKERS_REQUEST_LIMIT_BYTES", "100000000")
            .parse()
            .map_err(Error::internal)?;
    validate_ingress(max_blob_bytes, ingress_limit)?;
    if path == "/v1/status" && method == Method::Get {
        return json(&serde_json::json!({"status":"ok","protocol":PROTOCOL_VERSION}));
    }
    if path == "/v1/capabilities" && method == Method::Get {
        return capabilities(max_blob_bytes);
    }
    let write = route.access() == routes::Access::Write;
    let principal = auth::authorize(env, request.headers(), write).await?;
    let reserved_bytes = match route {
        // Pack reads charge their validated requested payload below, before D1/R2 work.
        routes::Route::PackRead => 0,
        routes::Route::PackWrite => max_blob_bytes + 8 + 41 * WORKER_BATCH_LIMIT as u64,
        routes::Route::BlobWrite => max_blob_bytes,
        routes::Route::ActionWrite => 64 * 1024 * 1024 + JSON_LIMIT as u64,
        routes::Route::ManifestWrite | routes::Route::ManifestRead => MANIFEST_LIMIT as u64,
        routes::Route::Batch => ACTION_BATCH_BYTES as u64,
        routes::Route::BlobRead => path
            .rsplit('/')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0),
        _ => JSON_LIMIT as u64,
    };
    limits::check(env, &principal, route.budget(&path), reserved_bytes).await?;
    routes::validate_body(request, route, max_blob_bytes)?;
    let namespace = principal.namespace.clone();
    let parts: Vec<_> = path.split('/').collect();
    if matches!(method, Method::Get | Method::Head)
        && parts.len() == 6
        && parts[1] == "v1"
        && matches!(parts[2], "blobs" | "action-results")
    {
        let digest = parse_digest(parts[3], parts[4], parts[5], parts[2] != "blobs")?;
        return edge::read(ctx, env, &namespace, parts[2], &digest, method).await;
    }
    if method == Method::Post && path == "/v1/action-results:batch" {
        let digests = digest_list(request, true).await?;
        // A bounded bulk query avoids one internal/D1 miss per cold member.
        let results = store(env, false)?.get_results(&namespace, &digests).await?;
        if serde_json::to_vec(&results)?.len() > ACTION_BATCH_BYTES {
            return Err(Error::new(413, "action batch response is too large"));
        }
        return media_json(
            &serde_json::json!({"results":results}),
            ACTION_RESULT_BATCH_MEDIA_TYPE,
        );
    }
    if method == Method::Post && path == "/v1/blobs:pack" {
        return download_pack(request, env, &principal, max_blob_bytes).await;
    }
    let store = store(env, write)?;
    match (method, path.as_str()) {
        (Method::Post, "/v1/blobs:missing") => {
            let digests = digest_list(request, false).await?;
            let visible: HashSet<_> = store
                .present_blobs(&namespace, &digests)
                .await?
                .into_iter()
                .collect();
            json(
                &serde_json::json!({"missing":digests.into_iter().filter(|d| !visible.contains(d)).collect::<Vec<_>>()}),
            )
        }
        (Method::Post, "/v1/blobs:pack-upload") => upload_pack(request, &store, &namespace).await,
        (method, _) => {
            let parts: Vec<_> = path.split('/').collect();
            if parts.len() != 6 || parts[1] != "v1" {
                return Err(Error::new(404, "not found"));
            }
            // /v1/{collection}/{algorithm}/{hash}/{size} has six slash-separated components.
            resource(request, &store, &namespace, method, &parts).await
        }
    }
}

async fn resource(
    request: &mut Request,
    store: &Store,
    namespace: &str,
    method: Method,
    parts: &[&str],
) -> Result<Response> {
    let action = parts[2] != "blobs";
    let digest = parse_digest(parts[3], parts[4], parts[5], action)?;
    match (method, parts[2]) {
        (Method::Head, "blobs") => {
            let key = store
                .visible_object(namespace, &digest)
                .await?
                .ok_or_else(|| Error::new(404, "blob not found"))?;
            let object = store.bucket.head(&key).await?;
            if !object.is_some_and(|o| o.size() == digest.size) {
                store.repair_blob(&digest, &key).await?;
                return Err(Error::new(404, "blob not found"));
            }
            let mut response = Response::empty()?;
            response
                .headers_mut()
                .set("content-type", "application/octet-stream")?;
            response
                .headers_mut()
                .set("content-length", &digest.size.to_string())?;
            response
                .headers_mut()
                .set("etag", &format!("\"{}\"", digest.hash))?;
            response
                .headers_mut()
                .set("digest", &format!("{}={}", digest.algorithm, digest.hash))?;
            Ok(response)
        }
        (Method::Get, "blobs") => {
            let key = store
                .visible_object(namespace, &digest)
                .await?
                .ok_or_else(|| Error::new(404, "blob not found"))?;
            let Some(object) = store.bucket.get(&key).execute().await? else {
                store.repair_blob(&digest, &key).await?;
                return Err(Error::new(404, "blob not found"));
            };
            if object.size() != digest.size {
                store.repair_blob(&digest, &key).await?;
                return Err(Error::new(404, "blob not found"));
            }
            let body = object
                .body()
                .ok_or_else(|| Error::new(500, "missing object body"))?
                .response_body()?;
            let mut response = Response::from_body(body)?;
            response
                .headers_mut()
                .set("content-type", "application/octet-stream")?;
            response
                .headers_mut()
                .set("content-length", &digest.size.to_string())?;
            response
                .headers_mut()
                .set("etag", &format!("\"{}\"", digest.hash))?;
            response
                .headers_mut()
                .set("digest", &format!("{}={}", digest.algorithm, digest.hash))?;
            Ok(response)
        }
        (Method::Put, "blobs") => {
            immutable(request)?;
            let stream = compression::body(
                request,
                store.max_blob_bytes,
                digest.size.min(store.max_blob_bytes),
            )?;
            upload::upload(store, namespace, &digest, stream).await?;
            empty(204)
        }
        (Method::Get | Method::Head, "action-results") => {
            let results = store.get_results(namespace, &[digest]).await?;
            let result = results
                .first()
                .ok_or_else(|| Error::new(404, "action result not found"))?;
            json(result)
        }
        (Method::Put, "action-results") => {
            immutable(request)?;
            let result: ActionResult =
                serde_json::from_slice(&read_body(request, JSON_LIMIT).await?)?;
            if result.version != 1 || result.action != digest {
                return Err(Error::new(400, "action result does not match request"));
            }
            if let Some(existing) = store
                .get_results(namespace, std::slice::from_ref(&digest))
                .await?
                .first()
            {
                return if existing == &result {
                    empty(204)
                } else {
                    Err(Error::new(409, "an immutable action result already exists"))
                };
            }
            let kind = validation::validate_action_descriptor(store, namespace, &digest).await?;
            validation::validate_action_result_shape(&result, kind)?;
            if let Some(metadata) = &result.metadata {
                validation::validate_client_metadata(store, namespace, metadata, kind).await?;
            }
            if let Some(root) = &result.output_root {
                validation::validate_tree(store, namespace, root).await?;
            }
            empty(store.commit(namespace, &digest, &result).await?)
        }
        (Method::Get, "action-manifests") => {
            let record = store
                .manifest(namespace, &digest)
                .await?
                .ok_or_else(|| Error::new(404, "action manifest not found"))?;
            let object = store
                .bucket
                .get(&record.object_key)
                .execute()
                .await?
                .ok_or_else(|| Error::new(404, "action manifest not found"))?;
            if object.size() > MANIFEST_LIMIT as u64 {
                return Err(Error::new(404, "action manifest not found"));
            }
            let bytes = object
                .body()
                .ok_or_else(|| Error::new(500, "missing manifest body"))?
                .bytes()
                .await?;
            if blake3::hash(&bytes).to_hex().as_str() != record.etag {
                return Err(Error::new(404, "action manifest not found"));
            }
            let mut response = Response::from_bytes(bytes)?;
            response
                .headers_mut()
                .set("content-type", TASK_ACTION_MANIFEST_MEDIA_TYPE)?;
            response
                .headers_mut()
                .set("etag", &format!("\"{}\"", record.etag))?;
            Ok(response)
        }
        (Method::Put, "action-manifests") => put_manifest(request, store, namespace, &digest).await,
        (_, "blobs" | "action-results" | "action-manifests") => {
            Err(Error::new(405, "method not allowed"))
        }
        _ => Err(Error::new(404, "not found")),
    }
}

fn validate_ingress(blob_limit: u64, ingress_limit: u64) -> Result<()> {
    let framed = blob_limit
        .checked_add(8 + 41 * WORKER_BATCH_LIMIT as u64 + 1024 * 1024)
        .ok_or_else(|| Error::internal("upload limits overflow"))?;
    if framed > ingress_limit {
        return Err(Error::internal(
            "blob/pack limits plus framing and 1 MiB safety margin exceed MBX_CACHE_WORKERS_REQUEST_LIMIT_BYTES",
        ));
    }
    Ok(())
}

fn capabilities(max_blob_bytes: u64) -> Result<Response> {
    let mut c = Capabilities::new(CapabilityProtocol::new(PROTOCOL_VERSION, 0));
    c.digest_algorithms = vec!["blake3".into(), "sha256".into()];
    c.compressors = vec!["identity".into(), "zstd".into()];
    c.action_kinds = BTreeMap::from([
        ("task".into(), ActionKindCapability::new(1, 1)),
        ("rustc".into(), ActionKindCapability::new(1, 1)),
        ("cc".into(), ActionKindCapability::new(1, 1)),
        (
            "build-script".into(),
            ActionKindCapability::new(*BUILD_SCRIPT_ACTION_SCHEMAS.end(), 1),
        ),
    ]);
    let mut f = CapabilityFeatures::default();
    f.batch = true;
    f.action_batch = true;
    f.action_manifests = true;
    f.blob_packs = true;
    f.blob_pack_uploads = true;
    c.features = f;
    let mut l = CapabilityLimits::default();
    l.max_batch_items = WORKER_BATCH_LIMIT as u64;
    l.max_blob_bytes = max_blob_bytes;
    l.max_pack_bytes = max_blob_bytes;
    l.max_inline_blob_bytes = 1_048_576;
    c.limits = l;
    json(&c)
}

fn parse_digest(algorithm: &str, hash: &str, size: &str, action: bool) -> Result<Digest> {
    let digest = Digest {
        algorithm: algorithm.into(),
        hash: hash.into(),
        size: size
            .parse()
            .map_err(|_| Error::new(400, "invalid digest size"))?,
    };
    check_digest(&digest, action)?;
    Ok(digest)
}
fn check_digest(d: &Digest, action: bool) -> Result<()> {
    d.validate()
        .map_err(|_| Error::new(400, "invalid digest"))?;
    if action && d.algorithm != "blake3" {
        return Err(Error::new(400, "action keys must use blake3"));
    }
    Ok(())
}
#[derive(Deserialize)]
struct DigestList {
    digests: Vec<Digest>,
}
async fn digest_list(request: &mut Request, action: bool) -> Result<Vec<Digest>> {
    let list: DigestList = serde_json::from_slice(&read_body(request, JSON_LIMIT).await?)?;
    if list.digests.len() > WORKER_BATCH_LIMIT {
        return Err(Error::new(400, "batch exceeds the supported size"));
    }
    let mut seen = HashSet::new();
    let mut digests = Vec::new();
    for d in list.digests {
        check_digest(&d, action)?;
        if seen.insert(d.clone()) {
            digests.push(d);
        }
    }
    Ok(digests)
}
async fn read_body(request: &mut Request, limit: usize) -> Result<Vec<u8>> {
    identity(request)?;
    routes::content_length(request, limit as u64)?;
    let mut stream = request.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::new(400, e))?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(Error::new(413, "request body is too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn identity(request: &Request) -> Result<()> {
    match request.headers().get("content-encoding")?.as_deref() {
        None | Some("identity") => Ok(()),
        _ => Err(Error::new(
            415,
            "only identity request encoding is supported",
        )),
    }
}
fn immutable(request: &Request) -> Result<()> {
    if request.headers().get("if-none-match")?.as_deref() != Some("*") {
        return Err(Error::new(412, "If-None-Match: * is required"));
    }
    Ok(())
}
fn json<T: Serialize>(value: &T) -> Result<Response> {
    Ok(Response::from_json(value)?)
}
fn media_json<T: Serialize>(value: &T, media: &str) -> Result<Response> {
    let mut response = Response::from_json(value)?;
    response.headers_mut().set("content-type", media)?;
    Ok(response)
}
fn empty(status: u16) -> Result<Response> {
    Ok(Response::empty()?.with_status(status))
}

async fn put_manifest(
    request: &mut Request,
    store: &Store,
    namespace: &str,
    key: &Digest,
) -> Result<Response> {
    let expected = if request.headers().get("if-none-match")?.as_deref() == Some("*") {
        None
    } else {
        let value = request
            .headers()
            .get("if-match")?
            .ok_or_else(|| Error::new(428, "If-None-Match: * or If-Match is required"))?;
        let etag = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(|| Error::new(400, "If-Match must contain one strong BLAKE3 ETag"))?;
        Some(etag.to_owned())
    };
    let current = store.manifest(namespace, key).await?;
    if current.as_ref().map(|row| row.etag.as_str()) != expected.as_deref() {
        return Err(Error::new(
            412,
            "action manifest changed; read and merge it before retrying",
        ));
    }
    let manifest: TaskActionManifest =
        serde_json::from_slice(&read_body(request, MANIFEST_LIMIT).await?)?;
    if !manifest.validate() || manifest.selector_digest() != *key {
        return Err(Error::new(400, "action manifest does not match request"));
    }
    let bytes = canonical_json(&manifest).map_err(Error::internal)?;
    let etag = blake3::hash(&bytes).to_hex().to_string();
    let object_key = upload::unique_key(&format!("{}/manifests", store.object_prefix));
    store.bucket.put(&object_key, bytes).execute().await?;
    if !store
        .commit_manifest(namespace, key, expected.as_deref(), &etag, &object_key)
        .await?
    {
        store.bucket.delete(&object_key).await?;
        return Err(Error::new(
            412,
            "action manifest changed; read and merge it before retrying",
        ));
    }
    // Superseded bodies are reclaimed by the orphan sweep after a grace period.
    let mut response = empty(if expected.is_some() { 204 } else { 201 })?;
    response.headers_mut().set("etag", &format!("\"{etag}\""))?;
    Ok(response)
}

async fn download_pack(
    request: &mut Request,
    env: &Env,
    principal: &auth::Principal,
    max_blob_bytes: u64,
) -> Result<Response> {
    let digests = digest_list(request, false).await?;
    let total = digests
        .iter()
        .try_fold(0u64, |n, d| n.checked_add(d.size))
        .ok_or_else(|| Error::new(413, "pack too large"))?;
    if total > max_blob_bytes {
        return Err(Error::new(413, "pack exceeds configured limit"));
    }
    // Account for artifact payload separately from bounded pack framing/control
    // overhead. A full legal pack fits the default 64 MiB anonymous payload budget.
    limits::check_bytes(env, principal, total).await?;
    let namespace = &principal.namespace;
    let backend = store(env, false)?;
    let pointers = backend.visible_objects(namespace, &digests).await?;
    let mut objects = Vec::new();
    let mut bytes = 0u64;
    for digest in digests {
        if let Some(key) = pointers.get(&digest.key()) {
            let object = backend.bucket.head(key).await?;
            if !object.is_some_and(|object| object.size() == digest.size) {
                backend.repair_blob(&digest, key).await?;
                continue;
            }
            bytes += digest.size;
            objects.push((digest, key.clone()));
        }
    }
    worker::console_log!(
        "mbx.pack members={} bytes={} strategy=bulk",
        objects.len(),
        bytes
    );
    let count = objects.len();
    let length = 8 + count as u64 * 41 + bytes;
    let stream = async_stream::try_stream! {
        yield BLOB_PACK_MAGIC.to_vec();
        // Fetch and consume one body at a time. Holding every GET open while
        // collecting headers can exhaust the platform's connection budget.
        for (digest, key) in objects {
            let object = backend.bucket.get(&key).execute().await?;
            let Some(object) = object else {
                backend.repair_blob(&digest,&key).await.map_err(|e| worker::Error::from(e.message))?;
                Err(worker::Error::from("pack member disappeared"))?;
                unreachable!();
            };
            if object.size() != digest.size {
                backend.repair_blob(&digest,&key).await.map_err(|e| worker::Error::from(e.message))?;
                Err(worker::Error::from("pack member changed size"))?;
            }
            let mut header=Vec::with_capacity(41);
            header.push(if digest.algorithm=="blake3"{1}else{2});
            header.extend(hex::decode(&digest.hash).map_err(|e| worker::Error::from(e.to_string()))?);
            header.extend(digest.size.to_be_bytes());
            yield header;
            let mut body=object.body().ok_or_else(|| worker::Error::from("missing object body"))?.stream()?;
            while let Some(chunk)=body.next().await {yield chunk?;}
        }
    };
    let fixed = worker::FixedLengthStream::wrap(stream, length);
    let raw: worker_sys::FixedLengthStream = fixed.into();
    let mut response = Response::from_body(worker::ResponseBody::Stream(raw.readable()))?;
    response
        .headers_mut()
        .set("content-type", BLOB_PACK_MEDIA_TYPE)?;
    response
        .headers_mut()
        .set("content-length", &length.to_string())?;
    response
        .headers_mut()
        .set("mbx-cache-pack-blobs", &count.to_string())?;
    response
        .headers_mut()
        .set("mbx-cache-pack-bytes", &bytes.to_string())?;
    Ok(response)
}

// Read a pack without buffering a complete frame or the complete request.
struct Input {
    stream: compression::BodyStream,
    pending: Vec<u8>,
    offset: usize,
}
impl Input {
    async fn take(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        while self.offset == self.pending.len() {
            match self.stream.next().await {
                Some(chunk) => {
                    self.pending = chunk?;
                    self.offset = 0;
                }
                None => return Ok(None),
            }
        }
        let end = self.pending.len().min(self.offset + max);
        let chunk = self.pending[self.offset..end].to_vec();
        self.offset = end;
        Ok(Some(chunk))
    }
    async fn exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(n);
        while bytes.len() < n {
            let chunk = self
                .take(n - bytes.len())
                .await?
                .ok_or_else(|| Error::new(400, "truncated blob pack"))?;
            bytes.extend(chunk);
        }
        Ok(bytes)
    }
}
async fn upload_pack(request: &mut Request, store: &Store, namespace: &str) -> Result<Response> {
    if request.headers().get("content-type")?.as_deref() != Some(BLOB_PACK_MEDIA_TYPE) {
        return Err(Error::new(415, "invalid blob pack content type"));
    }
    let count = required_number(request, "mbx-cache-pack-blobs")?;
    let declared = required_number(request, "mbx-cache-pack-bytes")?;
    if count > WORKER_BATCH_LIMIT as u64 || declared > store.max_blob_bytes {
        return Err(Error::new(413, "pack exceeds configured limit"));
    }
    let mut input = Input {
        stream: compression::body(
            request,
            store.max_blob_bytes + 8 + 41 * WORKER_BATCH_LIMIT as u64,
            declared + 8 + 41 * count,
        )?,
        pending: Vec::new(),
        offset: 0,
    };
    if input.exact(8).await? != BLOB_PACK_MAGIC {
        return Err(Error::new(400, "invalid blob pack magic"));
    }
    let mut total = 0u64;
    let mut staged = Vec::new();
    for _ in 0..count {
        let h = input.exact(41).await?;
        let algorithm = match h[0] {
            1 => "blake3",
            2 => "sha256",
            _ => return Err(Error::new(400, "invalid pack algorithm")),
        };
        let size = u64::from_be_bytes(h[33..41].try_into().unwrap());
        total = total
            .checked_add(size)
            .ok_or_else(|| Error::new(413, "pack too large"))?;
        if total > declared {
            return Err(Error::new(400, "pack exceeds declared bytes"));
        }
        let digest = Digest {
            algorithm: algorithm.into(),
            hash: hex::encode(&h[1..33]),
            size,
        };
        let input_ref = &mut input;
        let frame = async_stream::try_stream! {
            let mut remaining=size;
            while remaining>0 {
                let chunk=input_ref.take(remaining.min(64*1024) as usize).await?
                    .ok_or_else(|| Error::new(400,"truncated blob pack"))?;
                remaining-=chunk.len() as u64; yield chunk;
            }
        };
        let key = upload::persist(store, &digest, frame).await?;
        staged.push((digest, key, true));
    }
    if total != declared || input.take(1).await?.is_some() {
        return Err(Error::new(400, "pack contradicts declared headers"));
    }
    store.register_many(namespace, &staged).await?;
    media_json(
        &serde_json::json!({"created":0,"existing":count}),
        BLOB_PACK_RECEIPT_MEDIA_TYPE,
    )
}
fn required_number(request: &Request, name: &str) -> Result<u64> {
    request
        .headers()
        .get(name)?
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::new(400, format!("{name} must be an unsigned integer")))
}

#[event(scheduled)]
async fn scheduled(_event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    ctx.wait_until(async move {
        if let Err(error) = maintenance::sweep(&env).await {
            worker::console_error!("metadata sweep failed: {}", error.message);
        }
    });
}

fn store(env: &Env, primary: bool) -> Result<Store> {
    Ok(Store {
        primary: env.d1("MBX_DB")?,
        trusted_presence: auth::setting(env, "MBX_CACHE_D1_PRESENCE_RECONCILED", "false")
            .parse()
            .map_err(Error::internal)?,
        db: env.d1("MBX_DB")?.with_session(Some(if primary {
            "first-primary"
        } else {
            "first-unconstrained"
        }))?,
        bucket: env.bucket("MBX_BLOBS")?,
        max_blob_bytes: auth::setting(
            env,
            "MBX_CACHE_MAX_BLOB_BYTES",
            &DEFAULT_BLOB_LIMIT.to_string(),
        )
        .parse()
        .map_err(Error::internal)?,
        object_prefix: auth::object_prefix(env)?,
        validation_queries: std::sync::atomic::AtomicUsize::new(0),
        validation_bytes: std::sync::atomic::AtomicU64::new(0),
    })
}
fn error_response(error: Error) -> worker::Result<Response> {
    let mut response =
        Response::from_json(&serde_json::json!({"error":error.message}))?.with_status(error.status);
    response.headers_mut().set("cache-control", "no-store")?;
    if error.status == 426 {
        response.headers_mut().set("mbx-cache-protocol", "1")?;
    }
    Ok(response)
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn cached_read(
    raw: web_sys::Request,
    env: Env,
    raw_ctx: worker_sys::Context,
) -> std::result::Result<web_sys::Response, wasm_bindgen::JsValue> {
    let mut request = Request::from(raw);
    let ctx = Context::new(raw_ctx);
    let response: Result<Response> = async {
        let scope: edge::Scope = ctx.props()?;
        if !auth_policy::valid_namespace(&scope.namespace) {
            return Err(Error::new(401, "invalid cache scope"));
        }
        let path = request.path();
        let parts: Vec<_> = path.split('/').collect();
        if !matches!(request.method(), Method::Get | Method::Head)
            || parts.len() != 6
            || parts[1] != "v1"
            || !matches!(parts[2], "blobs" | "action-results")
        {
            return Err(Error::new(404, "not found"));
        }
        worker::console_log!("mbx.cache_miss kind={}", parts[2]);
        let method = request.method();
        let mut response = resource(
            &mut request,
            &store(&env, false)?,
            &scope.namespace,
            method,
            &parts,
        )
        .await?;
        response.headers_mut().set(
            "cache-control",
            if parts[2] == "blobs" {
                "public, max-age=86400"
            } else {
                "public, max-age=3600"
            },
        )?;
        Ok(response)
    }
    .await;
    match response {
        Ok(response) => Ok(response.into()),
        Err(error) => error_response(error).map(Into::into).map_err(Into::into),
    }
}
