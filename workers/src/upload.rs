//! Bounded streaming to a private R2 key; only a successful verification is published.
use crate::{
    error::{Error, Result},
    metadata::Store,
    model::{Algorithm, Digest},
};
use futures_util::{Stream, StreamExt};
use sha2::Digest as _;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = crypto, js_name = randomUUID)]
    fn random_uuid() -> String;
}
pub fn unique_key(prefix: &str) -> String {
    format!("{prefix}/{}", random_uuid())
}

pub async fn upload<S>(store: &Store, namespace: &str, digest: &Digest, input: S) -> Result<bool>
where
    S: Stream<Item = Result<Vec<u8>>>,
{
    if digest.size > store.max_blob_bytes {
        return Err(Error::new(413, "blob exceeds configured limit"));
    }
    let algorithm = digest.algorithm_kind().map_err(|e| Error::new(400, e))?;
    let object_key = unique_key("blobs");
    // The native stream tells R2 the decoded length without buffering a blob.
    let fixed =
        worker_sys::FixedLengthStream::new(digest.size as u32).map_err(worker::Error::from)?;
    let writer = fixed.writable().get_writer().map_err(worker::Error::from)?;
    let pump = async {
        let result: Result<()> = async {
            futures_util::pin_mut!(input);
            let mut count = 0u64;
            let mut blake3 = blake3::Hasher::new();
            let mut sha256 = sha2::Sha256::new();
            while let Some(chunk) = input.next().await {
                let chunk = chunk?;
                count = count
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| Error::new(413, "blob too large"))?;
                if count > digest.size {
                    return Err(Error::new(413, "blob exceeds declared size"));
                }
                match algorithm {
                    Algorithm::Blake3 => {
                        blake3.update(&chunk);
                    }
                    Algorithm::Sha256 => sha256.update(&chunk),
                }
                if !chunk.is_empty() {
                    let array = js_sys::Uint8Array::from(chunk.as_slice());
                    JsFuture::from(writer.write_with_chunk(&array))
                        .await
                        .map_err(worker::Error::from)?;
                }
            }
            let hash = if algorithm == Algorithm::Blake3 {
                blake3.finalize().to_hex().to_string()
            } else {
                hex::encode(sha256.finalize())
            };
            if count != digest.size || hash != digest.hash {
                return Err(Error::new(
                    400,
                    "content does not match the requested digest",
                ));
            }
            JsFuture::from(writer.close())
                .await
                .map_err(worker::Error::from)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = JsFuture::from(
                writer.abort_with_reason(&JsValue::from_str("upload verification failed")),
            )
            .await;
        }
        result
    };
    let persist = async {
        let result = store
            .bucket
            .put(&object_key, worker::Data::ReadableStream(fixed.readable()))
            .execute()
            .await;
        if result.is_err() {
            let _ =
                JsFuture::from(writer.abort_with_reason(&JsValue::from_str("R2 upload failed")))
                    .await;
        }
        result
    };
    let (verified, persisted) = futures_util::join!(pump, persist);
    if let Err(error) = verified {
        // The key is unique: cleanup can never delete another upload's object.
        let _ = store.bucket.delete(&object_key).await;
        return Err(error);
    }
    persisted?;
    let created = store.register(namespace, digest, &object_key).await?;
    if !created {
        store.bucket.delete(&object_key).await?;
    }
    Ok(created)
}
