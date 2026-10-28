//! Authorization precedes every cache lookup. Only immutable positive reads enter CachedStore.
use crate::{auth, error::Result, model::Digest};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Context, Env, Method, Request, Response};

#[derive(Serialize, Deserialize)]
pub struct Scope {
    pub namespace: String,
    pub epoch: String,
}

pub async fn read(
    ctx: &Context,
    env: &Env,
    namespace: &str,
    kind: &str,
    digest: &Digest,
    method: Method,
) -> Result<Response> {
    let uri = format!(
        "https://mbx-internal/v1/{kind}/{}/{}/{}",
        digest.algorithm, digest.hash, digest.size
    );
    let request = Request::new(&uri, method.clone())?;
    let response = loopback(ctx, env, namespace, &request).await;
    if !response
        .as_ref()
        .is_ok_and(|response| response.status_code() != 502)
    {
        worker::console_warn!("mbx.cache_fallback kind={kind}");
    }
    let response = match response {
        Ok(response) if response.status_code() != 502 => response,
        // Nimbus has seen transient empty 502s from the cache pipeline. Fall back without another authorization lookup.
        _ => {
            let mut request = Request::new(&uri, method.clone())?;
            match crate::resource(
                &mut request,
                &crate::store(env, false)?,
                namespace,
                method.clone(),
                &request_parts(&uri),
            )
            .await
            {
                Ok(response) => response,
                Err(error) => crate::error_response(error)?,
            }
        }
    };
    // Fetch/cache responses have immutable headers. Copy only the headers, never the streamed body.
    let headers = response.headers().clone();
    let response = response.with_headers(headers);
    let mut response = if method == Method::Head {
        Response::empty()?
            .with_status(response.status_code())
            .with_headers(response.headers().clone())
    } else {
        response
    };
    let status = response
        .headers()
        .get("cf-cache-status")?
        .unwrap_or_else(|| "BYPASS".into());
    response
        .headers_mut()
        .set("mbx-cache-edge-status", &status)?;
    // Only the internal entrypoint may cache this response. Downstream caches must not bypass authorization.
    response
        .headers_mut()
        .set("cache-control", "private, no-store")?;
    response
        .headers_mut()
        .delete("cloudflare-cdn-cache-control")?;
    response.headers_mut().delete("cdn-cache-control")?;
    Ok(response)
}
fn request_parts(uri: &str) -> Vec<&str> {
    // Internal URIs are constructed above, never accepted from the caller.
    uri.strip_prefix("https://mbx-internal")
        .unwrap()
        .split('/')
        .collect()
}
async fn loopback(
    ctx: &Context,
    env: &Env,
    namespace: &str,
    request: &Request,
) -> Result<Response> {
    let exports = js_sys::Reflect::get(ctx.as_ref(), &JsValue::from_str("exports"))
        .map_err(worker::Error::from)?;
    let constructor = js_sys::Reflect::get(&exports, &JsValue::from_str("CachedStore"))
        .map_err(worker::Error::from)?
        .unchecked_into::<js_sys::Function>();
    let options = js_sys::Object::new();
    let scope = Scope {
        namespace: namespace.to_owned(),
        epoch: auth::setting(env, "MBX_CACHE_CACHE_EPOCH", "v1"),
    };
    let props = worker::serde_wasm_bindgen::to_value(&scope).map_err(worker::Error::from)?;
    js_sys::Reflect::set(&options, &JsValue::from_str("props"), &props)
        .map_err(worker::Error::from)?;
    let args = js_sys::Array::new();
    args.push(&options);
    let stub =
        js_sys::Reflect::apply(&constructor, &exports, &args).map_err(worker::Error::from)?;
    let fetch = js_sys::Reflect::get(&stub, &JsValue::from_str("fetch"))
        .map_err(worker::Error::from)?
        .unchecked_into::<js_sys::Function>();
    let raw: web_sys::Request = request.try_into()?;
    let args = js_sys::Array::new();
    args.push(&raw);
    let value = js_sys::Reflect::apply(&fetch, &stub, &args).map_err(worker::Error::from)?;
    let promise = js_sys::Promise::resolve(&value);
    let response = JsFuture::from(promise)
        .await
        .map_err(worker::Error::from)?
        .dyn_into::<web_sys::Response>()
        .map_err(worker::Error::from)?;
    Ok(response.into())
}
