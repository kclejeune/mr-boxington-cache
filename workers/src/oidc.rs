//! Isolate-local OIDC key caching; only owned Rust data crosses request boundaries.
use crate::{
    auth_policy::{OidcProviderConfig, configured_algorithms, verify_jwt},
    error::{Error, Result},
};
use jsonwebtoken::{decode_header, jwk::JwkSet};
use serde::Deserialize;
use std::{cell::RefCell, collections::HashMap, time::Duration};
use worker::{Delay, Fetch};

#[derive(Clone, Default)]
struct Cached {
    set: Option<JwkSet>,
    uri: Option<String>,
    advertised: Vec<String>,
    fetched: f64,
    attempted: Option<f64>,
    refreshing: bool,
}
thread_local! {
    static KEYS: RefCell<HashMap<String,Cached>> = RefCell::new(HashMap::new());
}
struct RefreshGuard {
    key: String,
    attempted: f64,
}
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        KEYS.with_borrow_mut(|keys| {
            if let Some(cached) = keys.get_mut(&self.key)
                && cached.attempted == Some(self.attempted)
            {
                cached.refreshing = false;
            }
        });
    }
}
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
}
fn unauthorized() -> Error {
    Error::new(401, "invalid bearer token")
}
fn now() -> f64 {
    js_sys::Date::now() / 1000.0
}

pub async fn verify(
    token: &str,
    config: &OidcProviderConfig,
    configuration: &str,
) -> Result<serde_json::Value> {
    let header = decode_header(token).map_err(|_| unauthorized())?;
    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty() && kid.len() <= 256)
        .ok_or_else(unauthorized)?;
    // Reject unsupported algorithms before allowing a token to trigger network work.
    let algorithms = configured_algorithms(&config.algorithms, &[]).map_err(Error::internal)?;
    if !algorithms.contains(&header.alg)
        || header.crit.as_ref().is_some_and(|crit| !crit.is_empty())
    {
        return Err(unauthorized());
    }
    let cache_key = format!(
        "{}:{}",
        blake3::hash(configuration.as_bytes()).to_hex(),
        config.issuer
    );
    let (keys, advertised) = get_keys(config, &cache_key, kid).await?;
    let algorithms =
        configured_algorithms(&config.algorithms, &advertised).map_err(Error::internal)?;
    if !algorithms.contains(&header.alg) {
        return Err(unauthorized());
    }
    let jwk = keys.find(kid).ok_or_else(unauthorized)?;
    verify_jwt(token, jwk, header.alg, config).map_err(|_| unauthorized())
}

async fn get_keys(
    config: &OidcProviderConfig,
    cache_key: &str,
    kid: &str,
) -> Result<(JwkSet, Vec<String>)> {
    let deadline = now() + 35.0;
    loop {
        let cached = KEYS.with_borrow_mut(|keys| {
            // Configuration changes must not grow an isolate's cache indefinitely.
            if keys.len() >= 32 && !keys.contains_key(cache_key) {
                keys.retain(|_, entry| entry.refreshing);
            }
            let entry = keys.entry(cache_key.to_owned()).or_default();
            if entry.refreshing && entry.attempted.is_some_and(|at| now() - at > 35.0) {
                entry.refreshing = false;
            }
            entry.clone()
        });
        let known = cached
            .set
            .as_ref()
            .is_some_and(|set| set.find(kid).is_some());
        if known && now() - cached.fetched < config.jwks_refresh_seconds as f64 {
            return Ok((cached.set.unwrap(), cached.advertised));
        }
        if cached.refreshing {
            if known {
                return Ok((cached.set.unwrap(), cached.advertised));
            }
            if now() >= deadline {
                return Err(unauthorized());
            }
            // A wait belongs to this request's I/O context, never another request's promise.
            Delay::from(Duration::from_millis(10)).await;
            continue;
        }
        if cached.attempted.is_some_and(|at| now() - at < 30.0) {
            return if known {
                Ok((cached.set.unwrap(), cached.advertised))
            } else {
                Err(unauthorized())
            };
        }
        let attempted = now();
        KEYS.with_borrow_mut(|keys| {
            let entry = keys.get_mut(cache_key).unwrap();
            entry.refreshing = true;
            entry.attempted = Some(attempted);
        });
        let _guard = RefreshGuard {
            key: cache_key.to_owned(),
            attempted,
        };
        let attempts = if cached.set.is_some() { 1 } else { 3 };
        for attempt in 0..attempts {
            match fetch_keys(config, &cached).await {
                Ok((uri, advertised, set)) => {
                    KEYS.with_borrow_mut(|keys| {
                        if let Some(entry) = keys.get_mut(cache_key)
                            && entry.attempted == Some(attempted)
                        {
                            entry.set = Some(set.clone());
                            entry.uri = Some(uri);
                            entry.advertised = advertised.clone();
                            entry.fetched = now();
                        }
                    });
                    return Ok((set, advertised));
                }
                Err(_) if attempt + 1 < attempts => {
                    Delay::from(Duration::from_millis(250 * (attempt + 1))).await
                }
                Err(error) => worker::console_warn!(
                    "OIDC key refresh failed for {}: {}",
                    config.issuer,
                    error.message
                ),
            }
        }
        return if known {
            Ok((cached.set.unwrap(), cached.advertised))
        } else {
            Err(unauthorized())
        };
    }
}
async fn fetch_keys(
    config: &OidcProviderConfig,
    cached: &Cached,
) -> Result<(String, Vec<String>, JwkSet)> {
    let (uri, advertised) = if let Some(uri) = cached.uri.as_ref().or(config.jwks_uri.as_ref()) {
        (uri.clone(), cached.advertised.clone())
    } else {
        let uri = config.discovery_uri.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/openid-configuration",
                config.issuer.trim_end_matches('/')
            )
        });
        let document: Discovery = fetch_json(&uri).await?;
        if document.issuer != config.issuer {
            return Err(Error::new(401, "OIDC discovery issuer mismatch"));
        }
        (
            document.jwks_uri,
            document.id_token_signing_alg_values_supported,
        )
    };
    let set: JwkSet = fetch_json(&uri).await?;
    if set.keys.len() > 128 {
        return Err(Error::new(401, "OIDC key set is too large"));
    }
    Ok((uri, advertised, set))
}
async fn fetch_json<T: for<'a> Deserialize<'a>>(uri: &str) -> Result<T> {
    use futures_util::StreamExt;
    let controller = worker::AbortController::default();
    let signal = controller.signal();
    let read = async {
        let url = uri.parse().map_err(Error::internal)?;
        let mut response = Fetch::Url(url).send_with_signal(&signal).await?;
        if response.status_code() != 200 {
            return Err(Error::new(401, "OIDC endpoint returned an error"));
        }
        let mut body = response.stream()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(Error::new(401, "OIDC response is too large"));
            }
            bytes.extend(chunk);
        }
        Ok(bytes)
    };
    let timeout = Delay::from(Duration::from_secs(10));
    futures_util::pin_mut!(read, timeout);
    let bytes = match futures_util::future::select(read, timeout).await {
        futures_util::future::Either::Left((result, _)) => result?,
        futures_util::future::Either::Right(_) => {
            controller.abort();
            return Err(Error::new(401, "OIDC endpoint timed out"));
        }
    };

    serde_json::from_slice(&bytes).map_err(|_| Error::new(401, "invalid OIDC response"))
}
