use crate::error::{Error, Result};
use serde::Deserialize;
use worker::{Env, Headers};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    token: String,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
}

pub fn authorize(env: &Env, headers: &Headers, write: bool) -> Result<String> {
    if headers.get("mbx-cache-protocol")?.as_deref() != Some("1") {
        return Err(Error::new(426, "mbx cache protocol version 1 is required"));
    }
    let namespace = headers
        .get("mbx-cache-namespace")?
        .filter(|value| valid_namespace(value))
        .ok_or_else(|| Error::new(400, "a valid Mbx-Cache-Namespace header is required"))?;
    let public: Vec<String> = serde_json::from_str(&setting(
        env,
        "MBX_CACHE_ANONYMOUS_READ_NAMESPACES_JSON",
        "[]",
    ))
    .map_err(Error::internal)?;
    if !write
        && public
            .iter()
            .any(|pattern| matches_namespace(pattern, &namespace))
    {
        return Ok(namespace);
    }
    let grants: Vec<Grant> = serde_json::from_str(&setting(env, "MBX_CACHE_TOKENS_JSON", "[]"))
        .map_err(Error::internal)?;
    let authorization = headers.get("authorization")?.unwrap_or_default();
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::new(401, "a bearer token is required"))?;
    let grant = grants
        .iter()
        .find(|grant| constant_time_eq(grant.token.as_bytes(), token.as_bytes()))
        .ok_or_else(|| Error::new(401, "invalid bearer token"))?;
    let patterns = if write { &grant.write } else { &grant.read };
    if !patterns
        .iter()
        .any(|pattern| matches_namespace(pattern, &namespace))
    {
        return Err(Error::new(
            403,
            "token is not authorized for this namespace",
        ));
    }
    Ok(namespace)
}

pub fn setting(env: &Env, name: &str, fallback: &str) -> String {
    env.secret(name)
        .map(|value| value.to_string())
        .or_else(|_| env.var(name).map(|value| value.to_string()))
        .unwrap_or_else(|_| fallback.to_owned())
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn matches_namespace(pattern: &str, namespace: &str) -> bool {
    pattern == "*"
        || pattern == namespace
        || pattern.strip_suffix("/*").is_some_and(|prefix| {
            namespace.starts_with(prefix) && namespace.as_bytes().get(prefix.len()) == Some(&b'/')
        })
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
