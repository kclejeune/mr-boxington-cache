use crate::auth_policy::{
    Access, OidcProviderConfig, TokenGrant, configured_algorithms, constant_time_eq,
    matches_namespace, unverified_issuer, valid_namespace, validate_provider_config,
};
use crate::error::{Error, Result};
use worker::{Env, Headers};

#[derive(Clone)]
struct Config {
    public: Vec<String>,
    grants: Vec<TokenGrant>,
    providers: Vec<OidcProviderConfig>,
    oidc: String,
}
thread_local! { static CONFIG: std::cell::RefCell<Option<(blake3::Hash, Config)>> = const { std::cell::RefCell::new(None) }; }
pub struct Principal {
    pub namespace: String,
    pub key: String,
    pub anonymous: bool,
}
fn principal(env: &Env, namespace: String, identity: &str, anonymous: bool) -> Result<Principal> {
    let secret = setting(env, "MBX_CACHE_PRINCIPAL_KEY", "");
    if secret.len() < 32 && setting(env, "MBX_CACHE_RATE_LIMIT_MODE", "enforce") != "off" {
        return Err(Error::internal(
            "MBX_CACHE_PRINCIPAL_KEY must contain at least 32 bytes",
        ));
    }
    let key = blake3::keyed_hash(
        blake3::hash(secret.as_bytes()).as_bytes(),
        identity.as_bytes(),
    )
    .to_hex()
    .to_string();
    Ok(Principal {
        namespace,
        key,
        anonymous,
    })
}
fn configuration(env: &Env) -> Result<Config> {
    let public = setting(env, "MBX_CACHE_ANONYMOUS_READ_NAMESPACES_JSON", "[]");
    let grants = setting(env, "MBX_CACHE_TOKENS_JSON", "[]");
    let oidc = setting(env, "MBX_CACHE_OIDC_PROVIDERS_JSON", "[]");
    if public.len() + grants.len() + oidc.len() > 1024 * 1024 {
        return Err(Error::internal("authentication configuration too large"));
    }
    let hash = blake3::hash(serde_json::to_string(&[&public, &grants, &oidc])?.as_bytes());
    if let Some(config) = CONFIG.with_borrow(|cache| {
        cache
            .as_ref()
            .filter(|(key, _)| key == &hash)
            .map(|(_, config)| config.clone())
    }) {
        return Ok(config);
    }
    let config = Config {
        public: serde_json::from_str(&public)
            .map_err(|_| Error::internal("invalid anonymous configuration"))?,
        grants: serde_json::from_str(&grants)
            .map_err(|_| Error::internal("invalid static grant configuration"))?,
        providers: serde_json::from_str(&oidc)
            .map_err(|_| Error::internal("invalid OIDC configuration"))?,
        oidc,
    };
    crate::auth_policy::validate_patterns(&config.public).map_err(Error::internal)?;
    if config.grants.len() > 256 || config.providers.len() > 16 {
        return Err(Error::internal("too many authentication grants/providers"));
    }
    let mut tokens = std::collections::HashSet::new();
    for grant in &config.grants {
        if grant.token.is_empty()
            || grant.token.len() > 16384
            || !tokens.insert(&grant.token)
            || grant.read.is_empty() && grant.write.is_empty()
        {
            return Err(Error::internal("invalid or duplicate static grant"));
        }
        crate::auth_policy::validate_patterns(&grant.read).map_err(Error::internal)?;
        crate::auth_policy::validate_patterns(&grant.write).map_err(Error::internal)?;
    }
    let mut issuers = std::collections::HashSet::new();
    for provider in &config.providers {
        validate_provider_config(provider).map_err(Error::internal)?;
        configured_algorithms(&provider.algorithms, &[]).map_err(Error::internal)?;
        if !issuers.insert(&provider.issuer) {
            return Err(Error::internal("duplicate OIDC issuer"));
        }
    }
    CONFIG.with_borrow_mut(|cache| *cache = Some((hash, config.clone())));
    Ok(config)
}
pub async fn authorize(env: &Env, headers: &Headers, write: bool) -> Result<Principal> {
    if headers.get("mbx-cache-protocol")?.as_deref() != Some("1") {
        return Err(Error::new(426, "mbx cache protocol version 1 is required"));
    }
    let namespace = headers
        .get("mbx-cache-namespace")?
        .filter(|value| valid_namespace(value))
        .ok_or_else(|| Error::new(400, "a valid Mbx-Cache-Namespace header is required"))?;
    let authorization = headers.get("authorization")?.unwrap_or_default();
    if authorization.len() > 16 * 1024 + 7 {
        return Err(Error::new(401, "invalid bearer token"));
    }
    let config = configuration(env)?;
    if !write
        && config
            .public
            .iter()
            .any(|pattern| matches_namespace(pattern, &namespace))
    {
        return principal(env, namespace, "anonymous", true);
    }
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::new(401, "a bearer token is required"))?;
    if let Some(grant) = config
        .grants
        .iter()
        .find(|grant| constant_time_eq(grant.token.as_bytes(), token.as_bytes()))
    {
        let patterns = if write { &grant.write } else { &grant.read };
        if patterns
            .iter()
            .any(|pattern| matches_namespace(pattern, &namespace))
        {
            return principal(env, namespace, &format!("static:{}", grant.token), false);
        }
        return Err(Error::new(
            403,
            "token is not authorized for this namespace",
        ));
    }
    if token.len() > 16 * 1024 {
        return Err(Error::new(401, "invalid bearer token"));
    }
    let issuer = unverified_issuer(token).map_err(|_| Error::new(401, "invalid bearer token"))?;
    let provider = config
        .providers
        .iter()
        .find(|c| c.issuer == issuer)
        .ok_or_else(|| Error::new(401, "invalid bearer token"))?;
    let claims = crate::oidc::verify(token, provider, &config.oidc).await?;
    let access = if write { Access::Write } else { Access::Read };
    if !provider.rules.iter().any(|rule| {
        rule.matches_claims(&claims)
            && rule
                .patterns(access)
                .iter()
                .any(|p| matches_namespace(p, &namespace))
    }) {
        return Err(Error::new(
            403,
            "identity is not authorized for this namespace",
        ));
    }

    let subject = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::new(401, "invalid bearer token"))?;
    principal(
        env,
        namespace,
        &serde_json::to_string(&[&provider.issuer, subject])?,
        false,
    )
}

pub fn setting(env: &Env, name: &str, fallback: &str) -> String {
    env.secret(name)
        .map(|value| value.to_string())
        .or_else(|_| env.var(name).map(|value| value.to_string()))
        .unwrap_or_else(|_| fallback.to_owned())
}

/// A bucket may be shared with the native server. New writes and GC own only this prefix.
pub fn object_prefix(env: &Env) -> Result<String> {
    let prefix = setting(env, "MBX_CACHE_R2_PREFIX", "workers/v1")
        .trim_matches('/')
        .to_owned();
    if prefix.is_empty()
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::internal(
            "MBX_CACHE_R2_PREFIX must be a nonempty object prefix",
        ));
    }
    Ok(prefix)
}
