use crate::auth_policy::{
    Access, OidcProviderConfig, TokenGrant, configured_algorithms, constant_time_eq,
    matches_namespace, unverified_issuer, valid_namespace, validate_provider_config,
};
use crate::error::{Error, Result};
use worker::{Env, Headers};

pub async fn authorize(env: &Env, headers: &Headers, write: bool) -> Result<String> {
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
    let grants: Vec<TokenGrant> =
        serde_json::from_str(&setting(env, "MBX_CACHE_TOKENS_JSON", "[]"))
            .map_err(Error::internal)?;
    let authorization = headers.get("authorization")?.unwrap_or_default();
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::new(401, "a bearer token is required"))?;
    if let Some(grant) = grants
        .iter()
        .find(|grant| constant_time_eq(grant.token.as_bytes(), token.as_bytes()))
    {
        let patterns = if write { &grant.write } else { &grant.read };
        if patterns
            .iter()
            .any(|pattern| matches_namespace(pattern, &namespace))
        {
            return Ok(namespace);
        }
        return Err(Error::new(
            403,
            "token is not authorized for this namespace",
        ));
    }
    if token.len() > 16 * 1024 {
        return Err(Error::new(401, "invalid bearer token"));
    }
    let configuration = setting(env, "MBX_CACHE_OIDC_PROVIDERS_JSON", "[]");
    let configs: Vec<OidcProviderConfig> =
        serde_json::from_str(&configuration).map_err(Error::internal)?;
    if configs.len() > 16 {
        return Err(Error::internal(
            "at most 16 OIDC providers may be configured",
        ));
    }
    let mut issuers = std::collections::HashSet::new();
    for config in &configs {
        validate_provider_config(config).map_err(Error::internal)?;
        configured_algorithms(&config.algorithms, &[]).map_err(Error::internal)?;
        if !issuers.insert(&config.issuer) {
            return Err(Error::internal("duplicate OIDC issuer"));
        }
    }
    let issuer = unverified_issuer(token).map_err(|_| Error::new(401, "invalid bearer token"))?;
    let config = configs
        .iter()
        .find(|c| c.issuer == issuer)
        .ok_or_else(|| Error::new(401, "invalid bearer token"))?;
    let claims = crate::oidc::verify(token, config, &configuration).await?;
    let access = if write { Access::Write } else { Access::Read };
    if !config.rules.iter().any(|rule| {
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

    Ok(namespace)
}

pub fn setting(env: &Env, name: &str, fallback: &str) -> String {
    env.secret(name)
        .map(|value| value.to_string())
        .or_else(|_| env.var(name).map(|value| value.to_string()))
        .unwrap_or_else(|_| fallback.to_owned())
}
