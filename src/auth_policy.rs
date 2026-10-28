//! Runtime-independent authorization policy and JWT validation.
use anyhow::{Context, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode,
    jwk::{Jwk, KeyOperations, PublicKeyUse},
};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, str::FromStr};

const DEFAULT_JWKS_REFRESH_SECONDS: u64 = 300;
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 60;
const DEFAULT_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenGrant {
    pub token: String,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcProviderConfig {
    pub(crate) issuer: String,
    pub(crate) audiences: Vec<String>,
    #[serde(default)]
    pub(crate) discovery_uri: Option<String>,
    #[serde(default)]
    pub(crate) jwks_uri: Option<String>,
    #[serde(default)]
    pub(crate) algorithms: Vec<String>,
    #[serde(default = "default_jwks_refresh_seconds")]
    pub(crate) jwks_refresh_seconds: u64,
    #[serde(default = "default_clock_skew_seconds")]
    pub(crate) clock_skew_seconds: u64,
    pub(crate) rules: Vec<OidcRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcRule {
    pub(crate) claims: BTreeMap<String, ClaimRequirement>,
    #[serde(default)]
    pub(crate) read: Vec<String>,
    #[serde(default)]
    pub(crate) write: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ClaimRequirement {
    One(ScalarValue),
    Any(Vec<ScalarValue>),
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum ScalarValue {
    String(String),
    Number(serde_json::Number),
    Bool(bool),
}

#[derive(Clone, Copy)]
pub enum Access {
    Read,
    Write,
}

impl OidcRule {
    pub(crate) fn patterns(&self, access: Access) -> &[String] {
        match access {
            Access::Read => &self.read,
            Access::Write => &self.write,
        }
    }

    pub(crate) fn matches_claims(&self, claims: &Value) -> bool {
        self.claims.iter().all(|(name, requirement)| {
            claims
                .get(name)
                .is_some_and(|actual| requirement.matches(actual))
        })
    }
}

impl ClaimRequirement {
    fn matches(&self, actual: &Value) -> bool {
        let expected = match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Any(values) => values,
        };
        match actual {
            Value::Array(values) => values
                .iter()
                .any(|actual| expected.iter().any(|value| value.matches(actual))),
            actual => expected.iter().any(|value| value.matches(actual)),
        }
    }
}

impl ScalarValue {
    fn matches(&self, actual: &Value) -> bool {
        match (self, actual) {
            (Self::String(expected), Value::String(actual)) => expected == actual,
            (Self::Number(expected), Value::Number(actual)) => expected == actual,
            (Self::Bool(expected), Value::Bool(actual)) => expected == actual,
            _ => false,
        }
    }
}

pub(crate) fn validate_provider_config(config: &OidcProviderConfig) -> anyhow::Result<()> {
    if config.issuer.is_empty() || config.audiences.is_empty() || config.rules.is_empty() {
        bail!("each OIDC provider requires issuer, audiences, and rules");
    }
    if config.jwks_refresh_seconds == 0 {
        bail!("OIDC jwks_refresh_seconds must be greater than zero");
    }
    if config.rules.iter().any(|rule| rule.claims.is_empty()) {
        bail!("each OIDC authorization rule must require at least one claim");
    }
    Ok(())
}

pub(crate) fn configured_algorithms(
    configured: &[String],
    advertised: &[String],
) -> anyhow::Result<Vec<Algorithm>> {
    let mut algorithms = if configured.is_empty() {
        DEFAULT_ALGORITHMS.to_vec()
    } else {
        configured
            .iter()
            .map(|name| {
                Algorithm::from_str(name)
                    .map_err(|_| anyhow!("unsupported OIDC algorithm {name:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    algorithms.retain(|algorithm| DEFAULT_ALGORITHMS.contains(algorithm));
    if !advertised.is_empty() {
        let advertised = advertised
            .iter()
            .filter_map(|name| Algorithm::from_str(name).ok())
            .collect::<Vec<_>>();
        algorithms.retain(|algorithm| advertised.contains(algorithm));
    }
    if algorithms.is_empty() {
        bail!("OIDC provider has no mutually supported asymmetric signing algorithm");
    }
    Ok(algorithms)
}

pub(crate) fn unverified_issuer(token: &str) -> anyhow::Result<String> {
    let mut parts = token.split('.');
    let _header = parts.next().context("JWT is missing header")?;
    let payload = parts.next().context("JWT is missing payload")?;
    let _signature = parts.next().context("JWT is missing signature")?;
    if parts.next().is_some() {
        bail!("JWT has too many segments");
    }
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .context("JWT is missing issuer")
}

const fn default_jwks_refresh_seconds() -> u64 {
    DEFAULT_JWKS_REFRESH_SECONDS
}

const fn default_clock_skew_seconds() -> u64 {
    DEFAULT_CLOCK_SKEW_SECONDS
}

pub(crate) fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

pub(crate) fn matches_namespace(pattern: &str, namespace: &str) -> bool {
    pattern == "*"
        || pattern == namespace
        || pattern.strip_suffix("/*").is_some_and(|prefix| {
            namespace.starts_with(prefix) && namespace.as_bytes().get(prefix.len()) == Some(&b'/')
        })
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

pub(crate) fn verify_jwt(
    token: &str,
    jwk: &Jwk,
    algorithm: Algorithm,
    config: &OidcProviderConfig,
) -> anyhow::Result<Value> {
    if jwk.common.key_algorithm.is_some_and(|key_algorithm| {
        Algorithm::from_str(&key_algorithm.to_string()).ok() != Some(algorithm)
    }) || jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| usage != &PublicKeyUse::Signature)
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        bail!("JWT signing key is not valid for this algorithm");
    }
    let key = DecodingKey::from_jwk(jwk).context("decode JWT signing key")?;
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&config.audiences);
    validation.set_issuer(&[&config.issuer]);
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    validation.validate_nbf = true;
    validation.leeway = config.clock_skew_seconds;
    Ok(decode::<Value>(token, &key, &validation)
        .context("validate JWT")?
        .claims)
}
