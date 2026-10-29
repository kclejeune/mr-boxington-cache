//! Location-local approximate budgets, charged before storage/body work.
use crate::{
    auth::{Principal, setting},
    error::{Error, Result},
};
use worker::Env;
pub async fn check(
    env: &Env,
    principal: &Principal,
    class: &str,
    reserved_bytes: u64,
) -> Result<()> {
    let mode = setting(env, "MBX_CACHE_RATE_LIMIT_MODE", "enforce");
    if mode == "off" {
        return Ok(());
    }
    if mode != "enforce" && mode != "observe" {
        return Err(Error::internal("invalid rate limit mode"));
    }
    let binding = if principal.anonymous {
        "MBX_LIMIT_ANONYMOUS".to_owned()
    } else {
        format!("MBX_LIMIT_{class}")
    };
    let outcome = env
        .rate_limiter(&binding)?
        .limit(principal.key.clone())
        .await?;
    if !outcome.success {
        worker::console_warn!(
            "mbx.rate_limit class={} mode={}",
            if principal.anonymous {
                "ANONYMOUS"
            } else {
                class
            },
            mode
        );
        if mode == "enforce" {
            return Err(Error::new(429, "request budget exceeded"));
        }
    }
    check_bytes(env, principal, reserved_bytes).await
}

pub async fn check_bytes(env: &Env, principal: &Principal, reserved_bytes: u64) -> Result<()> {
    let mode = setting(env, "MBX_CACHE_RATE_LIMIT_MODE", "enforce");
    if mode == "off" {
        return Ok(());
    }
    if mode != "enforce" && mode != "observe" {
        return Err(Error::internal("invalid rate limit mode"));
    }
    // Reserve a conservative upper bound in 16 MiB units before payload/storage work.
    // Pack control JSON has its own bound and is parsed before reserving its payload.
    // Failed requests remain charged. This is an approximate local spending control.
    let binding = if principal.anonymous {
        "MBX_LIMIT_ANONYMOUS_BYTES"
    } else {
        "MBX_LIMIT_BYTES"
    };
    for _ in 0..reserved_bytes.div_ceil(16 * 1024 * 1024) {
        let outcome = env
            .rate_limiter(binding)?
            .limit(principal.key.clone())
            .await?;
        if !outcome.success {
            worker::console_warn!("mbx.rate_limit class=BYTES mode={}", mode);
            if mode == "enforce" {
                return Err(Error::new(429, "byte budget exceeded"));
            }
            break;
        }
    }
    Ok(())
}
