//! Closed method/path authorization table. Unknown routes never trigger OIDC work.
use crate::{
    JSON_LIMIT, MANIFEST_LIMIT, WORKER_BATCH_LIMIT,
    error::{Error, Result},
};
use worker::{Method, Request};
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Public,
    Read,
    Write,
}
#[derive(Clone, Copy, Debug)]
pub enum Route {
    Public,
    BlobRead,
    ActionRead,
    ManifestRead,
    Missing,
    PackRead,
    Batch,
    BlobWrite,
    ActionWrite,
    ManifestWrite,
    PackWrite,
}
impl Route {
    pub fn access(self) -> Access {
        match self {
            Self::Public => Access::Public,
            Self::BlobWrite | Self::ActionWrite | Self::ManifestWrite | Self::PackWrite => {
                Access::Write
            }
            _ => Access::Read,
        }
    }
    pub fn budget(self, path: &str) -> &'static str {
        match self {
            Self::PackRead | Self::PackWrite => "PACK",
            Self::Batch | Self::Missing => "BATCH",
            Self::ActionWrite => "VALIDATION",
            Self::BlobWrite | Self::ManifestWrite => "WRITE",
            Self::BlobRead
                if path
                    .rsplit('/')
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_some_and(|n| n > 512_000_000) =>
            {
                "LARGE"
            }
            _ => "READ",
        }
    }
}
pub fn classify(method: &Method, path: &str) -> Result<Route> {
    use Route::*;
    let route = match (method, path) {
        (Method::Get, "/v1/status" | "/v1/capabilities") => Public,
        (Method::Post, "/v1/blobs:missing") => Missing,
        (Method::Post, "/v1/blobs:pack") => PackRead,
        (Method::Post, "/v1/blobs:pack-upload") => PackWrite,
        (Method::Post, "/v1/action-results:batch") => Batch,
        _ => {
            let parts: Vec<_> = path.split('/').collect();
            if parts.len() != 6 || parts[1] != "v1" {
                return Err(Error::new(404, "not found"));
            }
            let route = match (method, parts[2]) {
                (Method::Get | Method::Head, "blobs") => BlobRead,
                (Method::Get | Method::Head, "action-results") => ActionRead,
                (Method::Get, "action-manifests") => ManifestRead,
                (Method::Put, "blobs") => BlobWrite,
                (Method::Put, "action-results") => ActionWrite,
                (Method::Put, "action-manifests") => ManifestWrite,
                _ => return Err(Error::new(404, "not found")),
            };
            let digest = crate::parse_digest(parts[3], parts[4], parts[5], parts[2] != "blobs")?;
            if matches!(route, BlobWrite) && digest.size > u32::MAX as u64 {
                return Err(Error::new(
                    413,
                    "blob exceeds Worker upload streaming limit",
                ));
            }
            route
        }
    };
    Ok(route)
}
pub fn content_length(request: &Request, limit: u64) -> Result<()> {
    if let Some(value) = request.headers().get("content-length")? {
        let length: u64 = value
            .parse()
            .map_err(|_| Error::new(400, "invalid Content-Length"))?;
        if length > limit {
            return Err(Error::new(413, "request body is too large"));
        }
    }
    Ok(())
}
pub fn validate_body(request: &Request, route: Route, blob_limit: u64) -> Result<()> {
    use Route::*;
    let (media, limit, compressed) = match route {
        BlobWrite => ("application/octet-stream", blob_limit, true),
        PackWrite => (
            mbx_cache_protocol::BLOB_PACK_MEDIA_TYPE,
            blob_limit + 8 + 41 * WORKER_BATCH_LIMIT as u64,
            true,
        ),
        ManifestWrite => (
            mbx_cache_protocol::TASK_ACTION_MANIFEST_MEDIA_TYPE,
            MANIFEST_LIMIT as u64,
            false,
        ),
        ActionWrite => (
            mbx_cache_protocol::ACTION_RESULT_MEDIA_TYPE,
            JSON_LIMIT as u64,
            false,
        ),
        Missing | PackRead | Batch => (
            mbx_cache_protocol::DIGEST_LIST_MEDIA_TYPE,
            JSON_LIMIT as u64,
            false,
        ),
        _ => return Ok(()),
    };
    let content_type = request.headers().get("content-type")?.unwrap_or_default();
    let content_type = content_type.split(';').next().unwrap_or("").trim();
    // Keep generic JSON compatibility, while recognizing the route's protocol type.
    let generic_json = matches!(route, ActionWrite | Missing | PackRead | Batch)
        && content_type == "application/json";
    if content_type != media && !generic_json {
        return Err(Error::new(415, "unsupported content type"));
    }
    content_length(request, limit)?;
    let encoding = request
        .headers()
        .get("content-encoding")?
        .unwrap_or_else(|| "identity".into());
    if encoding != "identity" && !(compressed && encoding == "zstd") {
        return Err(Error::new(415, "unsupported content encoding"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imported_blob_reads_do_not_have_the_upload_stream_size_limit() {
        let path = format!(
            "/v1/blobs/blake3/{}/{}",
            "a".repeat(64),
            u64::from(u32::MAX) + 1
        );
        for method in [Method::Get, Method::Head] {
            assert!(matches!(classify(&method, &path).unwrap(), Route::BlobRead));
        }
        assert_eq!(classify(&Method::Put, &path).unwrap_err().status, 413);
    }
    #[test]
    fn closed_routes() {
        for (path, access, methods) in [
            ("/v1/status", Access::Public, vec![Method::Get]),
            ("/v1/capabilities", Access::Public, vec![Method::Get]),
            ("/v1/blobs:missing", Access::Read, vec![Method::Post]),
            ("/v1/blobs:pack", Access::Read, vec![Method::Post]),
            ("/v1/action-results:batch", Access::Read, vec![Method::Post]),
            ("/v1/blobs:pack-upload", Access::Write, vec![Method::Post]),
        ] {
            for method in [
                Method::Get,
                Method::Head,
                Method::Post,
                Method::Put,
                Method::Delete,
                Method::Patch,
                Method::Options,
            ] {
                let result = classify(&method, path);
                if methods.contains(&method) {
                    assert_eq!(result.unwrap().access(), access);
                } else {
                    assert!(result.is_err());
                }
            }
        }
        for kind in ["blobs", "action-results", "action-manifests"] {
            let path = format!("/v1/{kind}/blake3/{}/0", "a".repeat(64));
            for method in [
                Method::Get,
                Method::Head,
                Method::Post,
                Method::Put,
                Method::Delete,
                Method::Patch,
                Method::Options,
            ] {
                let expected = match method {
                    Method::Get => Some(Access::Read),
                    Method::Head if kind != "action-manifests" => Some(Access::Read),
                    Method::Put => Some(Access::Write),
                    _ => None,
                };
                let actual = classify(&method, &path);
                if let Some(expected) = expected {
                    assert_eq!(actual.unwrap().access(), expected);
                } else {
                    assert!(actual.is_err());
                }
            }
        }
        assert!(classify(&Method::Post, "/v1/future").is_err());
    }
}
