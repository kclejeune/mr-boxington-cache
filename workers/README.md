# mbx-cache on Cloudflare Workers

A Rust/WASM entrypoint for the mbx v1 cache protocol, backed by a private R2
bucket and D1. The native server remains independently buildable. Both targets
use `mbx-cache-protocol` and `src/model.rs` / `src/validation.rs` for action
schemas, canonical object validation, output trees, and diagnostic references.
They also share `src/auth_policy.rs` for grant rules and JWT validation; the
Worker uses the pure-Rust cryptography backend compiled to WASM.

## Local development

Install Node.js 24+, Rust with the WASM target, and the matching Worker builder:

```sh
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.8.7 --locked
cd workers
npm ci
cp .dev.vars.example .dev.vars
npx wrangler d1 migrations apply MBX_DB --local
npm run dev
```

Wrangler builds the Rust Worker and serves it on localhost:8787 with local D1
and R2. The example token permits only the `default` namespace. Configure mbx:

```toml
[remote]
url = "http://localhost:8787"
namespace = "default"
mode = "read-write"
```

Set `MBX_REMOTE_TOKEN=development-token` in the client environment.

## Checks

From this directory:

```sh
cargo fmt --check
cargo clippy --target wasm32-unknown-unknown -- -D warnings
npm run build
npm test
```

The Node integration suite executes the compiled WASM in workerd through
Miniflare, using real local D1 SQL and R2 bindings. It needs permission to open
local sockets. It never accesses a Cloudflare account. Native server regression
checks remain the commands in the root README.

## Deploying your own instance

Use a dedicated bucket and database. These commands create remote resources:

```sh
npx wrangler d1 create mbx-cache
npx wrangler r2 bucket create mbx-cache
```

Put the returned database ID in `wrangler.jsonc`, or copy that file to the
ignored `wrangler.local.jsonc` and use `--config wrangler.local.jsonc` with each
Wrangler command. Adjust the bucket name if necessary. The checked-in zero
UUID is a local development placeholder, not a deployable database ID.

Set `MBX_CACHE_TOKENS_JSON` as a Worker secret containing the same static token
grants as the native server, for example:

```json
[{"token":"replace-with-a-secret","read":["acme/*"],"write":["acme/project"]}]
```

```sh
npx wrangler secret put MBX_CACHE_TOKENS_JSON
npx wrangler d1 migrations apply MBX_DB --remote
npm run deploy
```

Keep the R2 bucket private: downloads must pass protocol, authorization, and
namespace-membership checks in the Worker. Use a paid Workers plan for hashing,
D1 query capacity, and the configured CPU budget.

## Implemented behavior and limits

- BLAKE3 and SHA-256 blobs, verified size and hash, immutable writes, and
  namespace membership independent of globally deduplicated blob content.
- Streaming individual uploads and downloads, missing queries, upload/download
  blob packs, immutable action results, action batches, and manifest ETag CAS.
- Static bearer grants (`MBX_CACHE_TOKENS_JSON`), OIDC providers
  (`MBX_CACHE_OIDC_PROVIDERS_JSON`), and optional public read grants
  (`MBX_CACHE_ANONYMOUS_READ_NAMESPACES_JSON`); no anonymous writes.
- Identity and zstd uploads for individual blobs and blob packs, negotiated
  through capabilities. Zstd decoding uses pure Rust with a maximum 8 MiB
  history window, one block at a time. Concatenated and skippable frames are
  supported, with at most 1024 frames per request. Both encoded and decoded
  byte limits are enforced; invalid checksums, truncated frames, excessive
  windows, and trailing garbage are rejected. R2 stores decoded bytes and
  responses currently use identity encoding.
- The default blob and aggregate pack payload limit is 64 MiB, configurable with
  `MBX_CACHE_MAX_BLOB_BYTES` (1 through 4,294,967,295). Keep it below the request
  limit for your Cloudflare zone, allowing for pack framing. Streaming does not
  bypass ingress limits. There is no multi-request upload or content chunking.
- Batches advertise at most 512 members. D1 JSON-list joins avoid the bound
  parameter limit. Validation batches file memberships, and caps its D1 work
  at 500 queries per action commit; larger actions return 422 without publication.
- JSON requests are bounded at 2 MiB; manifests and individual protocol objects
  at 16 MiB. Large protocol objects are buffered for schema validation and
  canonicalization; artifact bodies are streamed. Benchmark concurrent large
  manifests/trees before using the full object-size limits in production.
- Manifest bodies live in R2; D1 stores the current pointer and canonical BLAKE3
  ETag. Reads and commit validation use primary-anchored D1 sessions.
- `/v1/status` and `/v1/capabilities` are public. Workers observability records
  invocations and internal failures; the native `/metrics` endpoint is not
  implemented in this target.

## CI authentication with OIDC

Use the same `MBX_CACHE_OIDC_PROVIDERS_JSON` provider configuration as the
native server. For example, configure it as a Worker variable or secret:

```json
[{
  "issuer": "https://token.actions.githubusercontent.com",
  "audiences": ["https://cache.example.com"],
  "rules": [
    {
      "claims": {"repository": "acme/project", "repository_owner_id": "123"},
      "read": ["acme/project"],
      "write": []
    },
    {
      "claims": {
        "repository": "acme/project",
        "repository_owner_id": "123",
        "event_name": "push",
        "ref_type": "branch",
        "ref": "refs/heads/main"
      },
      "read": ["acme/project"],
      "write": ["acme/project"]
    }
  ]
}]
```

Set `MBX_REMOTE_OIDC_AUDIENCE=https://cache.example.com` for mbx in a GitHub
Actions job with `id-token: write`. Static tokens and OIDC can coexist. Pin
stable numeric identity claims alongside repository names, and restrict write
grants to an exact protected branch and push event.

Providers require audiences and nonempty claim-constrained rules. Optional
`discovery_uri`, `jwks_uri`, `algorithms`, `jwks_refresh_seconds` (default 300),
and `clock_skew_seconds` (default 60) retain the native configuration semantics.
The Worker supports RS256/384/512, PS256/384/512, ES256/384, and EdDSA (Ed25519).
It checks signatures, key usage/algorithm restrictions, issuer, audience, expiry,
subject, and not-before before evaluating grants. Symmetric algorithms and
unsupported critical JWT headers are rejected.

Discovery and keys load lazily, with three initial attempts. An isolate caches
owned Rust key data, coalesces concurrent loads, refreshes stale or unknown keys,
and imposes a 30-second refresh cooldown. A failed refresh may retain an
already-known key; an unknown key never authenticates that way. Fetches have a
10-second deadline and 1 MiB response bound. Up to 16 providers, 128 keys per
key set, and 16 KiB bearer tokens are accepted. Use HTTPS for provider endpoints.

## Upload publication and retention

Each upload streams into a fresh private R2 key. A D1 transaction publishes the
winning verified object pointer and namespace membership only after R2 and
verification succeed. Concurrent identical uploads retain one object. Invalid
uploads never gain visibility, and cleanup only deletes their own unique key.
D1 failures can leave unreachable objects, which scheduled cleanup reclaims.

The hourly scheduled handler processes bounded pages. `MBX_CACHE_RETENTION_DAYS`
defaults to `0` (no expiration). A positive value removes up to 200 old blobs,
200 old results, and 200 old manifests per invocation. Blob retention is based
on object creation, not download recency. A result referencing an expired blob
may remain until its own expiration; clients treat failed restores as misses.

The same handler lists up to 100 R2 objects per invocation, with its cursor in
D1. Objects unreferenced by either blob metadata or a manifest pointer are
removed after a 24-hour grace period. This reclaims superseded manifests,
failed uploads, and expired blobs without racing active uploads or readers of
recent manifest versions. Cleanup throughput is deliberately bounded; tune the
schedule/page sizes for sustained workloads. Do not independently expire R2
objects with lifecycle rules: the current D1 deduplication pointers assume a
referenced object remains present until metadata retention removes it.
