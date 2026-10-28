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
- Batches advertise at most 256 members. D1 JSON-list joins avoid the bound
  parameter limit. Validation batches file memberships, and caps its D1 work
  at 500 queries per action commit; larger actions return 422 without publication.
- JSON requests are bounded at 2 MiB; manifests and individual protocol objects
  at 16 MiB. Large protocol objects are buffered for schema validation and
  canonicalization; artifact bodies are streamed. Benchmark concurrent large
  manifests/trees before using the full object-size limits in production.
- Manifest bodies live in R2; D1 stores the current pointer and canonical BLAKE3
  ETag. Ordinary reads use replica-eligible sessions. Writes, commit validation,
  and manifest concurrency checks use primary-anchored sessions.
- `/v1/status` and `/v1/capabilities` are public. Workers observability records
  invocations and internal failures; the native `/metrics` endpoint is not
  implemented in this target.

## Edge cache and D1 read replication

The default gateway always authenticates and authorizes the request, then calls
the internal `CachedStore` entrypoint with the authorized namespace in
`ctx.props`. Workers Caching serves immutable blobs for 24 hours and action
results for one hour, including requests assembled into blob packs and action
batches. A warm hit performs no D1 or R2 operation. The gateway normalizes paths
and strips caller headers/query parameters from the internal request, and sets
`Cache-Control: private, no-store` on the external response. Namespace isolation
does not depend on downstream caches honoring a custom header.

Only successful immutable reads are cacheable. Missing objects, errors, mutable
manifests, authorization, and writes always execute their handlers. A transient
cache-pipeline failure falls back to a direct read. Cross-version caching keeps
immutable data warm across deploys; change `MBX_CACHE_CACHE_EPOCH` (default `v1`)
to abandon old entries when changing cache semantics. Retention can remove an
origin object before its cached copy expires. Large objects exceeding Cloudflare's
cacheable size limit still stream from R2.

The six-line `entry.js` file is platform binding glue for the named entrypoint;
both handlers and all storage/authentication logic execute in Rust/WASM. No
Node runtime or compatibility flag is needed. This follows Cloudflare's
[gateway caching pattern](https://developers.cloudflare.com/workers/cache/configuration/).

Enable D1 read replication once for each deployed database:

```sh
python3 scripts/configure-d1.py --config wrangler.local.jsonc
```

This uses the logged-in Wrangler account to set `read_replication.mode=auto`.
Cache misses, manifest reads and missing-blob queries use
`withSession("first-unconstrained")`; writes and commit validation use
`withSession("first-primary")`. A request's queries share a session, preserving
sequential consistency within that request. Replicas can briefly miss a write
from a previous request; no negative result is cached. Primary validation and
atomic D1 transactions protect publication and manifest CAS from replica lag.

Inspect `mbx-cache-edge-status` for the **internal** cache outcome; the external
gateway's `Cf-Cache-Status` describes a different entrypoint. Miniflare exercises
the Rust entrypoint binding but does not emulate production Workers Caching.
Verify actual edge hits after deployment with a write-enabled token:

```sh
MBX_REMOTE_TOKEN=... python3 scripts/smoke-test.py \
  --url https://your-worker.workers.dev --namespace acme/project
```

The smoke test publishes small unique SHA-256 fixtures, requires real cache
hits, checks pack/batch reads, and checks authorization after warming the cache.

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

When `MBX_CACHE_CLEANUP_ENABLED=true`, the hourly handler processes bounded
pages restricted to the Worker object prefix. `MBX_CACHE_RETENTION_DAYS`
defaults to `0` (no expiration). A positive value removes up to 200 old blobs,
200 old results, and 200 old manifests per invocation. Blob retention is based
on object creation, not download recency. A result referencing an expired blob
may remain until its own expiration; clients treat failed restores as misses.

The same handler lists up to 100 R2 objects per invocation, with its cursor in
D1. Objects unreferenced by either blob metadata or a manifest pointer are
removed after a 24-hour grace period. This reclaims superseded manifests,
failed uploads, and expired blobs without racing active uploads or readers of
recent manifest versions. Cleanup throughput is deliberately bounded; tune the
schedule/page sizes for sustained workloads. Keep any legacy R2 expiration rules scoped to the native prefix, and use the
Worker's metadata retention for new objects.

## Importing PostgreSQL metadata repeatedly

`workers/scripts/migrate-postgres.py` exports a consistent, read-only snapshot
through SSH to the native host and inventories its existing R2 objects. The
source service's S3 credentials stay on that host. Blobs remain at their
original object keys; only manifest bodies are uploaded to the Worker prefix.
A Rust planner validates protocol records and generates bounded D1 SQL pages.
The host needs passwordless sudo for `postgres`/`psql` and for reading the
running cache service's S3 environment. PostgreSQL is never modified.

Create an ignored **plain JSON** `wrangler.local.jsonc` instance config with
actual account/database IDs and the existing bucket. Set these variables:

```json
{
  "MBX_CACHE_R2_PREFIX": "workers/v1",
  "MBX_CACHE_CLEANUP_ENABLED": "false",
  "MBX_CACHE_RETENTION_DAYS": "0"
}
```

From the repository root:

```sh
cargo build --features migration --bin mbx-cache-migrate
python3 workers/scripts/migrate-postgres.py --host gateway --database mbx_cache
# After inspecting the plan, export a fresh snapshot and apply it:
python3 workers/scripts/migrate-postgres.py --host gateway --database mbx_cache --apply
```

Run the same command again to catch up before switching clients. Each run
retains its snapshot, object inventory, manifest files, and SQL plan in a private
`/tmp/mbx-postgres-import-*` directory. `--output` selects a directory;
`--snapshot` and `--inventory` reuse completed exports. `--source` overrides the
stable source ID (by default `HOST/DATABASE`). Do not change the source ID
between runs for the same PostgreSQL database. Finish one import before
starting the next; an interrupted application can be retried from the same
snapshot and inventory using a fresh output directory.

Imports are additive. Blob pointers, namespace memberships, and immutable
results use conflict-safe inserts; existing Worker object pointers win.
Conflicting immutable results are preserved in D1 and reported in
`postgres_import_conflicts`. Source rows whose required top-level objects are
missing from R2 are skipped. This is a snapshot catch-up tool, not a deletion
replicator or a complete nested-tree integrity audit.

Manifest imports track the source microsecond timestamp and last imported ETag
in `postgres_manifest_imports`. A newer PostgreSQL manifest replaces the D1
manifest only if its ETag still matches the last imported version. Worker edits
win and are recorded as conflicts. Replaying an older snapshot cannot roll
back a newer import. Review conflicts at cutover; they may contain predictions
that clients should merge. The original server keeps running and client routing
is unchanged throughout import.

### Shared bucket and retention

New objects use `MBX_CACHE_R2_PREFIX` (default `workers/v1`). The prefix must not
overlap the native blob prefix. Cleanup is **disabled by default**, even if a
retention period is configured. Set `MBX_CACHE_CLEANUP_ENABLED=true` only when
ready. Orphan scans always stay inside the Worker prefix; imported native
objects are never deleted by that sweep. Its separate cursor prevents an old
whole-bucket cursor from changing the scan's scope.

A bucket-wide expiry rule would also expire Worker uploads. Scope the native
server's lifecycle rule to its existing prefix before deploying into a shared
bucket. For the gateway instance, that is `mbx-cache/v1/`, while new Worker
objects live under `workers/v1/`. Missing-blob queries check R2 availability,
and verified uploads can replace expired D1 object pointers atomically.

The batch limit is 256 to leave room for pointer lookups and repairs within
D1's per-invocation query limit. Existing large blobs remain downloadable even
when larger than the configured upload limit. Choose an appropriate decoded
upload limit for the instance; encoded uploads still face Cloudflare ingress
limits.
