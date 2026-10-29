# mbx-cache on Cloudflare Workers

A Rust/WASM entrypoint for the mbx v1 cache protocol, backed by a private R2
bucket and D1. The native server remains independently buildable. Both targets
use `mbx-cache-protocol` and `src/model.rs` / `src/validation.rs` for action
schemas, canonical object validation, output trees, and diagnostic references.
They also share `src/auth_policy.rs` for grant rules and JWT validation; the
Worker uses the pure-Rust cryptography backend compiled to WASM.

## Security and hardening

The Worker combines access controls with bounded storage and validation work:

- **Namespace-scoped access.** Routes declare their access requirements,
  grants are scoped to namespaces, and authentication runs before cache lookups.
  R2 stays private; external responses prevent downstream shared caching.
- **Bounded resource use.** Request and byte budgets apply per principal, with
  tighter shared limits for anonymous readers. Payload sizes, batch counts,
  decompression, and action-tree traversal have explicit limits.
- **Verified publication.** Uploads must match their declared size and digest
  before metadata makes them visible. Duplicate uploads still prove possession
  without redundant R2 writes. Packs publish atomically after full verification;
  immutable results and manifest updates enforce concurrency rules.
- **Predictable database work.** Bulk lookups use full-key index searches driven
  by the requested keys. Retention uses indexed selectors and bounded batches;
  writes and repairs use primary-anchored D1 sessions.
- **Scoped maintenance.** Cleanup is opt-in, limited to Worker-owned prefixes,
  and uses a grace period before deleting unreferenced objects. Retention is
  disabled by default and has explicitly soft cache semantics.
- **Operational visibility.** The deployment template enables invocation logs
  and traces at full sampling, with telemetry for rate limits, D1 work, cache
  outcomes, and cleanup progress.

Deployment also requires hostname/WAF controls, appropriate OIDC trust rules,
private storage, and integrity checks for imported content. See
[Production rollout](#production-rollout) for those operator responsibilities.

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
python3 scripts/test_query_plans.py
```

The Node integration suite executes the compiled WASM in workerd through
Miniflare, using real local D1 SQL and R2 bindings. It needs permission to open
local sockets. It never accesses a Cloudflare account. Native server regression
checks remain the commands in the root README. The query-plan checks use the
actual Worker SQL and migrated SQLite schema; the integration suite also covers
pack replay/write counts, failed publication, and maximum-size stored action
batches.

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

Configure a custom hostname in the chosen Wrangler config. The template disables
`workers.dev` and preview URLs:

```json
{"routes": [{"pattern": "cache.example.com", "custom_domain": true}]}
```

Set `MBX_CACHE_TOKENS_JSON` as a Worker secret containing the same static token
grants as the native server, for example:

```json
[{"token":"replace-with-a-secret","read":["acme/*"],"write":["acme/project"]}]
```

```sh
npx wrangler secret put MBX_CACHE_TOKENS_JSON
openssl rand -hex 32 | npx wrangler secret put MBX_CACHE_PRINCIPAL_KEY
npx wrangler d1 migrations apply MBX_DB --remote
npm run deploy
```

Keep the R2 bucket private: downloads must pass protocol, authorization, and
namespace-membership checks in the Worker. Use a paid Workers plan for hashing,
D1 query capacity, and the configured CPU budget. The principal key supplies
stable, keyed hashes for rate-limit identities; keep it secret and preserve it
across deployments. Review [Production rollout](#production-rollout) before
switching clients.

## Protocol support and limits

The Worker supports BLAKE3 and SHA-256 blobs, streaming uploads/downloads,
missing queries, blob packs, immutable action results, batched result reads, and
manifest ETag compare-and-swap. Namespace membership is separate from globally
deduplicated content. Static tokens, OIDC, and optional anonymous read grants use
the same JSON configuration formats as the native server; anonymous writes are
not supported.

| Resource | Worker limit |
| --- | --- |
| Blob upload or aggregate pack payload | 64 MiB by default; `MBX_CACHE_MAX_BLOB_BYTES` |
| Members per batch or pack | 16, advertised in capabilities |
| Action-result or digest-list request JSON | 1 MiB |
| Aggregate action-batch result JSON | 16 MiB |
| Manifest or individual protocol object | 16 MiB |
| Protocol bodies read during action validation | 64 MiB total |
| Directory traversal | 4,096 directories, depth 128, 100,000 entries/references |
| Validation I/O | 500 D1 queries; frontiers up to 16 MiB with six concurrent R2 reads |

Clients must use the protocol media types and split requests at the advertised
limits. Existing large blobs remain readable individually even when they exceed
the upload limit, subject to read budgets. Clients should honor
`limits.max_blob_bytes` before reading or sending oversized uploads and avoid
publishing action results when prerequisite uploads fail.

`MBX_CACHE_MAX_BLOB_BYTES` accepts values from 1 through 4,294,967,295. Both
encoded and decoded uploads are bounded. Pack framing adds 8 bytes plus 41 bytes
per member; the configured payload limit, framing, and a 1 MiB safety margin must
fit `MBX_CACHE_WORKERS_REQUEST_LIMIT_BYTES` (default 100,000,000). Set that value
to the actual ingress limit for your deployment before raising upload limits.
Streaming does not bypass ingress limits; multi-request uploads and delegated
direct-to-R2 uploads are not implemented.

Individual blobs and packs accept identity or zstd encoding. Zstd decoding uses
a maximum 8 MiB history window and at most 1,024 concatenated/skippable frames
per request. Invalid checksums, truncated frames, excessive windows, and trailing
garbage are rejected. R2 stores decoded bytes; responses use identity encoding.
Protocol objects are buffered for schema validation and canonicalization, while
artifact bodies are streamed. Benchmark concurrent large manifests and trees
before relying on the full object-size limits in production.

`/v1/status` and `/v1/capabilities` are public. The native `/metrics` endpoint is
not implemented in this target.

## Edge cache and D1 read replication

The default gateway always authenticates and authorizes the request, then calls
the internal `CachedStore` entrypoint with the authorized namespace in
`ctx.props`. Workers Caching serves immutable blobs for 24 hours and action
results for one hour for individual GET/HEAD requests. A warm hit performs no D1
or R2 operation. Pack downloads and action batches use bounded bulk D1 lookups
and origin reads rather than the internal cache entrypoint. The gateway
normalizes paths, strips caller headers/query parameters from the internal
request, and sets
`Cache-Control: private, no-store` on the external response. Namespace isolation
does not depend on downstream caches honoring a custom header.

Only successful immutable reads are cacheable. Missing objects, errors, mutable
manifests, authorization, and writes always execute their handlers. A transient
cache-pipeline failure falls back to a direct read. Cross-version caching keeps
immutable data warm across deploys; change `MBX_CACHE_CACHE_EPOCH` (`v2` in the
deployment template) to abandon old entries when changing cache semantics.
Retention can remove an origin object before its cached copy expires. Large
objects exceeding Cloudflare's cacheable size limit still stream from R2.

The `entry.js` file is platform binding glue for the named entrypoint;
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
MBX_REMOTE_TOKEN=... node scripts/smoke-test.mjs \
  --url https://cache.example.com --namespace acme/project
```

The smoke test publishes small SHA-256/BLAKE3 fixtures and an 8 MiB zstd upload,
requires real cache hits, checks pack/batch reads, and checks authorization after
warming the cache. It uses the Node 24 development tools, not a Node Worker
runtime.

Also verify namespace and action isolation in both cache-warming orders and a
miss after changing only the trusted cache epoch. Miniflare cannot prove the
production cache contract. Use Cloudflare diagnostics for serving-region and
primary/replica routing fields that the Rust SDK does not expose.

## CI authentication with OIDC

Use the same `MBX_CACHE_OIDC_PROVIDERS_JSON` provider configuration as the
native server. For example, configure it as a Worker variable or secret:

```json
[{
  "issuer": "https://token.actions.githubusercontent.com",
  "audiences": ["https://cache.example.com"],
  "rules": [
    {
      "claims": {"repository": "acme/project", "repository_id": "456", "repository_owner_id": "123"},
      "read": ["acme/project"],
      "write": []
    },
    {
      "claims": {
        "repository": "acme/project",
        "repository_id": "456",
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

The example grants repository-scoped reads and protected-branch writes. Treat
pull-request write access as a separate trust decision: repository identity
claims alone do not establish that the PR source is trusted. Keep **Send write
tokens to workflows from pull requests** disabled unless that trust model is
intentional, and restrict workflow remote writes to trusted PR contexts. For
read-only PR access, omit write grants from any `pull_request` rule. See
[GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc) and
[workflow permission calculation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#how-permissions-are-calculated-for-a-workflow-job).

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
key set, and 16 KiB bearer tokens are accepted. Provider endpoints require HTTPS;
redirects are manual, same-origin, and limited to three hops within the same
response-size and time budgets. For local development only, a provider can set
`allow_insecure_loopback: true` to permit HTTP on localhost, 127.0.0.1, or ::1.
HTTPS endpoints cannot redirect to HTTP.

## Upload publication and retention

New content streams into a fresh private R2 key. A D1 transaction publishes the
verified object pointer and namespace membership only after R2 storage and
verification succeed. Duplicate single and pack uploads hash and drain every
body/frame to prove possession while reusing healthy objects. Concurrent
identical uploads retain one winning object; repeated members within a pack
reuse the already verified frame.

Packs publish all memberships in one transaction after the final framing check.
Parsing or verification failures attempt to remove only newly staged objects.
An uncertain D1 publication outcome preserves staged objects for reference-aware
orphan cleanup, since publication may have committed. Successful blob PUTs
always return 204, and pack receipts normalize successful members to `existing`,
without disclosing global creation status.

Identical action-result replays return 204 before dependency reads; conflicting
replays return 409. Tree validation detects cycles and enforces the longest path
through shared subgraphs. Manifest writes preflight ETags and check them again
atomically at publication; reads verify the canonical BLAKE3 hash.

Blob reads and pack members check actual R2 sizes. Stale pointers are repaired
against the primary using compare-and-swap. Pack downloads omit members found
missing or wrong-sized during preflight and return the healthy members; an
object disappearing after streaming starts still fails the stream. These size
checks do not establish the integrity of same-sized imported content; imports
need the reconciliation described below.

Cleanup is disabled by default. With `MBX_CACHE_CLEANUP_ENABLED=true`, the hourly
handler inspects up to 1,000 objects and deletes at most 200 unreferenced objects
under the Worker prefix, retaining a 24-hour grace period. A persistent cursor
and bulk reference checks bound each invocation. This reclaims failed uploads,
superseded manifests, and expired blobs without deleting reused object keys.

`MBX_CACHE_RETENTION_DAYS=0` disables expiration. A positive value removes up to
200 old blob records, 200 action results, and 200 manifests per invocation using
indexed selectors. Blob age is based on creation, not download recency. Results
can outlive referenced blobs; clients treat failed restores as misses.

Retention is **soft**: authorized cached blobs can remain available for up to
24 hours and cached action results for up to one hour after origin deletion.
Credential revocation still applies on every request. Hard deletion requires
cache purge or shared-cache disabling and separate acceptance testing.

## Importing PostgreSQL metadata repeatedly

`workers/scripts/migrate-postgres.py` exports a consistent, read-only snapshot
through SSH to the native host and inventories its existing R2 objects. The
source service's S3 credentials stay on that host. Blobs remain at their
original object keys; manifest bodies are uploaded under the separate
`<worker-prefix>-imports/manifests/...` prefix. A Rust planner validates protocol
records and generates bounded D1 SQL pages.
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
python3 workers/scripts/migrate-postgres.py \
  --host cache-host.example.com --database mbx_cache
# After inspecting the plan, export a fresh snapshot and apply it:
python3 workers/scripts/migrate-postgres.py \
  --host cache-host.example.com --database mbx_cache --apply
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
bucket. For example, keep native objects under `native/v1/` and new Worker
objects under `workers/v1/`. Missing-blob queries check R2 availability, and
verified uploads can replace expired D1 object pointers atomically.

## Production rollout

1. **Prepare storage and routing.** Keep R2 private, use a custom hostname, and
   leave `workers_dev` and `preview_urls` disabled. Enable D1 replication with
   `scripts/configure-d1.py`. Apply all migrations, including the query indexes;
   run `scripts/test_query_plans.py` and verify staging D1 plans and costs before
   enabling retention.
2. **Configure secrets and identity.** Store `MBX_CACHE_TOKENS_JSON` and
   `MBX_CACHE_PRINCIPAL_KEY` as Worker secrets. Use at least 32 random bytes for
   the principal key. Review OIDC claim rules and PR trust explicitly. Principal
   budgets span namespaces; OIDC identities use issuer plus subject, and
   anonymous readers share an aggregate budget.
3. **Tune application and edge budgets.** Review `MBX_LIMIT_*` bindings and use
   account-unique namespace IDs. Start with `MBX_CACHE_RATE_LIMIT_MODE=observe`
   in staging, then use `enforce` for deployment; `off` is for local development.
   Apply coarse per-IP WAF limits and an exact method/path allowlist to the
   custom hostname, including public endpoints and auth failures. OIDC network
   work precedes the principal limiter. Application limits are approximate and
   location-local; strict global accounting requires a serialized service.
4. **Reconcile imports before trusting metadata alone.** Verify imported CAS
   content cryptographically or document the trusted source's equivalent
   integrity guarantee. Remove unrelated writers and exclude live prefixes from
   lifecycle expiration. Only then set `MBX_CACHE_D1_PRESENCE_RECONCILED=true`
   to remove missing-query R2 HEADs. The default is false.
5. **Enable maintenance last.** Keep cleanup disabled and retention at zero
   through cutover. Import prefixes must stay outside the Worker-owned prefix;
   reconcile any older imports that placed keys inside it before enabling
   cleanup. Dry-run the rollout in staging and size the schedule for sustained
   object growth. At 1,000 objects inspected hourly, a 24-hour full scan supports
   at most 24,000 Worker-owned objects without a deletion backlog; target orphan
   lag within 48 hours at that capacity. Monitor counts, oldest deleted orphan
   age, and cursor continuation, and scale the scan budget before exceeding it.
   Imported prefixes need separate reconciliation and cleanup.
6. **Verify deployed behavior.** Run the authenticated smoke test and the cache
   isolation/epoch checks above. Monitor payload bytes, D1 rows and duration,
   rate-limit outcomes, and cleanup progress. Invocation logs and traces are
   enabled at `head_sampling_rate: 1.0` in the deployment template. Avoid logging
   bearer tokens, claims, namespaces, or object keys in custom telemetry.

The template supplies these initial per-minute budgets:

| Request class | Budget |
| --- | --- |
| Reads | 600 per principal |
| Writes | 60 per principal |
| Batch/missing queries | 30 per principal |
| Packs, action validations, large reads | 10 per principal for each class |
| Anonymous requests | 20 shared |
| Reserved payload bytes | 1 GiB per principal; 64 MiB shared for anonymous traffic |

Byte budgets reserve conservative bounds in 16 MiB units before storage work;
failed requests remain charged. Pack downloads reserve the validated requested
artifact payload, with framing and control overhead bounded by request limits.
Empty packs reserve no payload units, and a 64 MiB pack payload fits the default
anonymous allowance. Tune these ceilings against actual traffic and observed
costs; they are not global accounting guarantees.
