//! Offline, deterministic PostgreSQL -> D1/R2 import planner. No credentials or writes to production.
use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use mbx_cache_protocol::{ActionResult, Digest, TaskActionManifest, canonical_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    snapshot: PathBuf,
    #[arg(long)]
    inventory: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value = "workers/v1")]
    worker_prefix: String,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record {
    Snapshot {
        source: String,
        snapshot_at: i64,
    },
    Blob {
        namespace: String,
        digest: Digest,
        created_at: i64,
    },
    Action {
        namespace: String,
        digest: Digest,
        result: ActionResult,
        created_at: i64,
    },
    Manifest {
        namespace: String,
        digest: Digest,
        etag: String,
        manifest: TaskActionManifest,
        updated_at: i64,
    },
    End,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Inventory {
    #[serde(rename = "inventory")]
    Header { bucket: String, prefix: String },
    Object {
        key: String,
        size: u64,
        created_at: i64,
    },
    #[serde(rename = "inventory_end")]
    End { pages: usize },
}
#[derive(Default, Serialize)]
struct Counts {
    memberships: usize,
    unique_blobs: usize,
    actions: usize,
    manifests: usize,
    missing_blobs: usize,
    skipped_actions: usize,
}
#[derive(Serialize)]
struct ManifestFile {
    key: String,
    file: String,
}
#[derive(Serialize)]
struct Plan {
    source: String,
    snapshot_at: i64,
    bucket: String,
    counts: Counts,
    sql_files: Vec<String>,
    manifests: Vec<ManifestFile>,
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
fn rows<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<Vec<T>> {
    BufReader::new(File::open(path)?)
        .lines()
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str(&line?)
                .with_context(|| format!("{} line {}", path.display(), i + 1))
        })
        .collect()
}
struct Sql {
    directory: PathBuf,
    files: Vec<String>,
    current: Option<File>,
    size: usize,
}
impl Sql {
    fn new(directory: &Path) -> Self {
        Self {
            directory: directory.into(),
            files: Vec::new(),
            current: None,
            size: 0,
        }
    }
    fn statement(&mut self, sql: &str) -> Result<()> {
        ensure!(sql.len() < 100_000, "SQL statement exceeds D1's limit");
        if self.current.is_none() || self.size + sql.len() > 4 * 1024 * 1024 {
            let name = format!("{:04}.sql", self.files.len());
            self.current = Some(File::create(self.directory.join(&name))?);
            self.files.push(name);
            self.size = 0;
        }
        writeln!(self.current.as_mut().unwrap(), "{sql};")?;
        self.size += sql.len() + 2;
        Ok(())
    }
    fn inserts(&mut self, prefix: &str, values: &[String], suffix: &str) -> Result<()> {
        let mut statement = prefix.to_owned();
        let mut count = 0;
        for row in values {
            if statement.len() + row.len() + suffix.len() > 60_000 && count > 0 {
                self.statement(&(statement + suffix))?;
                statement = prefix.to_owned();
                count = 0;
            }
            if count > 0 {
                statement.push(',');
            }
            statement.push_str(row);
            count += 1;
        }
        if count > 0 {
            self.statement(&(statement + suffix))?;
        }
        Ok(())
    }
}
fn plan(args: &Args) -> Result<Plan> {
    ensure!(
        !args.worker_prefix.trim_matches('/').is_empty(),
        "worker prefix must not be empty"
    );
    fs::create_dir_all(&args.output)?;
    let inventory = rows::<Inventory>(&args.inventory)?;
    ensure!(
        matches!(inventory.last(), Some(Inventory::End { .. })),
        "incomplete R2 inventory"
    );
    let mut objects = BTreeMap::new();
    let mut bucket = None;
    let mut prefix = None;
    for row in inventory {
        match row {
            Inventory::Header {
                bucket: b,
                prefix: p,
            } => {
                ensure!(bucket.is_none(), "duplicate inventory header");
                bucket = Some(b);
                prefix = Some(p);
            }
            Inventory::Object {
                key,
                size,
                created_at,
            } => {
                objects.insert(key, (size, created_at));
            }
            Inventory::End { pages } => ensure!(pages > 0, "inventory has no pages"),
        }
    }
    let prefix = prefix.context("missing inventory header")?;
    let worker_prefix = format!("{}/", args.worker_prefix.trim_matches('/'));
    ensure!(
        !prefix.starts_with(&worker_prefix) && !worker_prefix.starts_with(&prefix),
        "source and Worker object prefixes must not overlap"
    );
    let records = rows::<Record>(&args.snapshot)?;
    ensure!(
        matches!(records.last(), Some(Record::End)),
        "incomplete PostgreSQL snapshot"
    );
    let mut header = None;
    let mut blobs = BTreeMap::<Digest, Vec<(String, i64)>>::new();
    let mut actions = Vec::new();
    let mut manifests = Vec::new();
    for record in records {
        match record {
            Record::Snapshot {
                source,
                snapshot_at,
            } => {
                ensure!(header.is_none(), "duplicate snapshot header");
                header = Some((source, snapshot_at));
            }
            Record::Blob {
                namespace,
                digest,
                created_at,
            } => {
                digest
                    .validate()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                blobs
                    .entry(digest)
                    .or_default()
                    .push((namespace, created_at));
            }
            Record::Action {
                namespace,
                digest,
                result,
                created_at,
            } => actions.push((namespace, digest, result, created_at)),
            Record::Manifest {
                namespace,
                digest,
                etag,
                manifest,
                updated_at,
            } => manifests.push((namespace, digest, etag, manifest, updated_at)),
            Record::End => {}
        }
    }
    let (source, snapshot_at) = header.context("missing snapshot header")?;
    let mut counts = Counts::default();
    let mut sql = Sql::new(&args.output);
    let mut object_rows = Vec::new();
    let mut memberships = Vec::new();
    let mut available = BTreeSet::new();
    for (digest, holders) in blobs {
        let object_key = format!("{}{}", prefix, digest.key());
        if let Some(&(size, created_at)) = objects
            .get(&object_key)
            .filter(|(size, _)| *size == digest.size)
        {
            let _ = size;
            object_rows.push(format!(
                "({},{},{})",
                quote(&digest.key()),
                quote(&object_key),
                created_at
            ));
            counts.unique_blobs += 1;
            for (namespace, created_at) in holders {
                available.insert((namespace.clone(), digest.clone()));
                memberships.push(format!(
                    "({},{},{})",
                    quote(&namespace),
                    quote(&digest.key()),
                    created_at
                ));
                counts.memberships += 1;
            }
        } else {
            counts.missing_blobs += 1;
        }
    }
    sql.inserts(
        "INSERT INTO blob_objects(blob_key,object_key,created_at) VALUES ",
        &object_rows,
        " ON CONFLICT DO NOTHING",
    )?;
    sql.inserts(
        "INSERT INTO namespace_blobs(namespace,blob_key,created_at) VALUES ",
        &memberships,
        " ON CONFLICT DO NOTHING",
    )?;
    let mut action_rows = Vec::new();
    for (namespace, digest, result, created_at) in actions {
        digest
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        ensure!(
            digest == result.action && result.version == 1,
            "invalid source action result"
        );
        let references = std::iter::once(&result.action)
            .chain(result.metadata.iter())
            .chain(result.output_root.iter());
        if references
            .into_iter()
            .any(|d| !available.contains(&(namespace.clone(), d.clone())))
        {
            counts.skipped_actions += 1;
            continue;
        }
        let body = serde_json::to_string(&result)?;
        action_rows.push(format!(
            "({},{},{},{})",
            quote(&namespace),
            quote(&digest.key()),
            quote(&body),
            created_at
        ));
        counts.actions += 1;
    }
    sql.inserts(
        "INSERT INTO action_results(namespace,action_key,result,created_at) VALUES ",
        &action_rows,
        " ON CONFLICT DO NOTHING",
    )?;
    // Log immutable conflicts, preserving the target's result. JSON is serialized through the same Rust type as the Worker.
    // Batch conflict detection with source rows instead of one D1 request per action.
    for group in action_rows.chunks(40) {
        let values = group.join(",");
        sql.statement(&format!("WITH incoming(namespace,action_key,result,created_at) AS (VALUES {values}) INSERT INTO postgres_import_conflicts(source,kind,namespace,action_key,source_value,target_value) SELECT {},'action',i.namespace,i.action_key,i.result,a.result FROM incoming i JOIN action_results a ON a.namespace=i.namespace AND a.action_key=i.action_key WHERE a.result!=i.result ON CONFLICT(source,kind,namespace,action_key) DO UPDATE SET source_value=excluded.source_value,target_value=excluded.target_value",quote(&source)))?;
    }
    let mut files = Vec::new();
    for (namespace, digest, etag, manifest, updated_at) in manifests {
        ensure!(
            manifest.validate() && manifest.selector_digest() == digest,
            "invalid source manifest selector"
        );
        let bytes = canonical_json(&manifest)?;
        ensure!(
            blake3::hash(&bytes).to_hex().as_str() == etag,
            "source manifest ETag is not canonical BLAKE3"
        );
        let name = format!("manifest-{}.json", files.len());
        fs::write(args.output.join(&name), bytes)?;
        let key = format!(
            "{}-imports/manifests/{}/{}",
            args.worker_prefix.trim_matches('/'),
            blake3::hash(namespace.as_bytes()).to_hex(),
            etag
        );
        files.push(ManifestFile {
            key: key.clone(),
            file: name,
        });
        let n = quote(&namespace);
        let k = quote(&digest.key());
        let e = quote(&etag);
        let src = quote(&source);
        let epoch = updated_at / 1_000_000;
        sql.statement(&format!("INSERT INTO action_manifests(namespace,action_key,etag,object_key,updated_at) VALUES ({n},{k},{e},{},{epoch}) ON CONFLICT(namespace,action_key) DO UPDATE SET etag=excluded.etag,object_key=excluded.object_key,updated_at=excluded.updated_at WHERE EXISTS (SELECT 1 FROM postgres_manifest_imports p WHERE p.source={src} AND p.namespace={n} AND p.action_key={k} AND p.imported_etag=action_manifests.etag AND p.source_updated_at<{updated_at})",quote(&key)))?;
        sql.statement(&format!("INSERT INTO postgres_manifest_imports(source,namespace,action_key,source_updated_at,imported_etag) SELECT {src},{n},{k},{updated_at},{e} WHERE EXISTS (SELECT 1 FROM action_manifests WHERE namespace={n} AND action_key={k} AND etag={e}) ON CONFLICT(source,namespace,action_key) DO UPDATE SET source_updated_at=excluded.source_updated_at,imported_etag=excluded.imported_etag WHERE postgres_manifest_imports.source_updated_at<excluded.source_updated_at"))?;
        sql.statement(&format!("INSERT INTO postgres_import_conflicts(source,kind,namespace,action_key,source_value,target_value) SELECT {src},'manifest',{n},{k},{e},etag FROM action_manifests WHERE namespace={n} AND action_key={k} AND etag!={e} ON CONFLICT(source,kind,namespace,action_key) DO UPDATE SET source_value=excluded.source_value,target_value=excluded.target_value"))?;
        sql.statement(&format!("DELETE FROM postgres_import_conflicts WHERE source={src} AND kind='manifest' AND namespace={n} AND action_key={k} AND EXISTS (SELECT 1 FROM action_manifests WHERE namespace={n} AND action_key={k} AND etag={e})"))?;
        counts.manifests += 1;
    }
    // Manifest statements are deliberately not transactional with R2. Bodies upload first; pointers publish afterward.
    Ok(Plan {
        source,
        snapshot_at,
        bucket: bucket.context("missing bucket")?,
        counts,
        sql_files: sql.files,
        manifests: files,
    })
}
fn main() -> Result<()> {
    let args = Args::parse();
    if args.output.join("plan.json").exists() {
        bail!("output already contains a plan; use a fresh directory");
    }
    let plan = plan(&args)?;
    fs::write(
        args.output.join("plan.json"),
        serde_json::to_vec_pretty(&plan)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&plan.counts)?);
    Ok(())
}
