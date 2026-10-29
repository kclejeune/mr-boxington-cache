//! Validation shared by the native server and the Cloudflare Worker.
use crate::model::{
    ActionResult, BUILD_SCRIPT_ACTION_SCHEMAS, Digest, Directory, RustcAction, RustcMetadata,
    TaskAction, TaskMetadata,
};
use std::{collections::HashSet, future::Future};

pub(crate) trait ValidationStore: Sync {
    fn visible(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> impl Future<Output = Result<Vec<Digest>, ValidationError>> + Send;
    fn read_visible(
        &self,
        namespace: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ValidationError>> + Send {
        async move {
            if !self
                .visible(namespace, std::slice::from_ref(digest))
                .await?
                .contains(digest)
            {
                return Ok(None);
            }
            self.read(digest).await
        }
    }
    fn read_visible_many(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> impl Future<Output = Result<Vec<Option<Vec<u8>>>, ValidationError>> + Send {
        async move {
            let mut objects = Vec::new();
            for digest in digests {
                objects.push(self.read_visible(namespace, digest).await?);
            }
            Ok(objects)
        }
    }
    /// Read one bounded protocol object, never an arbitrary artifact.
    fn read(
        &self,
        _digest: &Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ValidationError>> + Send {
        async { Err(ValidationError::internal("unscoped reads unsupported")) }
    }
}

#[derive(Debug)]
pub(crate) struct ValidationError {
    pub status: u16,
    pub message: String,
}
impl ValidationError {
    pub fn bad_request(message: impl ToString) -> Self {
        Self {
            status: 400,
            message: message.to_string(),
        }
    }
    pub fn unprocessable(message: impl ToString) -> Self {
        Self {
            status: 422,
            message: message.to_string(),
        }
    }
    pub fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: 500,
            message: error.to_string(),
        }
    }
}
fn validate_digest(digest: &Digest) -> Result<(), ValidationError> {
    digest
        .validate()
        .map_err(|_| ValidationError::bad_request("invalid digest"))
}

pub(crate) async fn validate_tree(
    state: &impl ValidationStore,
    namespace: &str,
    root: &Digest,
) -> Result<(), ValidationError> {
    use std::collections::{HashMap, VecDeque};
    let mut pending = VecDeque::from([root.clone()]);
    let mut discovered = HashSet::from([root.clone()]);
    let mut references = HashSet::new();
    let mut graph = HashMap::<Digest, Vec<Digest>>::new();
    let mut protocol_bytes = 0u64;
    let mut entries = 0usize;
    while !pending.is_empty() {
        // A frontier has at most 16 MiB of bodies, even with six concurrent R2 reads.
        let mut frontier = Vec::new();
        let mut bytes = 0u64;
        while let Some(digest) = pending.front() {
            validate_digest(digest)?;
            if digest.size > 16 * 1024 * 1024 {
                return Err(ValidationError::unprocessable(
                    "directory object is too large",
                ));
            }
            if frontier.len() == 16 || bytes + digest.size > 16 * 1024 * 1024 {
                break;
            }
            bytes += digest.size;
            frontier.push(pending.pop_front().unwrap());
        }
        protocol_bytes = protocol_bytes.saturating_add(bytes);
        if protocol_bytes > 64 * 1024 * 1024 {
            return Err(ValidationError::unprocessable(
                "directory graph exceeds byte budget",
            ));
        }
        let objects = state.read_visible_many(namespace, &frontier).await?;
        if objects.len() != frontier.len() {
            return Err(ValidationError::internal("invalid directory read result"));
        }
        let mut files = Vec::new();
        for (digest, body) in frontier.into_iter().zip(objects) {
            let body =
                body.ok_or_else(|| ValidationError::unprocessable("directory object is missing"))?;
            let directory: Directory = serde_json::from_slice(&body)
                .map_err(|_| ValidationError::unprocessable("directory object is invalid"))?;
            if serde_json::to_vec(&directory).map_err(ValidationError::internal)? != body {
                return Err(ValidationError::unprocessable(
                    "directory object is not canonical JSON",
                ));
            }
            if directory.version != 1 {
                return Err(ValidationError::unprocessable(
                    "unsupported directory object version",
                ));
            }
            entries = entries
                .saturating_add(directory.files.len())
                .saturating_add(directory.directories.len())
                .saturating_add(directory.symlinks.len());
            if entries > 100_000 {
                return Err(ValidationError::unprocessable(
                    "directory graph exceeds entry budget",
                ));
            }
            validate_directory_entries(&directory)?;
            let children: Vec<_> = directory
                .directories
                .into_iter()
                .map(|node| node.digest)
                .collect();
            let current_files: Vec<_> = directory
                .files
                .into_iter()
                .map(|node| node.digest)
                .collect();
            for reference in children.iter().chain(&current_files) {
                validate_digest(reference)?;
                references.insert(reference.clone());
            }
            if references.len() > 100_000 {
                return Err(ValidationError::unprocessable(
                    "directory graph exceeds reference budget",
                ));
            }
            for child in &children {
                if discovered.insert(child.clone()) {
                    pending.push_back(child.clone());
                }
            }
            if discovered.len() > 4096 {
                return Err(ValidationError::unprocessable(
                    "directory graph is too large",
                ));
            }
            files.extend(current_files);
            graph.insert(digest, children);
        }
        let visible: HashSet<_> = state
            .visible(namespace, &files)
            .await?
            .into_iter()
            .collect();
        if files.iter().any(|digest| !visible.contains(digest)) {
            return Err(ValidationError::unprocessable("file blob is missing"));
        }
    }
    // Topological processing detects cycles and the longest path, including DAGs
    // whose shortest path would hide an over-depth branch during BFS.
    let mut incoming = HashMap::<Digest, usize>::new();
    for (parent, children) in &graph {
        incoming.entry(parent.clone()).or_default();
        for child in children {
            *incoming.entry(child.clone()).or_default() += 1;
        }
    }
    let mut ready: VecDeque<_> = incoming
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(key, _)| key.clone())
        .collect();
    let mut depth = HashMap::from([(root.clone(), 1usize)]);
    let mut visited = 0;
    while let Some(parent) = ready.pop_front() {
        visited += 1;
        let current = *depth.get(&parent).unwrap_or(&1);
        if current > 128 {
            return Err(ValidationError::unprocessable(
                "directory graph is too deep",
            ));
        }
        for child in &graph[&parent] {
            let child_depth = depth.entry(child.clone()).or_default();
            *child_depth = (*child_depth).max(current + 1);
            let count = incoming.get_mut(child).unwrap();
            *count -= 1;
            if *count == 0 {
                ready.push_back(child.clone());
            }
        }
    }
    if visited != graph.len() {
        return Err(ValidationError::unprocessable(
            "directory graph contains a cycle",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionKind {
    BuildScript,
    Cc,
    Rustc,
    Task,
}

pub(crate) fn validate_action_result_shape(
    result: &ActionResult,
    action_kind: ActionKind,
) -> Result<(), ValidationError> {
    if action_kind != ActionKind::Task
        && (result.metadata.is_none() || result.output_root.is_none())
    {
        return Err(ValidationError::unprocessable(
            "compiler action results require metadata and an output root",
        ));
    }
    Ok(())
}

pub(crate) async fn validate_action_descriptor(
    state: &impl ValidationStore,
    namespace: &str,
    digest: &Digest,
) -> Result<ActionKind, ValidationError> {
    let value = read_canonical_object(state, namespace, digest, "action descriptor").await?;
    let object = value
        .as_object()
        .ok_or_else(|| ValidationError::unprocessable("action descriptor must be a JSON object"))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ValidationError::unprocessable("action descriptor kind is required"))?
        .to_owned();
    let version = object
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ValidationError::unprocessable("action descriptor version is required"))?;
    match kind.as_str() {
        "build-script" => validate_build_script_action(value, version),
        "cc" => validate_cc_action(value, version),
        "task" => validate_task_action(value, version),
        "rustc" => validate_rustc_action(value, version),
        _ => Err(ValidationError::unprocessable(format!(
            "unsupported action kind {kind:?}"
        ))),
    }
}

fn validate_build_script_action(
    value: serde_json::Value,
    version: u64,
) -> Result<ActionKind, ValidationError> {
    if !u8::try_from(version).is_ok_and(|version| BUILD_SCRIPT_ACTION_SCHEMAS.contains(&version)) {
        return Err(ValidationError::unprocessable(format!(
            "unsupported build-script action schema {version}"
        )));
    }
    // Schema 3 added archive_timestamps, which mbx always serializes, as null
    // when no archive policy applies.
    let has_archive_timestamps = value
        .as_object()
        .is_some_and(|object| object.contains_key("archive_timestamps"));
    if has_archive_timestamps != (version >= 3) {
        return Err(ValidationError::unprocessable(
            "invalid build-script action archive_timestamps field",
        ));
    }
    let action =
        serde_json::from_value::<crate::model::BuildScriptAction>(value).map_err(|error| {
            ValidationError::unprocessable(format!("invalid build-script action: {error}"))
        })?;
    if !action.validate() {
        return Err(ValidationError::unprocessable(
            "invalid build-script action values",
        ));
    }
    Ok(ActionKind::BuildScript)
}

fn validate_cc_action(
    value: serde_json::Value,
    version: u64,
) -> Result<ActionKind, ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported cc action schema {version}"
        )));
    }
    let action = serde_json::from_value::<crate::model::CcAction>(value)
        .map_err(|error| ValidationError::unprocessable(format!("invalid cc action: {error}")))?;
    if !action.validate() {
        return Err(ValidationError::unprocessable("invalid cc action values"));
    }
    Ok(ActionKind::Cc)
}

fn validate_task_action(
    value: serde_json::Value,
    version: u64,
) -> Result<ActionKind, ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported task action schema {version}"
        )));
    }
    let object = value
        .as_object()
        .expect("action descriptors are checked to be objects");
    for field in [
        "version",
        "kind",
        "task",
        "phase",
        "run",
        "args",
        "shell",
        "outputs",
        "root",
        "source_hash",
        "environment",
        "vars",
        "tools",
        "os",
        "arch",
    ] {
        if !object.contains_key(field) {
            return Err(ValidationError::unprocessable(format!(
                "task action field {field:?} is required"
            )));
        }
    }
    let action = serde_json::from_value::<TaskAction>(value)
        .map_err(|error| ValidationError::unprocessable(format!("invalid task action: {error}")))?;
    if !action.validate() {
        return Err(ValidationError::unprocessable("invalid task action values"));
    }
    Ok(ActionKind::Task)
}

pub(crate) fn validate_rustc_action(
    value: serde_json::Value,
    version: u64,
) -> Result<ActionKind, ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported rustc action schema {version}"
        )));
    }
    let action = serde_json::from_value::<RustcAction>(value).map_err(|error| {
        ValidationError::unprocessable(format!("invalid rustc action: {error}"))
    })?;
    if !action.validate() {
        return Err(ValidationError::unprocessable(
            "invalid rustc action values",
        ));
    }
    Ok(ActionKind::Rustc)
}

pub(crate) async fn validate_client_metadata(
    state: &impl ValidationStore,
    namespace: &str,
    digest: &Digest,
    action_kind: ActionKind,
) -> Result<(), ValidationError> {
    let value = read_canonical_object(state, namespace, digest, "client metadata").await?;
    let object = value
        .as_object()
        .ok_or_else(|| ValidationError::unprocessable("client metadata must be a JSON object"))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ValidationError::unprocessable("client metadata kind is required"))?;
    let version = object
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ValidationError::unprocessable("client metadata version is required"))?;
    let expected_kind = match action_kind {
        ActionKind::BuildScript => "build-script",
        ActionKind::Cc => "cc",
        ActionKind::Rustc => "rustc",
        ActionKind::Task => "task",
    };
    if kind != expected_kind {
        return Err(ValidationError::unprocessable(
            "client metadata kind does not match action kind",
        ));
    }
    match action_kind {
        ActionKind::Task => validate_task_metadata(value, version),
        ActionKind::BuildScript => {
            validate_build_script_metadata(state, namespace, value, version).await
        }
        ActionKind::Cc => validate_cc_metadata(state, namespace, value, version).await,
        ActionKind::Rustc => validate_rustc_metadata(state, namespace, value, version).await,
    }
}

async fn validate_build_script_metadata(
    state: &impl ValidationStore,
    namespace: &str,
    value: serde_json::Value,
    version: u64,
) -> Result<(), ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported build-script metadata schema {version}"
        )));
    }
    let metadata: crate::model::BuildScriptMetadata =
        serde_json::from_value(value).map_err(|error| {
            ValidationError::unprocessable(format!("invalid build-script metadata: {error}"))
        })?;
    if !metadata.validate() {
        return Err(ValidationError::unprocessable(
            "invalid build-script metadata values",
        ));
    }
    require_output_blobs(
        state,
        namespace,
        &metadata.stdout,
        &metadata.stderr,
        "build-script",
    )
    .await
}

async fn validate_cc_metadata(
    state: &impl ValidationStore,
    namespace: &str,
    value: serde_json::Value,
    version: u64,
) -> Result<(), ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported cc metadata schema {version}"
        )));
    }
    let metadata: crate::model::CcMetadata = serde_json::from_value(value)
        .map_err(|error| ValidationError::unprocessable(format!("invalid cc metadata: {error}")))?;
    if !metadata.validate() {
        return Err(ValidationError::unprocessable("invalid cc metadata values"));
    }
    require_output_blobs(state, namespace, &metadata.stdout, &metadata.stderr, "cc").await
}

fn validate_task_metadata(value: serde_json::Value, version: u64) -> Result<(), ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported task metadata schema {version}"
        )));
    }
    let metadata: TaskMetadata = serde_json::from_value(value).map_err(|error| {
        ValidationError::unprocessable(format!("invalid task metadata: {error}"))
    })?;
    if !metadata.validate() {
        return Err(ValidationError::unprocessable(
            "invalid task metadata values",
        ));
    }
    for root in metadata.roots {
        validate_task_root(&root)?;
    }
    Ok(())
}

async fn validate_rustc_metadata(
    state: &impl ValidationStore,
    namespace: &str,
    value: serde_json::Value,
    version: u64,
) -> Result<(), ValidationError> {
    if version != 1 {
        return Err(ValidationError::unprocessable(format!(
            "unsupported rustc metadata schema {version}"
        )));
    }
    let metadata: RustcMetadata = serde_json::from_value(value).map_err(|error| {
        ValidationError::unprocessable(format!("invalid rustc metadata: {error}"))
    })?;
    if !metadata.validate() {
        return Err(ValidationError::unprocessable(
            "invalid rustc metadata values",
        ));
    }
    require_output_blobs(
        state,
        namespace,
        &metadata.stdout,
        &metadata.stderr,
        "rustc",
    )
    .await
}

async fn require_output_blobs(
    state: &impl ValidationStore,
    namespace: &str,
    stdout: &Digest,
    stderr: &Digest,
    kind: &str,
) -> Result<(), ValidationError> {
    validate_digest(stdout)?;
    validate_digest(stderr)?;
    let visible = state
        .visible(namespace, &[stdout.clone(), stderr.clone()])
        .await?;
    if !visible.contains(stdout) || !visible.contains(stderr) {
        return Err(ValidationError::unprocessable(format!(
            "{kind} output blob is missing"
        )));
    }
    Ok(())
}

pub(crate) fn validate_task_root(root: &str) -> Result<(), ValidationError> {
    if root.is_empty()
        || root.starts_with('/')
        || root.contains(['\\', '\0'])
        || root
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ValidationError::unprocessable(
            "task metadata root must be a safe relative path",
        ));
    }
    Ok(())
}

async fn read_canonical_object(
    state: &impl ValidationStore,
    namespace: &str,
    digest: &Digest,
    label: &str,
) -> Result<serde_json::Value, ValidationError> {
    validate_digest(digest)?;
    if digest.size > 16 * 1024 * 1024 {
        return Err(ValidationError::unprocessable(format!(
            "{label} is too large"
        )));
    }
    let bytes = state
        .read_visible(namespace, digest)
        .await?
        .ok_or_else(|| ValidationError::unprocessable(format!("{label} blob is missing")))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ValidationError::unprocessable(format!("{label} is invalid JSON")))?;
    if !value.is_object() || serde_json::to_vec(&value).map_err(ValidationError::internal)? != bytes
    {
        return Err(ValidationError::unprocessable(format!(
            "{label} is not canonical JSON"
        )));
    }
    Ok(value)
}

pub(crate) fn validate_directory_entries(directory: &Directory) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for node in &directory.directories {
        validate_entry(&mut names, &node.name, node.mode)?;
    }
    for node in &directory.files {
        validate_entry(&mut names, &node.name, node.mode)?;
        let _ = node.executable;
    }
    for node in &directory.symlinks {
        validate_entry(&mut names, &node.name, node.mode)?;
        if node.target.is_empty() || node.target.contains('\0') {
            return Err(ValidationError::unprocessable("invalid symlink target"));
        }
    }
    Ok(())
}

fn validate_entry(
    names: &mut HashSet<String>,
    name: &str,
    mode: u32,
) -> Result<(), ValidationError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
        || mode > 0o7777
    {
        return Err(ValidationError::unprocessable("invalid directory entry"));
    }
    if !names.insert(name.to_owned()) {
        return Err(ValidationError::unprocessable("duplicate directory entry"));
    }
    Ok(())
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::Arc,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Wake, Waker},
    };
    #[derive(Default)]
    struct Objects {
        bodies: HashMap<Digest, Vec<u8>>,
        reads: AtomicUsize,
    }
    impl ValidationStore for Objects {
        async fn visible(
            &self,
            _: &str,
            digests: &[Digest],
        ) -> Result<Vec<Digest>, ValidationError> {
            Ok(digests
                .iter()
                .filter(|d| self.bodies.contains_key(*d))
                .cloned()
                .collect())
        }
        async fn read(&self, digest: &Digest) -> Result<Option<Vec<u8>>, ValidationError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.bodies.get(digest).cloned())
        }
    }
    // The fake store completes synchronously, so a pending future is a test failure.
    fn run<T>(future: impl Future<Output = T>) -> T {
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(Noop));
        match std::pin::pin!(future)
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("fake store yielded"),
        }
    }
    fn directory(children: &[Digest]) -> Vec<u8> {
        let value = serde_json::json!({"version":1,"directories":children.iter().enumerate().map(|(i,d)|serde_json::json!({"name":format!("n{i}"),"mode":493,"digest":d})).collect::<Vec<_>>(),"files":[],"symlinks":[]});
        serde_json::to_vec(&serde_json::from_value::<Directory>(value).unwrap()).unwrap()
    }
    fn add(store: &mut Objects, children: &[Digest]) -> Digest {
        let bytes = directory(children);
        let digest = Digest {
            algorithm: "blake3".into(),
            hash: blake3::hash(&bytes).to_hex().to_string(),
            size: bytes.len() as u64,
        };
        store.bodies.insert(digest.clone(), bytes);
        digest
    }
    #[test]
    fn aggregate_budget_is_charged_before_next_read() {
        let mut store = Objects::default();
        let keys: Vec<_> = (0..5)
            .map(|i| Digest {
                algorithm: "blake3".into(),
                hash: format!("{i:064x}"),
                size: 16 * 1024 * 1024,
            })
            .collect();
        for i in 0..5 {
            store.bodies.insert(
                keys[i].clone(),
                directory(if i < 4 {
                    std::slice::from_ref(&keys[i + 1])
                } else {
                    &[]
                }),
            );
        }
        assert!(
            run(validate_tree(&store, "n", &keys[0]))
                .unwrap_err()
                .message
                .contains("byte budget")
        );
        assert_eq!(store.reads.load(Ordering::Relaxed), 4);
    }
    #[test]
    fn longest_shared_path_enforces_depth() {
        let mut store = Objects::default();
        let leaf = add(&mut store, &[]);
        let mut chain = leaf.clone();
        for _ in 0..128 {
            chain = add(&mut store, &[chain]);
        }
        let root = add(&mut store, &[leaf, chain]);
        assert!(
            run(validate_tree(&store, "n", &root))
                .unwrap_err()
                .message
                .contains("too deep")
        );
    }
    #[test]
    fn shared_subtrees_are_valid_and_read_once() {
        let mut store = Objects::default();
        let leaf = add(&mut store, &[]);
        let branch = add(&mut store, std::slice::from_ref(&leaf));
        let root = add(&mut store, &[leaf, branch]);
        run(validate_tree(&store, "n", &root)).unwrap();
        assert_eq!(store.reads.load(Ordering::Relaxed), 3);
    }
}
