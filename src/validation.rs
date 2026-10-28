//! Validation shared by the native server and the Cloudflare Worker.
use crate::model::{
    ActionResult, BUILD_SCRIPT_ACTION_SCHEMAS, Digest, Directory, RustcAction, RustcMetadata,
    TaskAction, TaskMetadata,
};
use std::{collections::HashSet, future::Future};

pub(crate) trait ValidationStore {
    fn visible(
        &self,
        namespace: &str,
        digests: &[Digest],
    ) -> impl Future<Output = Result<Vec<Digest>, ValidationError>> + Send;
    /// Read one bounded protocol object, never an arbitrary artifact.
    fn read(
        &self,
        digest: &Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ValidationError>> + Send;
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

async fn require_blob(
    state: &(impl ValidationStore + Sync),
    namespace: &str,
    digest: &Digest,
    label: &str,
) -> Result<(), ValidationError> {
    validate_digest(digest)?;
    if state
        .visible(namespace, std::slice::from_ref(digest))
        .await?
        .contains(digest)
    {
        Ok(())
    } else {
        Err(ValidationError::unprocessable(format!(
            "{label} is missing"
        )))
    }
}

pub(crate) async fn validate_tree(
    state: &(impl ValidationStore + Sync),
    namespace: &str,
    root: &Digest,
) -> Result<(), ValidationError> {
    enum Visit {
        Enter(Digest),
        Exit(Digest),
    }

    let mut pending = vec![Visit::Enter(root.clone())];
    let mut visiting = HashSet::new();
    let mut seen = HashSet::new();
    while let Some(visit) = pending.pop() {
        let digest = match visit {
            Visit::Exit(digest) => {
                visiting.remove(&digest);
                seen.insert(digest);
                continue;
            }
            Visit::Enter(digest) => digest,
        };
        if seen.contains(&digest) {
            continue;
        }
        if !visiting.insert(digest.clone()) {
            return Err(ValidationError::unprocessable(
                "directory graph contains a cycle",
            ));
        }
        if seen.len() + visiting.len() > 100_000 {
            return Err(ValidationError::unprocessable(
                "directory graph is too large",
            ));
        }
        if digest.size > 16 * 1024 * 1024 {
            return Err(ValidationError::unprocessable(
                "directory object is too large",
            ));
        }
        if !state
            .visible(namespace, std::slice::from_ref(&digest))
            .await?
            .contains(&digest)
        {
            return Err(ValidationError::unprocessable(
                "directory object is missing",
            ));
        }
        let bytes = state
            .read(&digest)
            .await?
            .ok_or_else(|| ValidationError::unprocessable("directory object is missing"))?;
        let directory: Directory = serde_json::from_slice(&bytes)
            .map_err(|_| ValidationError::unprocessable("directory object is invalid"))?;
        if serde_json::to_vec(&directory).map_err(ValidationError::internal)? != bytes {
            return Err(ValidationError::unprocessable(
                "directory object is not canonical JSON",
            ));
        }
        if directory.version != 1 {
            return Err(ValidationError::unprocessable(
                "unsupported directory object version",
            ));
        }
        validate_directory_entries(&directory)?;
        let files: Vec<_> = directory
            .files
            .into_iter()
            .map(|file| file.digest)
            .collect();
        for digest in &files {
            validate_digest(digest)?;
        }
        let visible: HashSet<_> = state
            .visible(namespace, &files)
            .await?
            .into_iter()
            .collect();
        if files.iter().any(|digest| !visible.contains(digest)) {
            return Err(ValidationError::unprocessable("file blob is missing"));
        }
        pending.push(Visit::Exit(digest));
        pending.extend(
            directory
                .directories
                .into_iter()
                .map(|node| Visit::Enter(node.digest)),
        );
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
    state: &(impl ValidationStore + Sync),
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
    state: &(impl ValidationStore + Sync),
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
    state: &(impl ValidationStore + Sync),
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
    state: &(impl ValidationStore + Sync),
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
    state: &(impl ValidationStore + Sync),
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
    state: &(impl ValidationStore + Sync),
    namespace: &str,
    stdout: &Digest,
    stderr: &Digest,
    kind: &str,
) -> Result<(), ValidationError> {
    require_blob(state, namespace, stdout, &format!("{kind} stdout blob")).await?;
    require_blob(state, namespace, stderr, &format!("{kind} stderr blob")).await
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
    state: &(impl ValidationStore + Sync),
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
    if !state
        .visible(namespace, std::slice::from_ref(digest))
        .await?
        .contains(digest)
    {
        return Err(ValidationError::unprocessable(format!(
            "{label} blob is missing"
        )));
    }
    let bytes = state
        .read(digest)
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
