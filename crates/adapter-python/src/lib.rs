//! Python repository investigation adapter.

pub mod oracles;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use edsa_adapter_sdk::{ExperimentEvidence, ExperimentRequest, ExperimentRunner, Oracle};
use edsa_core::{Language, RepositoryInventory, resolve_repository_path};
use edsa_sandbox::{SandboxPolicy, SandboxRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyManager {
    Uv,
    Poetry,
    Pipenv,
    PipRequirements,
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PythonEnvironmentPlan {
    pub image: String,
    pub manager: DependencyManager,
    pub lockfile: Option<String>,
    pub preparation_command: Vec<String>,
    pub locked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PythonFramework {
    Flask,
    FastApi,
    Django,
    Generic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PythonHypothesisKind {
    PathTraversal,
    CommandInjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PythonTarget {
    pub module: String,
    pub callable: String,
    pub framework: PythonFramework,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reproducer {
    pub image: String,
    pub command: Vec<String>,
    pub oracle: Oracle,
    pub negative_control: Oracle,
}

impl Reproducer {
    /// Replays this recorded reproducer without model participation.
    ///
    /// # Errors
    /// Returns a sandbox execution error.
    pub async fn replay(
        &self,
        runner: &ExperimentRunner,
        root: PathBuf,
        cancellation: CancellationToken,
    ) -> Result<ExperimentEvidence, edsa_adapter_sdk::AdapterError> {
        runner
            .execute(
                ExperimentRequest {
                    sandbox: SandboxRequest {
                        source_root: root,
                        image: self.image.clone(),
                        command: self.command.clone(),
                        environment: BTreeMap::new(),
                    },
                    oracle: self.oracle.clone(),
                    negative_control: self.negative_control.clone(),
                },
                cancellation,
            )
            .await
    }
}

#[must_use]
pub fn is_python_repository(inventory: &RepositoryInventory) -> bool {
    inventory.detection.languages.contains(&Language::Python)
}

#[must_use]
pub fn environment_plan(inventory: &RepositoryInventory) -> PythonEnvironmentPlan {
    let paths = inventory
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<Vec<_>>();
    let (manager, lockfile, command, locked) = if paths.contains(&"uv.lock") {
        (
            DependencyManager::Uv,
            Some("uv.lock"),
            vec!["uv", "sync", "--frozen"],
            true,
        )
    } else if paths.contains(&"poetry.lock") {
        (
            DependencyManager::Poetry,
            Some("poetry.lock"),
            vec!["poetry", "install", "--no-interaction", "--sync"],
            true,
        )
    } else if paths.contains(&"Pipfile.lock") {
        (
            DependencyManager::Pipenv,
            Some("Pipfile.lock"),
            vec!["pipenv", "sync"],
            true,
        )
    } else if let Some(requirements) = paths.iter().find(|path| {
        path.starts_with("requirements")
            && Path::new(path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
    }) {
        (
            DependencyManager::PipRequirements,
            Some(*requirements),
            vec![
                "python",
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                *requirements,
            ],
            false,
        )
    } else {
        (DependencyManager::None, None, Vec::new(), false)
    };
    PythonEnvironmentPlan {
        image: "python:3.12-slim".into(),
        manager,
        lockfile: lockfile.map(str::to_owned),
        preparation_command: command.into_iter().map(str::to_owned).collect(),
        locked,
    }
}

#[must_use]
pub fn baseline_request(root: PathBuf, image: impl Into<String>) -> SandboxRequest {
    SandboxRequest {
        source_root: root,
        image: image.into(),
        command: vec![
            "python".into(),
            "-c".into(),
            "import pathlib; [compile(p.read_text(encoding='utf-8'), str(p), 'exec') for p in pathlib.Path('.').rglob('*.py')]".into(),
        ],
        environment: BTreeMap::new(),
    }
}

/// Returns the hardened sandbox policy with only the adapter's non-secret
/// negative-control selector added to the environment allowlist.
#[must_use]
pub fn sandbox_policy() -> SandboxPolicy {
    let mut policy = SandboxPolicy::default();
    policy
        .allowed_environment
        .insert("EDSA_NEGATIVE_CONTROL".into());
    policy
}

/// Uses the ordinary test suite as the post-change regression gate.
#[must_use]
pub fn regression_request(root: PathBuf, image: impl Into<String>) -> SandboxRequest {
    baseline_request(root, image)
}

/// Detects a supported framework using bounded text reads only.
///
/// # Errors
/// Returns an error if an inventoried Python file cannot be read.
pub fn detect_framework(
    root: &Path,
    inventory: &RepositoryInventory,
) -> Result<PythonFramework, PythonAdapterError> {
    let mut combined = String::new();
    for file in inventory.files.iter().filter(|file| {
        Path::new(&file.relative_path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("py"))
    }) {
        let path = resolve_repository_path(root, Path::new(&file.relative_path))?;
        let bytes = fs::read(path)?;
        combined.push_str(&String::from_utf8_lossy(
            &bytes[..bytes.len().min(64 * 1024)],
        ));
    }
    Ok(
        if combined.contains("from flask") || combined.contains("import flask") {
            PythonFramework::Flask
        } else if combined.contains("from fastapi") || combined.contains("import fastapi") {
            PythonFramework::FastApi
        } else if combined.contains("from django") || combined.contains("import django") {
            PythonFramework::Django
        } else {
            PythonFramework::Generic
        },
    )
}

#[must_use]
pub fn generated_experiment(
    root: PathBuf,
    image: impl Into<String>,
    kind: PythonHypothesisKind,
    target: &PythonTarget,
) -> (ExperimentRequest, Reproducer) {
    let script = experiment_script(kind, target);
    let command = vec!["python".into(), "-c".into(), script];
    let oracle = oracles::vulnerability_marker();
    let negative_control = oracles::clean_control_marker();
    let reproducer = Reproducer {
        image: image.into(),
        command: command.clone(),
        oracle: oracle.clone(),
        negative_control: negative_control.clone(),
    };
    (
        ExperimentRequest {
            sandbox: SandboxRequest {
                source_root: root,
                image: reproducer.image.clone(),
                command,
                environment: BTreeMap::new(),
            },
            oracle,
            negative_control,
        },
        reproducer,
    )
}

fn experiment_script(kind: PythonHypothesisKind, target: &PythonTarget) -> String {
    let (attack, control) = match kind {
        PythonHypothesisKind::PathTraversal => ("../../etc/passwd", "safe.txt"),
        PythonHypothesisKind::CommandInjection => ("edsa;printf EDSA_COMMAND_MARKER", "edsa-safe"),
    };
    let invocation = match target.framework {
        PythonFramework::Generic => format!(
            "result=getattr(importlib.import_module({:?}), {:?})(candidate)",
            target.module, target.callable
        ),
        PythonFramework::Flask => format!(
            "app=getattr(importlib.import_module({:?}), {:?}); result=app.test_client().get(candidate).get_data(as_text=True)",
            target.module, target.callable
        ),
        PythonFramework::FastApi => format!(
            "from fastapi.testclient import TestClient; app=getattr(importlib.import_module({:?}), {:?}); result=TestClient(app).get(candidate).text",
            target.module, target.callable
        ),
        PythonFramework::Django => {
            "from django.test import Client; result=Client().get(candidate).content.decode()".into()
        }
    };
    format!(
        "import importlib,os\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\ncandidate={control:?} if control else {attack:?}\ntry:\n {invocation}\n text=str(result)\n vulnerable=({marker:?} in text)\n print('EDSA_CONTROL_CLEAN' if control and not vulnerable else ('EDSA_VULNERABLE' if vulnerable else 'EDSA_NOT_REPRODUCED'))\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
        marker = if kind == PythonHypothesisKind::CommandInjection {
            "EDSA_COMMAND_MARKER"
        } else {
            "root:"
        }
    )
}

#[derive(Debug, Error)]
pub enum PythonAdapterError {
    #[error("Python repository read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Python repository path failed validation: {0}")]
    Path(#[from] edsa_core::PathPolicyError),
}
