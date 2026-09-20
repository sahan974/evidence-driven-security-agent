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
    SqlInjection,
    UnsafeDeserialization,
    BrokenAuthorization,
    SensitiveDataExposure,
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
                        writable_cache_root: None,
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
        writable_cache_root: None,
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
                writable_cache_root: None,
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
        PythonHypothesisKind::PathTraversal => ("../../etc/passwd", "documents/safe.txt"),
        PythonHypothesisKind::CommandInjection => ("edsa;printf EDSA_COMMAND_MARKER", "edsa-safe"),
        PythonHypothesisKind::SqlInjection => ("' OR '1'='1", "edsa-safe"),
        PythonHypothesisKind::UnsafeDeserialization
        | PythonHypothesisKind::BrokenAuthorization
        | PythonHypothesisKind::SensitiveDataExposure => ("unused", "unused"),
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
    if kind == PythonHypothesisKind::SqlInjection {
        return format!(
            "import importlib,json,os,sqlite3,sys\nsys.path.insert(0,'/workspace')\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\ncandidate={control:?} if control else {attack:?}\nconnection=sqlite3.connect(':memory:')\nconnection.execute('CREATE TABLE accounts (id INTEGER PRIMARY KEY, username TEXT NOT NULL)')\nconnection.execute(\"INSERT INTO accounts (id, username) VALUES (1, 'admin')\")\nconnection.execute(\"INSERT INTO accounts (id, username) VALUES (2, 'edsa-safe-user')\")\nconnection.commit()\ntry:\n module_object=importlib.import_module({module:?})\n target=getattr(module_object, {callable:?})\n result=target(connection,candidate)\n observed={{'candidate': candidate, 'returned_row': result, 'module_file': getattr(module_object, '__file__', None), 'callable_module': getattr(target, '__module__', None), 'callable_qualname': getattr(target, '__qualname__', None)}}\n print('EDSA_SQL_OBSERVATION='+json.dumps(observed, default=str, sort_keys=True))\n if control:\n  clean=(result is None)\n  print('EDSA_CONTROL_CLEAN' if clean else 'EDSA_NOT_REPRODUCED')\n else:\n  reproduced=(result == (1,))\n  print('EDSA_VULNERABLE' if reproduced else 'EDSA_NOT_REPRODUCED')\nexcept sqlite3.Error as error:\n print('EDSA_NOT_REPRODUCED:'+type(error).__name__)\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
            module = target.module,
            callable = target.callable,
        );
    }
    if kind == PythonHypothesisKind::PathTraversal {
        return format!(
            "import importlib,json,os,sys\nsys.path.insert(0,'/workspace')\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\nos.makedirs('/tmp/edsa/documents',exist_ok=True)\nopen('/tmp/edsa/documents/safe.txt','w',encoding='utf-8').write('EDSA_SAFE_DOCUMENT')\nopen('/tmp/edsa/outside.txt','w',encoding='utf-8').write('EDSA_OUTSIDE_SENTINEL')\nos.chdir('/tmp/edsa')\ncandidate='safe.txt' if control else '../outside.txt'\ntry:\n module_object=importlib.import_module({module:?})\n target=getattr(module_object, {callable:?})\n result=target(candidate)\n observed={{'candidate': candidate, 'returned_content': result, 'module_file': getattr(module_object, '__file__', None), 'callable_module': getattr(target, '__module__', None), 'callable_qualname': getattr(target, '__qualname__', None)}}\n print('EDSA_PATH_OBSERVATION='+json.dumps(observed, default=str, sort_keys=True))\n if control:\n  clean=(result == 'EDSA_SAFE_DOCUMENT')\n  print('EDSA_CONTROL_CLEAN' if clean else 'EDSA_NOT_REPRODUCED')\n else:\n  escaped=(result == 'EDSA_OUTSIDE_SENTINEL')\n  print('EDSA_VULNERABLE' if escaped else 'EDSA_NOT_REPRODUCED')\nexcept FileNotFoundError as error:\n print('EDSA_NOT_REPRODUCED:'+type(error).__name__)\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
            module = target.module,
            callable = target.callable,
        );
    }
    if kind == PythonHypothesisKind::UnsafeDeserialization {
        return format!(
            "import importlib,os,pickle,sys\nsys.path.insert(0,'/workspace')\nmarker_hit=False\ndef mark_deserialized():\n global marker_hit\n marker_hit=True\nclass Marker:\n def __reduce__(self): return (mark_deserialized,())\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\npayload=pickle.dumps({{}} if control else Marker())\ntry:\n getattr(importlib.import_module({module:?}), {callable:?})(payload)\n vulnerable=marker_hit\n print('EDSA_CONTROL_CLEAN' if control and not vulnerable else ('EDSA_VULNERABLE' if vulnerable else 'EDSA_NOT_REPRODUCED'))\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
            module = target.module,
            callable = target.callable,
        );
    }
    if kind == PythonHypothesisKind::CommandInjection {
        return format!(
            "import importlib,os,sys\nsys.path.insert(0,'/workspace')\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\nos.makedirs('/tmp/edsa/bin',exist_ok=True)\nshim='/tmp/edsa/bin/nslookup'\nif not os.path.exists(shim): os.symlink('/bin/echo',shim)\nos.environ['PATH']='/tmp/edsa/bin:'+os.environ.get('PATH','')\ncandidate='edsa-safe' if control else 'edsa-safe; printf EDSA_COMMAND_MARKER'\ntry:\n result=getattr(importlib.import_module({module:?}), {callable:?})(candidate)\n text=str(result)\n vulnerable=not control and 'EDSA_COMMAND_MARKER' in text\n clean=control and 'edsa-safe' in text and 'EDSA_COMMAND_MARKER' not in text\n print('EDSA_CONTROL_CLEAN' if clean else ('EDSA_VULNERABLE' if vulnerable else 'EDSA_NOT_REPRODUCED'))\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
            module = target.module,
            callable = target.callable,
        );
    }
    if kind == PythonHypothesisKind::BrokenAuthorization {
        return format!(
            "import importlib,os\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\nrecords={{'invoice-1':{{'owner_id':'owner','value':'private'}}}}\ntry:\n result=getattr(importlib.import_module({module:?}), {callable:?})(records,'invoice-1','owner' if control else 'attacker')\n vulnerable=(not control and result is not None)\n print('EDSA_CONTROL_CLEAN' if control and result is not None else ('EDSA_VULNERABLE' if vulnerable else 'EDSA_NOT_REPRODUCED'))\nexcept PermissionError:\n print('EDSA_CONTROL_CLEAN' if not control else 'EDSA_NOT_REPRODUCED')\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
            module = target.module,
            callable = target.callable,
        );
    }
    if kind == PythonHypothesisKind::SensitiveDataExposure {
        return format!(
            "import importlib,os\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\nuser={{'id':'1','display_name':'edsa','token':'secret'}}\ntry:\n result=getattr(importlib.import_module({module:?}), {callable:?})(user)\n text=str(result)\n vulnerable=(not control and 'secret' in text)\n clean=(control and 'secret' not in text)\n print('EDSA_CONTROL_CLEAN' if clean else ('EDSA_VULNERABLE' if vulnerable else 'EDSA_NOT_REPRODUCED'))\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
            module = target.module,
            callable = target.callable,
        );
    }
    format!(
        "import importlib,os,sys\nsys.path.insert(0,'/workspace')\ncontrol=os.getenv('EDSA_NEGATIVE_CONTROL')=='1'\ncandidate={control:?} if control else {attack:?}\n{setup}\ntry:\n {invocation}\n text=str(result)\n vulnerable=({marker:?} in text)\n print('EDSA_CONTROL_CLEAN' if control and not vulnerable else ('EDSA_VULNERABLE' if vulnerable else 'EDSA_NOT_REPRODUCED'))\nexcept Exception as error:\n print('EDSA_INCONCLUSIVE:'+type(error).__name__)\n",
        setup = if kind == PythonHypothesisKind::PathTraversal {
            "os.makedirs('/tmp/edsa/documents',exist_ok=True); open('/tmp/edsa/documents/safe.txt','w',encoding='utf-8').write('safe'); os.chdir('/tmp/edsa')"
        } else {
            ""
        },
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
