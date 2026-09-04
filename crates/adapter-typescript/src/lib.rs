//! TypeScript and JavaScript repository investigation adapter.

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
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRunner {
    Vitest,
    Jest,
    PackageScript,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeEnvironmentPlan {
    pub image: String,
    pub manager: PackageManager,
    pub lockfile: String,
    pub install_command: Vec<String>,
    pub test_runner: TestRunner,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeHypothesisKind {
    PathTraversal,
    Ssrf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeTarget {
    pub module: String,
    pub callable: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reproducer {
    pub image: String,
    pub command: Vec<String>,
    pub oracle: Oracle,
    pub negative_control: Oracle,
}

impl Reproducer {
    /// Replays the recorded experiment without LLM participation.
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
pub fn is_node_repository(inventory: &RepositoryInventory) -> bool {
    inventory
        .detection
        .languages
        .contains(&Language::TypeScript)
        || inventory
            .detection
            .languages
            .contains(&Language::JavaScript)
}

/// Selects a package manager exclusively from a committed lockfile and detects
/// the configured test runner without executing package scripts.
///
/// # Errors
/// Returns an error when no supported lockfile exists, paths fail validation,
/// or `package.json` is malformed.
pub fn environment_plan(
    root: &Path,
    inventory: &RepositoryInventory,
) -> Result<NodeEnvironmentPlan, TypeScriptAdapterError> {
    let paths = inventory
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<Vec<_>>();
    let (manager, lockfile, install): (PackageManager, &str, &[&str]) =
        if paths.contains(&"pnpm-lock.yaml") {
            (
                PackageManager::Pnpm,
                "pnpm-lock.yaml",
                &["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"],
            )
        } else if paths.contains(&"yarn.lock") {
            (
                PackageManager::Yarn,
                "yarn.lock",
                &["yarn", "install", "--immutable", "--ignore-scripts"],
            )
        } else if paths.contains(&"package-lock.json") {
            (
                PackageManager::Npm,
                "package-lock.json",
                &["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            )
        } else {
            return Err(TypeScriptAdapterError::MissingLockfile);
        };
    let package_path = resolve_repository_path(root, Path::new("package.json"))?;
    let package: serde_json::Value = serde_json::from_slice(&fs::read(package_path)?)?;
    let scripts = package.get("scripts").and_then(|value| value.as_object());
    let test_text = scripts
        .and_then(|value| value.get("test"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let dependencies = package
        .get("devDependencies")
        .and_then(|value| value.as_object());
    let test_runner = if test_text.contains("vitest")
        || dependencies.is_some_and(|value| value.contains_key("vitest"))
    {
        TestRunner::Vitest
    } else if test_text.contains("jest")
        || dependencies.is_some_and(|value| value.contains_key("jest"))
    {
        TestRunner::Jest
    } else {
        TestRunner::PackageScript
    };
    Ok(NodeEnvironmentPlan {
        image: "node:22-slim".into(),
        manager,
        lockfile: lockfile.into(),
        install_command: install.iter().map(|value| (*value).into()).collect(),
        test_runner,
    })
}

#[must_use]
pub fn sandbox_policy() -> SandboxPolicy {
    let mut policy = SandboxPolicy::default();
    policy
        .allowed_environment
        .insert("EDSA_NEGATIVE_CONTROL".into());
    policy
}

#[must_use]
pub fn baseline_request(root: PathBuf, plan: &NodeEnvironmentPlan) -> SandboxRequest {
    let command: &[&str] = match (plan.manager, plan.test_runner) {
        (PackageManager::Npm, TestRunner::Vitest) => {
            &["npm", "exec", "--offline", "vitest", "run", "--"]
        }
        (PackageManager::Npm, TestRunner::Jest) => {
            &["npm", "exec", "--offline", "jest", "--", "--runInBand"]
        }
        (PackageManager::Npm, TestRunner::PackageScript) => &["npm", "test", "--", "--runInBand"],
        (PackageManager::Pnpm, TestRunner::Vitest) => &["pnpm", "exec", "vitest", "run"],
        (PackageManager::Pnpm, TestRunner::Jest) => &["pnpm", "exec", "jest", "--runInBand"],
        (PackageManager::Pnpm, TestRunner::PackageScript) => &["pnpm", "test", "--", "--runInBand"],
        (PackageManager::Yarn, TestRunner::Vitest) => &["yarn", "vitest", "run"],
        (PackageManager::Yarn, TestRunner::Jest) => &["yarn", "jest", "--runInBand"],
        (PackageManager::Yarn, TestRunner::PackageScript) => &["yarn", "test", "--runInBand"],
    };
    SandboxRequest {
        source_root: root,
        image: plan.image.clone(),
        command: command.iter().map(|value| (*value).to_owned()).collect(),
        environment: BTreeMap::new(),
    }
}

#[must_use]
pub fn regression_request(root: PathBuf, plan: &NodeEnvironmentPlan) -> SandboxRequest {
    baseline_request(root, plan)
}

#[must_use]
pub fn generated_experiment(
    root: PathBuf,
    image: impl Into<String>,
    kind: NodeHypothesisKind,
    target: &NodeTarget,
) -> (ExperimentRequest, Reproducer) {
    let script = match kind {
        NodeHypothesisKind::PathTraversal => traversal_script(target),
        NodeHypothesisKind::Ssrf => ssrf_script(target),
    };
    let command = vec![
        "node".into(),
        "--input-type=module".into(),
        "--eval".into(),
        script,
    ];
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

fn traversal_script(target: &NodeTarget) -> String {
    format!(
        "const control=process.env.EDSA_NEGATIVE_CONTROL==='1';\nconst payload=control?'safe.txt':'../../etc/passwd';\ntry {{ const mod=await import({module:?}); const result=String(await mod[{callable:?}](payload)); const vulnerable=result.includes('root:'); console.log(control&&!vulnerable?'EDSA_CONTROL_CLEAN':vulnerable?'EDSA_VULNERABLE':'EDSA_NOT_REPRODUCED'); }} catch(error) {{ console.log('EDSA_INCONCLUSIVE:'+error.constructor.name); }}",
        module = target.module,
        callable = target.callable
    )
}

fn ssrf_script(target: &NodeTarget) -> String {
    format!(
        "import http from 'node:http';\nconst control=process.env.EDSA_NEGATIVE_CONTROL==='1'; let callback=false;\nconst server=http.createServer((req,res)=>{{callback=true;res.end('ok')}});\nawait new Promise(resolve=>server.listen(0,'127.0.0.1',resolve)); const port=server.address().port;\nconst url=control?'http://127.0.0.1:1/clean':`http://127.0.0.1:${{port}}/edsa`;\ntry {{ const mod=await import({module:?}); await mod[{callable:?}](url); await new Promise(resolve=>setTimeout(resolve,25)); console.log(control&&!callback?'EDSA_CONTROL_CLEAN':callback?'EDSA_VULNERABLE':'EDSA_NOT_REPRODUCED'); }} catch(error) {{ console.log(control&&!callback?'EDSA_CONTROL_CLEAN':'EDSA_INCONCLUSIVE:'+error.constructor.name); }} finally {{ server.close(); }}",
        module = target.module,
        callable = target.callable
    )
}

#[derive(Debug, Error)]
pub enum TypeScriptAdapterError {
    #[error("no supported npm, pnpm, or yarn lockfile was found")]
    MissingLockfile,
    #[error("repository path validation failed: {0}")]
    Path(#[from] edsa_core::PathPolicyError),
    #[error("repository read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("package.json is malformed: {0}")]
    Json(#[from] serde_json::Error),
}
