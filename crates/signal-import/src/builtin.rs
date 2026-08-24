use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use edsa_core::{
    RepositoryInventory, SCHEMA_VERSION, Signal, SignalSource, resolve_repository_path,
};
use thiserror::Error;

use crate::signal_id;

const MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
];
const ENTRY_NAMES: &[&str] = &[
    "main.rs",
    "main.py",
    "app.py",
    "server.js",
    "index.js",
    "main.go",
];
const DANGEROUS: &[(&str, &[&str])] = &[
    (
        "dangerous-command-execution",
        &[
            "Command::new(",
            "subprocess.",
            "os.system(",
            "child_process",
            "exec(",
        ],
    ),
    (
        "dangerous-dynamic-evaluation",
        &["eval(", "exec(", "new Function("],
    ),
    (
        "dangerous-unsafe-deserialization",
        &["pickle.loads(", "yaml.load(", "ObjectInputStream"],
    ),
    (
        "dangerous-path-operation",
        &["../", "PathBuf::from(", "send_file(", "readFile("],
    ),
];

/// Collects deterministic, low-cost signals without requiring an external analyzer.
/// Repository code is read but never executed.
///
/// # Errors
/// Returns an error when Git status, repository file access, or repository path
/// validation fails.
pub fn collect_builtin_signals(
    root: &Path,
    inventory: &RepositoryInventory,
) -> Result<Vec<Signal>, BuiltinError> {
    let changed = changed_files(root)?;
    let mut signals = Vec::new();
    for file in &inventory.files {
        let path = &file.relative_path;
        let name = path.rsplit('/').next().unwrap_or(path);
        if MANIFESTS.contains(&name) {
            signals.push(make_signal(
                "repository-manifest",
                path,
                1,
                "Dependency or build manifest",
                "manifest",
            ));
        }
        if changed.contains(path) {
            signals.push(make_signal(
                "changed-file",
                path,
                1,
                "File differs from the repository revision",
                "git",
            ));
        }
        if is_test(path) {
            signals.push(make_signal(
                "test-file",
                path,
                1,
                "Repository test surface",
                "path",
            ));
        }
        if ENTRY_NAMES.contains(&name) {
            signals.push(make_signal(
                "entry-point",
                path,
                1,
                "Likely application entry point",
                "path",
            ));
        }

        let resolved = resolve_repository_path(root, Path::new(path))?;
        let Ok(content) = fs::read_to_string(resolved) else {
            continue;
        };
        for (line_index, line) in content.lines().enumerate() {
            for (rule, patterns) in DANGEROUS {
                if patterns.iter().any(|pattern| line.contains(pattern)) {
                    let line_number = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
                    signals.push(make_signal(
                        rule,
                        path,
                        line_number,
                        "Potentially security-sensitive operation",
                        "content-search",
                    ));
                }
            }
        }
    }
    signals.sort_by(|a, b| {
        (&a.relative_path, a.start_line, &a.rule).cmp(&(&b.relative_path, b.start_line, &b.rule))
    });
    signals.dedup_by(|a, b| a.id == b.id);
    Ok(signals)
}

fn make_signal(rule: &str, path: &str, line: u32, message: &str, detector: &str) -> Signal {
    let line_text = line.to_string();
    let mut metadata = BTreeMap::new();
    metadata.insert("provenance.detector".into(), detector.into());
    metadata.insert("provenance.tool".into(), "edsa-builtin".into());
    Signal {
        schema_version: SCHEMA_VERSION,
        id: signal_id(&["builtin", rule, path, &line_text]),
        source: SignalSource::BuiltInRule,
        rule: rule.into(),
        relative_path: path.into(),
        start_line: line,
        message: message.into(),
        metadata,
    }
}

fn is_test(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("tests/")
        || lower.contains("/tests/")
        || lower.contains("/test_")
        || lower.ends_with("_test.rs")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
}

fn changed_files(root: &Path) -> Result<BTreeSet<String>, BuiltinError> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(BuiltinError::Git(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let mut changed = BTreeSet::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let text = String::from_utf8_lossy(record);
        let path = text.get(3..).unwrap_or_default();
        let path = path
            .rsplit(" -> ")
            .next()
            .unwrap_or(path)
            .replace('\\', "/");
        changed.insert(path);
    }
    Ok(changed)
}

#[derive(Debug, Error)]
pub enum BuiltinError {
    #[error("built-in signal file access failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("repository path policy rejected a file: {0}")]
    Path(#[from] edsa_core::PathPolicyError),
    #[error("git status failed: {0}")]
    Git(String),
}
