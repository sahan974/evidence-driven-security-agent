use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

use edsa_core::PatchGate;
use edsa_reporting::ReplayPlan;

pub(super) fn go_sources(repository: &Path, plan: &ReplayPlan) -> Result<String, String> {
    if plan.command.first().is_none_or(|program| program != "go") {
        return Ok("{}".into());
    }
    let package = plan.command.get(2).ok_or("Missing Go package")?;
    if Path::new(package)
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err("Go replay must select a local package".into());
    }
    let root = repository.join(&plan.relative_source_root);
    let inventory = edsa_core::ingest_repository(&root, &edsa_core::RepositoryPolicy::default())
        .map_err(|error| error.to_string())?;
    let mut sources = BTreeMap::new();
    for file in inventory.files {
        let name = file.relative_path;
        if name.ends_with("_test.go")
            && (package == "./..."
                || Path::new(&name).parent() == Some(Path::new(package.trim_start_matches("./")))
                || (package == "." && Path::new(&name).parent() == Some(Path::new(""))))
        {
            let source = fs::read_to_string(root.join(&name)).map_err(|error| error.to_string())?;
            sources.insert(name, source);
        }
    }
    serde_json::to_string(&sources).map_err(|error| error.to_string())
}

pub(super) fn verification(
    plan: &ReplayPlan,
    rule: &str,
    gate: PatchGate,
    index: Option<u32>,
    sources: &Result<String, String>,
) -> Result<Vec<String>, String> {
    if !filesystem_rule(rule) {
        return Err("No patch verifier for this finding class".into());
    }
    let mode = if gate == PatchGate::VariantSearch {
        index
            .filter(|value| *value < 8)
            .ok_or("Invalid variant index")?
            .to_string()
    } else {
        "proof".into()
    };
    match plan.command.first().map(String::as_str) {
        Some("python") => {
            let script = if mode == "proof" {
                include_str!("python_patch_proof.py")
            } else {
                include_str!("python_patch_variants.py")
            };
            let mut command = vec!["python".into(), "-c".into(), script.into(),
                plan.command.last().cloned().ok_or("Missing replay script")?];
            if mode != "proof" { command.push(mode); }
            Ok(command)
        }
        Some("node") => Ok(vec!["node".into(), "--input-type=module".into(),
            "--experimental-strip-types".into(), "--eval".into(), include_str!("node_patch_gate.mjs").into(),
            plan.command.last().cloned().ok_or("Missing replay script")?, mode]),
        Some("go") => Ok(vec!["sh".into(), "-c".into(),
            "set -eu; helper=$(mktemp /tmp/edsa-gate-XXXXXX.go); trap 'rm -f \"$helper\"' EXIT; printf '%s' \"$1\" > \"$helper\"; go run \"$helper\" \"$2\" \"$3\" \"$4\"".into(),
            "edsa-patch".into(), include_str!("go_patch_gate.go").into(),
            serde_json::to_string(&plan.command).map_err(|error| error.to_string())?,
            mode, sources.clone()?]),
        _ => Err("Unsupported replay runtime".into()),
    }
}

fn filesystem_rule(rule: &str) -> bool {
    let normalized = rule.to_ascii_lowercase().replace('_', "-");
    normalized.contains("path-traversal")
        || normalized.contains("filesystem-boundary")
        || normalized.contains("unbounded-file-read")
        || normalized.contains("file-read-by-path")
        || normalized.contains("unvalidated-path-input")
        || normalized
            .split(|character: char| !character.is_ascii_alphanumeric())
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair == ["cwe", "22"])
}

pub(super) fn image(plan: &ReplayPlan) -> String {
    let variable = match plan.command.first().map(String::as_str) {
        Some("python") => "EDSA_PATCH_PYTHON_IMAGE",
        Some("node") => "EDSA_PATCH_TYPESCRIPT_IMAGE",
        Some("go") => "EDSA_PATCH_GO_IMAGE",
        _ => "EDSA_PATCH_IMAGE",
    };
    std::env::var(variable)
        .or_else(|_| std::env::var("EDSA_PATCH_IMAGE"))
        .unwrap_or_else(|_| plan.image.clone())
}

#[cfg(test)]
mod tests {
    use super::filesystem_rule;

    #[test]
    fn filesystem_rule_accepts_recorded_aliases_and_rejects_other_findings() {
        for rule in [
            "path_traversal_write_read",
            "path-traversal",
            "filesystem_boundary",
            "unbounded_file_read",
            "file-read-by-path",
            "unvalidated_path_input",
            "CWE-22 filesystem path traversal",
        ] {
            assert!(filesystem_rule(rule), "{rule}");
        }
        for rule in [
            "fuzz_target_exposed",
            "ssrf",
            "CWE-221",
            "command-injection",
        ] {
            assert!(!filesystem_rule(rule), "{rule}");
        }
    }
}
