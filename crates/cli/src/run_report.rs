use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use edsa_core::{RunEvent, RunStatus, SCHEMA_VERSION};
use edsa_evidence::RunStore;
use edsa_reporting::{
    BuilderDescriptor, BundleArtifactInput, BundleError, EvidenceBundleManifest, FindingConfidence,
    ReportFinding, RunReport, SourceDescriptor, verify_bundle, write_run_bundle,
};
use serde_json::Value;
use thiserror::Error;

/// Resolves either a run directory or an already selected bundle directory.
#[must_use]
pub fn bundle_path(run_or_bundle: &Path) -> PathBuf {
    if run_or_bundle.join("manifest.json").is_file() {
        run_or_bundle.to_path_buf()
    } else {
        run_or_bundle.join("bundle")
    }
}

/// Verifies the bundle and, when given a run directory, checks it against the
/// original immutable configuration and event ledger.
///
/// # Errors
/// Returns an error when any report or artifact is missing, malformed, or
/// modified, or when the live run and aggregate bundle disagree.
pub fn verify_run(run_or_bundle: &Path) -> Result<EvidenceBundleManifest, RunReportError> {
    let bundle = bundle_path(run_or_bundle);
    let manifest = verify_bundle(&bundle)?;
    if run_or_bundle.join("run.json").is_file() {
        let store = RunStore::open(run_or_bundle)?;
        let configuration = store.configuration()?;
        if manifest.source.repository != configuration.repository.repository_path
            || manifest.source.revision != configuration.repository.revision
            || manifest.source.content_digest != configuration.repository.content_digest
        {
            return Err(RunReportError::RunBundleMismatch);
        }
        let mut canonical_events = Vec::new();
        for event in store.events()? {
            canonical_events.extend(serde_json::to_vec(&event)?);
            canonical_events.push(b'\n');
        }
        if fs::read(bundle.join("events.jsonl"))? != canonical_events {
            return Err(RunReportError::RunBundleMismatch);
        }
    }
    Ok(manifest)
}

/// Returns the repository recorded by a run directory, if the supplied path is
/// a run rather than a standalone bundle.
///
/// # Errors
/// Returns an error when the stored run configuration cannot be read or parsed.
pub fn repository_path(run_or_bundle: &Path) -> Result<Option<PathBuf>, RunReportError> {
    if !run_or_bundle.join("run.json").is_file() {
        return Ok(None);
    }
    let configuration: edsa_core::RunConfiguration =
        serde_json::from_slice(&fs::read(run_or_bundle.join("run.json"))?)?;
    Ok(Some(PathBuf::from(
        configuration.repository.repository_path,
    )))
}

/// Finalizes a durable terminal run into one aggregate, verifiable report bundle.
///
/// # Errors
/// Returns an error when the run ledger or a finding bundle is invalid, evidence
/// is missing, reports disagree, or output files cannot be written.
pub fn finalize(store: &RunStore) -> Result<EvidenceBundleManifest, RunReportError> {
    let target = store.root().join("bundle");
    if target.exists() {
        return Ok(verify_bundle(&target)?);
    }
    let configuration = store.configuration()?;
    let events = store.events()?;
    let mut findings = Vec::new();
    let mut plans = Vec::new();
    let mut artifacts = Vec::new();
    let cases = store.root().join("cases");
    if cases.is_dir() {
        let mut entries = fs::read_dir(&cases)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let manifest = verify_bundle(&entry.path())?;
            findings.extend(manifest.findings);
            plans.extend(manifest.replay_plans);
            for artifact in manifest.artifacts {
                artifacts.push(BundleArtifactInput {
                    logical_name: format!(
                        "{}/{}",
                        entry.file_name().to_string_lossy(),
                        artifact.logical_name
                    ),
                    media_type: artifact.media_type,
                    bytes: fs::read(entry.path().join(artifact.relative_path))?,
                });
            }
        }
    }
    add_inconclusive_findings(&events, &mut findings);
    let report = report(configuration.run_id.as_str(), &events, findings.len());
    Ok(write_run_bundle(
        &target,
        SourceDescriptor {
            repository: configuration.repository.repository_path,
            revision: configuration.repository.revision,
            content_digest: configuration.repository.content_digest,
        },
        BuilderDescriptor {
            id: "edsa-live-scan".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        findings,
        plans,
        &events,
        artifacts,
        &report,
    )?)
}

fn add_inconclusive_findings(events: &[RunEvent], findings: &mut Vec<ReportFinding>) {
    let mut known = findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for event in events.iter().filter(|event| {
        event.payload.get("stage").and_then(Value::as_str) == Some("experiment_rejected")
    }) {
        let Some(hypothesis) = event
            .payload
            .get("hypothesis")
            .cloned()
            .and_then(|value| serde_json::from_value::<edsa_core::Hypothesis>(value).ok())
        else {
            continue;
        };
        if known.contains(hypothesis.id.as_str()) {
            continue;
        }
        known.insert(hypothesis.id.as_str().to_owned());
        let signal = event
            .payload
            .get("signal")
            .cloned()
            .and_then(|value| serde_json::from_value::<edsa_core::Signal>(value).ok());
        let message = event
            .payload
            .get("error")
            .and_then(Value::as_str)
            .map_or_else(
                || hypothesis.claim.clone(),
                |error| format!("{} Verification limitation: {error}", hypothesis.claim),
            );
        findings.push(ReportFinding {
            id: hypothesis.id.as_str().to_owned(),
            rule_id: signal
                .as_ref()
                .map_or_else(|| "EDSA-INCONCLUSIVE".into(), |value| value.rule.clone()),
            title: hypothesis.title,
            message,
            relative_path: signal
                .as_ref()
                .map_or_else(|| "unknown".into(), |value| value.relative_path.clone()),
            start_line: signal.as_ref().map_or(1, |value| value.start_line.max(1)),
            verdict: edsa_core::Verdict::Inconclusive,
            confidence: FindingConfidence::Low,
            evidence_digests: Vec::new(),
        });
    }
}

fn report(run_id: &str, events: &[RunEvent], finding_count: usize) -> RunReport {
    let terminal = events.last();
    let terminal_payload = terminal.map_or(&Value::Null, |event| &event.payload);
    let experiments = events
        .iter()
        .filter(|event| {
            event.payload.get("stage").and_then(Value::as_str) == Some("deterministic_experiment")
        })
        .filter_map(|event| event.payload.get("execution").cloned())
        .collect::<Vec<_>>();
    let signals = role_items(events, "mapper", "signals");
    let hypotheses = role_items(events, "hypothesis_planner", "hypotheses");
    let failures = events
        .iter()
        .filter(|event| {
            matches!(
                event.status,
                RunStatus::Failed | RunStatus::TimedOut | RunStatus::Cancelled
            ) || event.payload.get("error").is_some()
        })
        .map(|event| {
            event
                .payload
                .get("error")
                .and_then(Value::as_str)
                .map_or_else(
                    || event.message.clone(),
                    |error| format!("{}: {error}", event.message),
                )
        })
        .collect::<Vec<_>>();
    let mut limitations = Vec::new();
    if finding_count == 0 {
        limitations.push("No replayable finding bundle was produced by this run.".into());
    }
    let status = terminal.map_or(RunStatus::Failed, |event| event.status);
    if status != RunStatus::Completed {
        limitations.push(format!("The run ended with status {status:?}."));
    }
    RunReport {
        schema_version: SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        status,
        signals,
        hypotheses,
        experiments,
        verdicts: terminal_payload
            .get("verdicts")
            .cloned()
            .and_then(|value| serde_json::from_value::<BTreeMap<String, usize>>(value).ok())
            .unwrap_or_default(),
        limitations,
        failures,
        resource_usage: cumulative_usage(events),
    }
}

fn cumulative_usage(events: &[RunEvent]) -> Value {
    let mut keys = std::collections::BTreeSet::new();
    let mut turns = 0_u64;
    let mut model_tokens = 0_u64;
    let mut cost_microusd = 0_u64;
    let mut experiments = 0_u64;
    for event in events {
        let Some(key) = event.payload.get("checkpoint_key").and_then(Value::as_str) else {
            continue;
        };
        if !key.starts_with("role:") || !keys.insert(key.to_owned()) {
            continue;
        }
        turns = turns.saturating_add(1);
        model_tokens = model_tokens.saturating_add(
            event
                .payload
                .pointer("/checkpoint/usage/total_tokens")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        );
        cost_microusd = cost_microusd.saturating_add(
            event
                .payload
                .pointer("/checkpoint/estimated_cost_microusd")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        );
        if key.starts_with("role:experiment_designer:") {
            experiments = experiments.saturating_add(1);
        }
    }
    serde_json::json!({
        "turns": turns,
        "model_tokens": model_tokens,
        "cost_microusd": cost_microusd,
        "experiments": experiments
    })
}

fn role_items(events: &[RunEvent], role: &str, field: &str) -> Vec<Value> {
    events
        .iter()
        .find(|event| {
            event.payload.get("stage").and_then(Value::as_str) == Some("role_response")
                && event.payload.get("role").and_then(Value::as_str) == Some(role)
        })
        .and_then(|event| event.payload.pointer(&format!("/response/{field}")))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[derive(Debug, Error)]
pub enum RunReportError {
    #[error("run storage failed: {0}")]
    Store(#[from] edsa_evidence::RunStoreError),
    #[error("report bundle failed: {0}")]
    Bundle(#[from] BundleError),
    #[error("report I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("report JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the live run ledger or source metadata disagrees with its report bundle")]
    RunBundleMismatch,
}
