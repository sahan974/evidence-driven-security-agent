use std::collections::BTreeMap;

use edsa_core::{SCHEMA_VERSION, Signal, SignalSource};
use serde::Deserialize;
use thiserror::Error;

use crate::signal_id;

#[derive(Debug, Deserialize)]
struct SarifLog {
    version: String,
    runs: Vec<Run>,
}

#[derive(Debug, Deserialize)]
struct Run {
    tool: Tool,
    #[serde(default)]
    results: Vec<ResultRecord>,
}

#[derive(Debug, Deserialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: String,
    #[serde(default)]
    semantic_version: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResultRecord {
    #[serde(default)]
    rule_id: Option<String>,
    message: Message,
    #[serde(default)]
    locations: Vec<Location>,
    #[serde(default)]
    code_flows: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Message {
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: Option<PhysicalLocation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: Option<ArtifactLocation>,
    region: Option<Region>,
}

#[derive(Debug, Deserialize)]
struct ArtifactLocation {
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    #[serde(default = "one")]
    start_line: u32,
}

const fn one() -> u32 {
    1
}

/// Imports SARIF 2.1.0 results as unconfirmed external signals.
///
/// # Errors
/// Returns an error when the document is malformed, uses another SARIF version,
/// or contains metadata that cannot be normalized as JSON.
pub fn import_sarif(bytes: &[u8], artifact_reference: &str) -> Result<Vec<Signal>, SarifError> {
    let log: SarifLog = serde_json::from_slice(bytes)?;
    if log.version != "2.1.0" {
        return Err(SarifError::UnsupportedVersion(log.version));
    }
    let mut signals = Vec::new();
    for (run_index, run) in log.runs.into_iter().enumerate() {
        let tool_version = run
            .tool
            .driver
            .semantic_version
            .or(run.tool.driver.version)
            .unwrap_or_default();
        for (result_index, result) in run.results.into_iter().enumerate() {
            let rule = result.rule_id.unwrap_or_else(|| "unknown-rule".into());
            let locations = if result.locations.is_empty() {
                vec![Location {
                    physical_location: None,
                }]
            } else {
                result.locations
            };
            let flow = serde_json::to_string(&result.code_flows)?;
            for (location_index, location) in locations.into_iter().enumerate() {
                let physical = location.physical_location;
                let path = physical
                    .as_ref()
                    .and_then(|value| value.artifact_location.as_ref())
                    .and_then(|value| value.uri.clone())
                    .unwrap_or_default();
                let path = normalize_uri(&path);
                let line = physical
                    .and_then(|value| value.region)
                    .map_or(1, |value| value.start_line);
                let mut metadata = BTreeMap::new();
                metadata.insert("provenance.artifact".into(), artifact_reference.into());
                metadata.insert("provenance.tool".into(), run.tool.driver.name.clone());
                metadata.insert("provenance.tool_version".into(), tool_version.clone());
                metadata.insert("sarif.code_flows".into(), flow.clone());
                metadata.insert("sarif.location_index".into(), location_index.to_string());
                metadata.insert("sarif.run_index".into(), run_index.to_string());
                let line_text = line.to_string();
                let result_text = result_index.to_string();
                signals.push(Signal {
                    schema_version: SCHEMA_VERSION,
                    id: signal_id(&[
                        "sarif",
                        artifact_reference,
                        &run_index.to_string(),
                        &result_text,
                        &location_index.to_string(),
                        &rule,
                        &path,
                        &line_text,
                    ]),
                    source: SignalSource::ExternalAnalyzer,
                    rule: rule.clone(),
                    relative_path: path,
                    start_line: line,
                    message: result.message.text.clone(),
                    metadata,
                });
            }
        }
    }
    Ok(signals)
}

fn normalize_uri(uri: &str) -> String {
    uri.strip_prefix("file:///")
        .unwrap_or(uri)
        .replace("%20", " ")
        .replace('\\', "/")
}

#[derive(Debug, Error)]
pub enum SarifError {
    #[error("malformed SARIF: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported SARIF version {0}; expected 2.1.0")]
    UnsupportedVersion(String),
}
