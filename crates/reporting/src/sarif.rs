use edsa_core::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportFinding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub message: String,
    pub relative_path: String,
    pub start_line: u32,
    pub verdict: Verdict,
    pub confidence: FindingConfidence,
    pub evidence_digests: Vec<String>,
}

#[must_use]
pub fn export_sarif(findings: &[ReportFinding]) -> Value {
    let results = findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule_id,
                "level": level(finding.verdict),
                "message": { "text": finding.message },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": finding.relative_path },
                    "region": { "startLine": finding.start_line }
                }}],
                "partialFingerprints": { "edsaFindingId": finding.id },
                "properties": {
                    "edsa.verdict": verdict(finding.verdict),
                    "edsa.confidence": confidence(finding.confidence),
                    "edsa.evidenceDigests": finding.evidence_digests,
                    "edsa.confirmed": finding.verdict == Verdict::Confirmed
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": {
            "name": "Evidence-Driven Security Agent",
            "semanticVersion": env!("CARGO_PKG_VERSION"),
            "informationUri": "https://github.com/"
        }}, "results": results }]
    })
}

/// Validates the SARIF fields emitted by this crate's constrained SARIF profile.
///
/// # Errors
/// Returns an error when required SARIF 2.1.0 structure or EDSA state properties are absent.
pub fn validate_sarif(document: &Value) -> Result<(), SarifValidationError> {
    if document.get("version").and_then(Value::as_str) != Some("2.1.0") {
        return Err(SarifValidationError::Version);
    }
    let runs = document
        .get("runs")
        .and_then(Value::as_array)
        .ok_or(SarifValidationError::Runs)?;
    if runs.is_empty() {
        return Err(SarifValidationError::Runs);
    }
    for result in runs
        .iter()
        .filter_map(|run| run.get("results"))
        .filter_map(Value::as_array)
        .flatten()
    {
        if result.get("ruleId").and_then(Value::as_str).is_none() {
            return Err(SarifValidationError::Result);
        }
        let properties = result
            .get("properties")
            .ok_or(SarifValidationError::State)?;
        if properties
            .get("edsa.verdict")
            .and_then(Value::as_str)
            .is_none()
            || properties
                .get("edsa.confidence")
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(SarifValidationError::State);
        }
        let line = result
            .pointer("/locations/0/physicalLocation/region/startLine")
            .and_then(Value::as_u64)
            .ok_or(SarifValidationError::Location)?;
        if line == 0 {
            return Err(SarifValidationError::Location);
        }
    }
    Ok(())
}

const fn level(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Confirmed => "error",
        Verdict::Rejected => "none",
        Verdict::Inconclusive => "note",
    }
}
const fn verdict(value: Verdict) -> &'static str {
    match value {
        Verdict::Confirmed => "confirmed",
        Verdict::Rejected => "rejected",
        Verdict::Inconclusive => "inconclusive",
    }
}
const fn confidence(value: FindingConfidence) -> &'static str {
    match value {
        FindingConfidence::Low => "low",
        FindingConfidence::Medium => "medium",
        FindingConfidence::High => "high",
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SarifValidationError {
    #[error("SARIF version must be 2.1.0")]
    Version,
    #[error("SARIF must contain at least one run")]
    Runs,
    #[error("SARIF result is missing its rule")]
    Result,
    #[error("SARIF result is missing verdict or confidence state")]
    State,
    #[error("SARIF result location is missing or invalid")]
    Location,
}
