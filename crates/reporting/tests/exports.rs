use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edsa_adapter_sdk::{Oracle, SandboxBackend};
use edsa_core::{OracleKind, Verdict};
use edsa_reporting::{
    BuilderDescriptor, BundleArtifactInput, FindingConfidence, ReplayPlan, ReportFinding,
    SourceDescriptor, export_sarif, replay_finding, validate_sarif, verify_bundle, write_bundle,
};
use edsa_sandbox::docker::SandboxError;
use edsa_sandbox::{SandboxOutput, SandboxRequest};
use tokio_util::sync::CancellationToken;

#[test]
fn sarif_profile_has_version_locations_verdicts_and_confidence() {
    let profile: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/sarif-profile.json")).unwrap();
    let sarif = export_sarif(&[
        finding("confirmed", Verdict::Confirmed, FindingConfidence::High),
        finding(
            "supported",
            Verdict::Inconclusive,
            FindingConfidence::Medium,
        ),
    ]);
    validate_sarif(&sarif).unwrap();
    for key in profile["requiredTopLevel"].as_array().unwrap() {
        assert!(sarif.get(key.as_str().unwrap()).is_some());
    }
    assert_eq!(sarif["version"], profile["version"]);
    let results = sarif
        .pointer("/runs/0/results")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(results[0]["properties"]["edsa.verdict"], "confirmed");
    assert_eq!(results[1]["properties"]["edsa.verdict"], "inconclusive");
    assert_ne!(
        results[0]["properties"]["edsa.confidence"],
        results[1]["properties"]["edsa.confidence"]
    );
}

#[test]
fn bundle_exports_all_formats_and_verifies_offline() {
    let directory = tempfile::tempdir().unwrap();
    let mut report = finding("finding-1", Verdict::Confirmed, FindingConfidence::High);
    report.evidence_digests = vec![digest(b"proof")];
    let manifest = write_bundle(
        directory.path(),
        source(),
        builder(),
        vec![report],
        vec![plan("finding-1")],
        &[],
        vec![BundleArtifactInput {
            logical_name: "proof-output".into(),
            media_type: "text/plain".into(),
            bytes: b"proof".to_vec(),
        }],
    )
    .unwrap();
    assert_eq!(verify_bundle(directory.path()).unwrap(), manifest);
    for path in [
        "manifest.json",
        "attestation.json",
        "events.jsonl",
        "reports/results.sarif",
        "reports/summary.md",
    ] {
        assert!(directory.path().join(path).is_file());
    }
    let attestation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("attestation.json")).unwrap())
            .unwrap();
    assert_eq!(attestation["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(attestation["predicate"]["source"]["revision"], "abc123");
    assert_eq!(attestation["predicate"]["builder"]["id"], "edsa:test");
    assert_eq!(
        attestation["predicate"]["commands"][0][0],
        "fixture-command"
    );
}

#[test]
fn tampered_artifact_fails_offline_verification_clearly() {
    let directory = tempfile::tempdir().unwrap();
    let mut report = finding("finding-1", Verdict::Confirmed, FindingConfidence::High);
    report.evidence_digests = vec![digest(b"original")];
    let manifest = write_bundle(
        directory.path(),
        source(),
        builder(),
        vec![report],
        vec![plan("finding-1")],
        &[],
        vec![BundleArtifactInput {
            logical_name: "proof".into(),
            media_type: "text/plain".into(),
            bytes: b"original".to_vec(),
        }],
    )
    .unwrap();
    std::fs::write(
        directory.path().join(&manifest.artifacts[0].relative_path),
        b"tampered",
    )
    .unwrap();
    let error = verify_bundle(directory.path()).unwrap_err();
    assert!(error.to_string().contains("digest or size mismatch"));
}

#[derive(Debug)]
struct ReplayBackend {
    calls: Mutex<Vec<SandboxRequest>>,
    outputs: Mutex<Vec<SandboxOutput>>,
}

#[async_trait]
impl SandboxBackend for ReplayBackend {
    async fn run(
        &self,
        request: SandboxRequest,
        _cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError> {
        self.calls.lock().unwrap().push(request);
        Ok(self.outputs.lock().unwrap().remove(0))
    }
}

#[tokio::test]
async fn replay_uses_only_verified_adapter_metadata_and_reproduces_oracle() {
    let directory = tempfile::tempdir().unwrap();
    let repository = tempfile::tempdir().unwrap();
    write_bundle(
        directory.path(),
        source(),
        builder(),
        vec![finding(
            "finding-1",
            Verdict::Confirmed,
            FindingConfidence::High,
        )],
        vec![plan("finding-1")],
        &[],
        Vec::new(),
    )
    .unwrap();
    let backend = Arc::new(ReplayBackend {
        calls: Mutex::new(Vec::new()),
        outputs: Mutex::new(vec![
            output("EDSA_REPRODUCED"),
            output("EDSA_CONTROL_CLEAN"),
        ]),
    });
    let evidence = replay_finding(
        directory.path(),
        repository.path(),
        "finding-1",
        backend.clone(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(evidence.oracle_passed);
    assert!(evidence.negative_control_passed);
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].command, ["fixture-command", "--replay"]);
    assert_eq!(calls[1].environment["EDSA_NEGATIVE_CONTROL"], "1");
}

#[tokio::test]
async fn tampered_bundle_is_rejected_before_replay_execution() {
    let directory = tempfile::tempdir().unwrap();
    let repository = tempfile::tempdir().unwrap();
    write_bundle(
        directory.path(),
        source(),
        builder(),
        vec![finding(
            "finding-1",
            Verdict::Confirmed,
            FindingConfidence::High,
        )],
        vec![plan("finding-1")],
        &[],
        Vec::new(),
    )
    .unwrap();
    std::fs::write(directory.path().join("reports/summary.md"), b"tampered").unwrap();
    let backend = Arc::new(ReplayBackend {
        calls: Mutex::new(Vec::new()),
        outputs: Mutex::new(Vec::new()),
    });
    assert!(
        replay_finding(
            directory.path(),
            repository.path(),
            "finding-1",
            backend.clone(),
            CancellationToken::new()
        )
        .await
        .is_err()
    );
    assert!(backend.calls.lock().unwrap().is_empty());
}

fn finding(id: &str, verdict: Verdict, confidence: FindingConfidence) -> ReportFinding {
    ReportFinding {
        id: id.into(),
        rule_id: "CWE-22".into(),
        title: "Path traversal".into(),
        message: "Executable evidence observed".into(),
        relative_path: "src/app.rs".into(),
        start_line: 12,
        verdict,
        confidence,
        evidence_digests: Vec::new(),
    }
}

fn plan(id: &str) -> ReplayPlan {
    ReplayPlan {
        finding_id: id.into(),
        relative_source_root: ".".into(),
        image: "fixture:local".into(),
        command: vec!["fixture-command".into(), "--replay".into()],
        environment: BTreeMap::new(),
        oracle: Oracle {
            kind: OracleKind::StdoutPattern,
            expected: "EDSA_REPRODUCED".into(),
        },
        negative_control: Oracle {
            kind: OracleKind::StdoutPattern,
            expected: "EDSA_CONTROL_CLEAN".into(),
        },
    }
}

fn source() -> SourceDescriptor {
    SourceDescriptor {
        repository: "fixture".into(),
        revision: "abc123".into(),
        content_digest: "b".repeat(64),
    }
}
fn builder() -> BuilderDescriptor {
    BuilderDescriptor {
        id: "edsa:test".into(),
        version: "0.1.0".into(),
    }
}
fn output(marker: &str) -> SandboxOutput {
    SandboxOutput {
        container_name: "mock".into(),
        exit_code: Some(0),
        stdout: marker.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
