use std::fs;

use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, EvidenceId, EvidenceRef, ExperimentId, GateOutcome,
    Hypothesis, HypothesisId, InvestigationPhase, PatchAttemptId, PatchVerification,
    SCHEMA_VERSION, SignalId, Verdict,
};
use edsa_evidence::{ArtifactError, ArtifactStore, EventKind, Ledger, LedgerError};
use tempfile::tempdir;

fn hypothesis() -> Hypothesis {
    Hypothesis {
        schema_version: SCHEMA_VERSION,
        id: HypothesisId::new("hyp-1"),
        title: "Traversal".to_owned(),
        claim: "A crafted path escapes the root".to_owned(),
        weakness: "CWE-22".to_owned(),
        signal_ids: vec![SignalId::new("sig-1")],
    }
}

fn assessment() -> EvidenceAssessment {
    EvidenceAssessment {
        schema_version: SCHEMA_VERSION,
        baseline_passed: true,
        oracle_passed: true,
        negative_control_passed: true,
        reproduced_runs: 2,
        evidence: vec![EvidenceRef {
            schema_version: SCHEMA_VERSION,
            id: EvidenceId::new("ev-1"),
            media_type: "text/plain".to_owned(),
            sha256: "a".repeat(64),
            size_bytes: 10,
        }],
    }
}

fn gates() -> PatchVerification {
    PatchVerification {
        schema_version: SCHEMA_VERSION,
        build: GateOutcome::Passed,
        original_proof_stopped: GateOutcome::Passed,
        negative_control: GateOutcome::Passed,
        regression_suite: GateOutcome::Passed,
        static_rescan: GateOutcome::Passed,
    }
}

fn complete_events(ledger: &Ledger) -> Vec<edsa_evidence::InvestigationEvent> {
    let mut events: Vec<edsa_evidence::InvestigationEvent> = Vec::new();
    let kinds = [
        EventKind::HypothesisProposed(hypothesis()),
        EventKind::InvestigationStarted,
        EventKind::ExperimentRecorded {
            id: ExperimentId::new("exp-1"),
        },
        EventKind::EvidenceReady,
        EventKind::VerdictAssigned {
            policy: ConfirmationPolicy::default(),
            assessment: assessment(),
            verdict: Verdict::Confirmed,
        },
        EventKind::PatchProposed {
            id: PatchAttemptId::new("patch-1"),
        },
        EventKind::PatchVerified {
            id: PatchAttemptId::new("patch-1"),
            verification: gates(),
        },
    ];
    for (index, kind) in kinds.into_iter().enumerate() {
        let event = if let Some(previous) = events.last() {
            edsa_evidence::InvestigationEvent::new(
                u64::try_from(index + 1).unwrap(),
                format!("event-{}", index + 1),
                "hyp-1",
                &previous.event_hash,
                kind,
            )
            .unwrap()
        } else {
            ledger.next_event("event-1", "hyp-1", kind).unwrap()
        };
        events.push(event);
    }
    events
}

#[test]
fn database_jsonl_roundtrip_reconstructs_identical_state() {
    let directory = tempdir().unwrap();
    let mut source = Ledger::open(directory.path().join("source.db")).unwrap();
    source.append(&complete_events(&source)).unwrap();
    let expected = source.reconstruct().unwrap();
    assert_eq!(expected.phase, InvestigationPhase::PatchVerified);

    let mut jsonl = Vec::new();
    source.export_jsonl(&mut jsonl).unwrap();
    let mut destination = Ledger::open(directory.path().join("destination.db")).unwrap();
    destination.import_jsonl(jsonl.as_slice()).unwrap();

    assert_eq!(destination.events().unwrap(), source.events().unwrap());
    assert_eq!(destination.reconstruct().unwrap(), expected);
}

#[test]
fn duplicate_event_fails_without_partial_append() {
    let directory = tempdir().unwrap();
    let mut ledger = Ledger::open(directory.path().join("events.db")).unwrap();
    let events = complete_events(&ledger);
    ledger.append(&events).unwrap();
    let result = ledger.append(&[events[0].clone()]);
    assert!(result.is_err());
    assert_eq!(ledger.events().unwrap().len(), events.len());
}

#[test]
fn corrupted_jsonl_hash_fails_safely() {
    let directory = tempdir().unwrap();
    let source = Ledger::open(directory.path().join("source.db")).unwrap();
    let mut events = complete_events(&source);
    events[0].event_hash = "f".repeat(64);
    let json = format!("{}\n", serde_json::to_string(&events[0]).unwrap());
    let mut destination = Ledger::open(directory.path().join("destination.db")).unwrap();
    assert!(matches!(
        destination.import_jsonl(json.as_bytes()),
        Err(LedgerError::HashChain(1))
    ));
    assert!(destination.events().unwrap().is_empty());
}

#[test]
fn corrupted_sqlite_metadata_is_detected() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("events.db");
    let mut ledger = Ledger::open(&database).unwrap();
    ledger.append(&complete_events(&ledger)).unwrap();
    drop(ledger);

    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE events SET event_hash = ?1 WHERE sequence = 1",
            ["f".repeat(64)],
        )
        .unwrap();
    drop(connection);

    let ledger = Ledger::open(&database).unwrap();
    assert!(matches!(
        ledger.events(),
        Err(LedgerError::StorageMetadata(1))
    ));
}

#[test]
fn artifacts_are_immutable_and_detect_hash_drift() {
    let directory = tempdir().unwrap();
    let store = ArtifactStore::open(directory.path().join("artifacts")).unwrap();
    let stored = store.put(b"proof").unwrap();
    assert_eq!(store.put(b"proof").unwrap(), stored);
    assert_eq!(store.get(&stored.sha256).unwrap(), b"proof");

    fs::write(store.path_for_digest(&stored.sha256).unwrap(), b"tampered").unwrap();
    assert!(matches!(
        store.get(&stored.sha256),
        Err(ArtifactError::HashDrift(_))
    ));
}

#[test]
fn traversal_shaped_digests_are_rejected() {
    let directory = tempdir().unwrap();
    let store = ArtifactStore::open(directory.path().join("artifacts")).unwrap();
    for malicious in ["../secret", "..\\secret", "/absolute"] {
        assert!(matches!(
            store.path_for_digest(malicious),
            Err(ArtifactError::InvalidDigest(_))
        ));
    }
}
