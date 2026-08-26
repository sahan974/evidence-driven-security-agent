use std::collections::BTreeMap;

use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, EvidenceId, EvidenceRef, ExperimentId, GateOutcome,
    Hypothesis, HypothesisId, HypothesisState, InvestigationPhase, PatchAttemptId,
    PatchVerification, SCHEMA_VERSION, Signal, SignalId, SignalSource, TransitionError, Verdict,
};
use proptest::prelude::*;

fn hypothesis() -> Hypothesis {
    Hypothesis {
        schema_version: SCHEMA_VERSION,
        id: HypothesisId::new("hyp-1"),
        title: "Untrusted path may escape the workspace".to_owned(),
        claim: "Joining an absolute path discards the configured root".to_owned(),
        weakness: "CWE-22".to_owned(),
        signal_ids: vec![SignalId::new("sig-1")],
    }
}

fn assessment(oracle_passed: bool) -> EvidenceAssessment {
    EvidenceAssessment {
        schema_version: SCHEMA_VERSION,
        baseline_passed: true,
        oracle_passed,
        negative_control_passed: true,
        reproduced_runs: 2,
        evidence: vec![EvidenceRef {
            schema_version: SCHEMA_VERSION,
            id: EvidenceId::new("evidence-1"),
            media_type: "application/json".to_owned(),
            sha256: "abc123".to_owned(),
            size_bytes: 42,
        }],
    }
}

fn passing_patch_gates() -> PatchVerification {
    PatchVerification {
        schema_version: SCHEMA_VERSION,
        build: GateOutcome::Passed,
        original_proof_stopped: GateOutcome::Passed,
        negative_control: GateOutcome::Passed,
        regression_suite: GateOutcome::Passed,
        static_rescan: GateOutcome::Passed,
        variant_search: GateOutcome::Passed,
    }
}

#[test]
fn state_machine_accepts_a_fully_verified_path() {
    let mut state = HypothesisState::new(hypothesis());
    state.begin_investigation().unwrap();
    state.record_experiment(ExperimentId::new("exp-1")).unwrap();
    state.evidence_ready().unwrap();
    let verdict = state
        .decide(&ConfirmationPolicy::default(), &assessment(true))
        .unwrap();
    assert_eq!(verdict, Verdict::Confirmed);

    let patch_id = PatchAttemptId::new("patch-1");
    state.propose_patch(patch_id.clone()).unwrap();
    state
        .verify_patch(&patch_id, &passing_patch_gates())
        .unwrap();
    assert_eq!(state.phase, InvestigationPhase::PatchVerified);
}

#[test]
fn state_machine_rejects_illegal_transitions_with_typed_errors() {
    let mut state = HypothesisState::new(hypothesis());
    assert!(matches!(
        state.evidence_ready(),
        Err(TransitionError::InvalidPhase { .. })
    ));
    state.begin_investigation().unwrap();
    assert_eq!(state.evidence_ready(), Err(TransitionError::NoExperiments));
}

#[test]
fn state_machine_keeps_verdict_and_patch_gates_independent_from_model_output() {
    let policy = ConfirmationPolicy::default();
    assert_eq!(policy.verdict(&assessment(true)), Verdict::Confirmed);
    assert_eq!(policy.verdict(&assessment(false)), Verdict::Rejected);

    let mut evidence_free = assessment(true);
    evidence_free.evidence.clear();
    assert_eq!(policy.verdict(&evidence_free), Verdict::Inconclusive);

    let mut failed = passing_patch_gates();
    failed.regression_suite = GateOutcome::Failed;
    assert!(!failed.all_required_gates_pass());
}

#[test]
fn stable_json_snapshot_uses_schema_versions_and_sorted_metadata() {
    let signal = Signal {
        schema_version: SCHEMA_VERSION,
        id: SignalId::new("sig-1"),
        source: SignalSource::BuiltInRule,
        rule: "path-join".to_owned(),
        relative_path: "src/path.rs".to_owned(),
        start_line: 7,
        message: "Untrusted path reaches a file operation".to_owned(),
        metadata: BTreeMap::from([
            ("analyzer".to_owned(), "edsa".to_owned()),
            ("language".to_owned(), "rust".to_owned()),
        ]),
    };

    let json = serde_json::to_string_pretty(&signal).unwrap();
    assert_eq!(
        json,
        r#"{
  "schema_version": 1,
  "id": "sig-1",
  "source": "built_in_rule",
  "rule": "path-join",
  "relative_path": "src/path.rs",
  "start_line": 7,
  "message": "Untrusted path reaches a file operation",
  "metadata": {
    "analyzer": "edsa",
    "language": "rust"
  }
}"#
    );
}

proptest! {
    #[test]
    fn arbitrary_transition_sequences_never_panic(operations in prop::collection::vec(0_u8..7, 0..100)) {
        let mut state = HypothesisState::new(hypothesis());
        for (index, operation) in operations.into_iter().enumerate() {
            let experiment = ExperimentId::new(format!("exp-{index}"));
            let patch = PatchAttemptId::new("patch-1");
            match operation {
                0 => { let _ = state.begin_investigation(); }
                1 => { let _ = state.record_experiment(experiment); }
                2 => { let _ = state.evidence_ready(); }
                3 => { let _ = state.decide(&ConfirmationPolicy::default(), &assessment(true)); }
                4 => { let _ = state.propose_patch(patch); }
                5 => { let _ = state.verify_patch(&patch, &passing_patch_gates()); }
                _ => { let _ = state.decide(&ConfirmationPolicy::default(), &assessment(false)); }
            }
        }

        prop_assert_eq!(state.schema_version, SCHEMA_VERSION);
        prop_assert_eq!(state.verdict.is_some(), matches!(
            state.phase,
            InvestigationPhase::Decided
                | InvestigationPhase::PatchProposed
                | InvestigationPhase::PatchVerified
        ));
    }
}
