use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ConfirmationPolicy, EvidenceAssessment, ExperimentId, Hypothesis, PatchAttemptId,
    PatchVerification, SCHEMA_VERSION, Verdict,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationPhase {
    Proposed,
    Investigating,
    EvidenceReady,
    Decided,
    PatchProposed,
    PatchVerified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HypothesisState {
    pub schema_version: u16,
    pub hypothesis: Hypothesis,
    pub phase: InvestigationPhase,
    pub experiments: Vec<ExperimentId>,
    pub verdict: Option<Verdict>,
    pub patch_attempt: Option<PatchAttemptId>,
}

impl HypothesisState {
    #[must_use]
    pub const fn new(hypothesis: Hypothesis) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            hypothesis,
            phase: InvestigationPhase::Proposed,
            experiments: Vec::new(),
            verdict: None,
            patch_attempt: None,
        }
    }

    /// Starts deterministic investigation work.
    ///
    /// # Errors
    /// Returns [`TransitionError::InvalidPhase`] unless the hypothesis is proposed.
    pub fn begin_investigation(&mut self) -> Result<(), TransitionError> {
        self.require_phase(InvestigationPhase::Proposed)?;
        self.phase = InvestigationPhase::Investigating;
        Ok(())
    }

    /// Records a unique experiment executed for this hypothesis.
    ///
    /// # Errors
    /// Returns an error outside the investigating phase or when `id` is duplicated.
    pub fn record_experiment(&mut self, id: ExperimentId) -> Result<(), TransitionError> {
        self.require_phase(InvestigationPhase::Investigating)?;
        if self.experiments.contains(&id) {
            return Err(TransitionError::DuplicateExperiment(id));
        }
        self.experiments.push(id);
        Ok(())
    }

    /// Closes experiment collection and makes the evidence decidable.
    ///
    /// # Errors
    /// Returns an error outside the investigating phase or if no experiment exists.
    pub fn evidence_ready(&mut self) -> Result<(), TransitionError> {
        self.require_phase(InvestigationPhase::Investigating)?;
        if self.experiments.is_empty() {
            return Err(TransitionError::NoExperiments);
        }
        self.phase = InvestigationPhase::EvidenceReady;
        Ok(())
    }

    /// Assigns a verdict solely through the supplied deterministic policy and evidence.
    ///
    /// # Errors
    /// Returns [`TransitionError::InvalidPhase`] unless evidence is ready.
    pub fn decide(
        &mut self,
        policy: &ConfirmationPolicy,
        assessment: &EvidenceAssessment,
    ) -> Result<Verdict, TransitionError> {
        self.require_phase(InvestigationPhase::EvidenceReady)?;
        let verdict = policy.verdict(assessment);
        self.verdict = Some(verdict);
        self.phase = InvestigationPhase::Decided;
        Ok(verdict)
    }

    /// Associates a patch attempt with a confirmed hypothesis.
    ///
    /// # Errors
    /// Returns an error unless the hypothesis is decided and confirmed.
    pub fn propose_patch(&mut self, id: PatchAttemptId) -> Result<(), TransitionError> {
        self.require_phase(InvestigationPhase::Decided)?;
        if self.verdict != Some(Verdict::Confirmed) {
            return Err(TransitionError::PatchRequiresConfirmedVerdict);
        }
        self.patch_attempt = Some(id);
        self.phase = InvestigationPhase::PatchProposed;
        Ok(())
    }

    /// Marks the proposed patch verified when every deterministic gate passes.
    ///
    /// # Errors
    /// Returns an error for the wrong phase, a mismatched attempt, or any failed gate.
    pub fn verify_patch(
        &mut self,
        id: &PatchAttemptId,
        verification: &PatchVerification,
    ) -> Result<(), TransitionError> {
        self.require_phase(InvestigationPhase::PatchProposed)?;
        if self.patch_attempt.as_ref() != Some(id) {
            return Err(TransitionError::PatchAttemptMismatch);
        }
        if !verification.all_required_gates_pass() {
            return Err(TransitionError::PatchGatesFailed);
        }
        self.phase = InvestigationPhase::PatchVerified;
        Ok(())
    }

    fn require_phase(&self, expected: InvestigationPhase) -> Result<(), TransitionError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(TransitionError::InvalidPhase {
                expected,
                actual: self.phase,
            })
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransitionError {
    #[error("invalid phase: expected {expected:?}, found {actual:?}")]
    InvalidPhase {
        expected: InvestigationPhase,
        actual: InvestigationPhase,
    },
    #[error("experiment {0:?} is already recorded")]
    DuplicateExperiment(ExperimentId),
    #[error("evidence cannot be ready until an experiment is recorded")]
    NoExperiments,
    #[error("a patch can only be proposed for a confirmed hypothesis")]
    PatchRequiresConfirmedVerdict,
    #[error("patch attempt does not match the proposed patch")]
    PatchAttemptMismatch,
    #[error("one or more deterministic patch gates failed")]
    PatchGatesFailed,
}
