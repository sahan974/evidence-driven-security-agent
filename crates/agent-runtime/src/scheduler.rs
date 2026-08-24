use std::collections::BTreeMap;

use edsa_core::HypothesisId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HypothesisCandidate {
    pub id: HypothesisId,
    pub confidence: u16,
    pub impact: u16,
    pub information_gain: u16,
    pub expected_cost_microusd: u64,
}

impl HypothesisCandidate {
    /// Creates a candidate with scores in the inclusive range `0..=1000`.
    ///
    /// # Errors
    /// Returns an error when a score exceeds 1000.
    pub fn new(
        id: HypothesisId,
        confidence: u16,
        impact: u16,
        information_gain: u16,
        expected_cost_microusd: u64,
    ) -> Result<Self, SchedulerError> {
        if [confidence, impact, information_gain]
            .into_iter()
            .any(|score| score > 1_000)
        {
            return Err(SchedulerError::ScoreOutOfRange);
        }
        Ok(Self {
            id,
            confidence,
            impact,
            information_gain,
            expected_cost_microusd,
        })
    }

    #[must_use]
    pub fn priority(&self) -> i128 {
        i128::from(self.confidence) * i128::from(self.impact)
            + i128::from(self.information_gain) * 1_000
            - i128::from(self.expected_cost_microusd)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisDisposition {
    Queued,
    Running,
    Deferred { reason: String },
    Rejected { reason: String },
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduledHypothesis {
    pub candidate: HypothesisCandidate,
    pub disposition: HypothesisDisposition,
    pub evidence_notes: Vec<String>,
    pub revisit_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceAction {
    Branch {
        parent: HypothesisId,
        children: Vec<HypothesisCandidate>,
        evidence: String,
    },
    Defer {
        id: HypothesisId,
        reason: String,
    },
    Reject {
        id: HypothesisId,
        reason: String,
    },
    Revisit {
        id: HypothesisId,
        evidence: String,
    },
    Complete {
        id: HypothesisId,
        evidence: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct HypothesisScheduler {
    hypotheses: BTreeMap<HypothesisId, ScheduledHypothesis>,
}

impl HypothesisScheduler {
    /// Inserts a new candidate.
    ///
    /// # Errors
    /// Returns an error when the identifier already exists.
    pub fn enqueue(&mut self, candidate: HypothesisCandidate) -> Result<(), SchedulerError> {
        if self.hypotheses.contains_key(&candidate.id) {
            return Err(SchedulerError::Duplicate(candidate.id));
        }
        self.hypotheses.insert(
            candidate.id.clone(),
            ScheduledHypothesis {
                candidate,
                disposition: HypothesisDisposition::Queued,
                evidence_notes: Vec::new(),
                revisit_count: 0,
            },
        );
        Ok(())
    }

    pub fn next_candidate(&mut self) -> Option<HypothesisCandidate> {
        let id = self
            .hypotheses
            .values()
            .filter(|item| item.disposition == HypothesisDisposition::Queued)
            .max_by(|left, right| {
                left.candidate
                    .priority()
                    .cmp(&right.candidate.priority())
                    .then_with(|| right.candidate.id.cmp(&left.candidate.id))
            })?
            .candidate
            .id
            .clone();
        let item = self.hypotheses.get_mut(&id)?;
        item.disposition = HypothesisDisposition::Running;
        Some(item.candidate.clone())
    }

    /// Applies an evidence-driven scheduling decision.
    ///
    /// # Errors
    /// Returns an error for unknown hypotheses or duplicate branch children.
    pub fn apply(&mut self, action: EvidenceAction) -> Result<(), SchedulerError> {
        match action {
            EvidenceAction::Branch {
                parent,
                children,
                evidence,
            } => {
                let parent = self.hypothesis_mut(&parent)?;
                parent.disposition = HypothesisDisposition::Completed;
                parent.evidence_notes.push(evidence);
                for child in children {
                    self.enqueue(child)?;
                }
            }
            EvidenceAction::Defer { id, reason } => {
                self.hypothesis_mut(&id)?.disposition = HypothesisDisposition::Deferred { reason };
            }
            EvidenceAction::Reject { id, reason } => {
                self.hypothesis_mut(&id)?.disposition = HypothesisDisposition::Rejected { reason };
            }
            EvidenceAction::Revisit { id, evidence } => {
                let hypothesis = self.hypothesis_mut(&id)?;
                hypothesis.disposition = HypothesisDisposition::Queued;
                hypothesis.evidence_notes.push(evidence);
                hypothesis.revisit_count = hypothesis.revisit_count.saturating_add(1);
            }
            EvidenceAction::Complete { id, evidence } => {
                let hypothesis = self.hypothesis_mut(&id)?;
                hypothesis.disposition = HypothesisDisposition::Completed;
                hypothesis.evidence_notes.push(evidence);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: &HypothesisId) -> Option<&ScheduledHypothesis> {
        self.hypotheses.get(id)
    }

    fn hypothesis_mut(
        &mut self,
        id: &HypothesisId,
    ) -> Result<&mut ScheduledHypothesis, SchedulerError> {
        self.hypotheses
            .get_mut(id)
            .ok_or_else(|| SchedulerError::Unknown(id.clone()))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SchedulerError {
    #[error("candidate score must be in 0..=1000")]
    ScoreOutOfRange,
    #[error("hypothesis already exists: {0:?}")]
    Duplicate(HypothesisId),
    #[error("hypothesis is unknown: {0:?}")]
    Unknown(HypothesisId),
}
