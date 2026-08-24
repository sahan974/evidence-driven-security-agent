//! Unconfirmed security-signal collection and normalization.

mod builtin;
mod sarif;
mod semgrep;

use std::collections::BTreeMap;

use edsa_core::{Signal, SignalId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use builtin::{BuiltinError, collect_builtin_signals};
pub use sarif::{SarifError, import_sarif};
pub use semgrep::{CapabilityLimitation, SemgrepError, SemgrepOptions, run_semgrep};

/// A duplicate group retains each original signal and its complete provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CorrelatedSignals {
    pub correlation_key: String,
    pub signal_ids: Vec<SignalId>,
}

#[must_use]
pub fn correlate_signals(signals: &[Signal]) -> Vec<CorrelatedSignals> {
    let mut groups = BTreeMap::<String, Vec<SignalId>>::new();
    for signal in signals {
        let key = format!(
            "{}:{}:{}",
            signal.relative_path.to_ascii_lowercase(),
            signal.start_line,
            normalized_rule(&signal.rule)
        );
        groups.entry(key).or_default().push(signal.id.clone());
    }
    groups
        .into_iter()
        .filter_map(|(correlation_key, mut signal_ids)| {
            signal_ids.sort();
            signal_ids.dedup();
            (signal_ids.len() > 1).then_some(CorrelatedSignals {
                correlation_key,
                signal_ids,
            })
        })
        .collect()
}

pub(crate) fn signal_id(parts: &[&str]) -> SignalId {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_le_bytes());
        digest.update(part.as_bytes());
    }
    SignalId::new(format!("sig-{:x}", digest.finalize()))
}

fn normalized_rule(rule: &str) -> String {
    rule.rsplit(['/', ':'])
        .next()
        .unwrap_or(rule)
        .to_ascii_lowercase()
        .replace(['_', '-'], "")
}
