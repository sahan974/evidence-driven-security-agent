use std::collections::BTreeMap;
use std::path::Path;

use edsa_adapter_sdk::Oracle;
use edsa_core::{OracleKind, Verdict};
use edsa_reporting::{
    BuilderDescriptor, FindingConfidence, ReplayPlan, ReportFinding, SourceDescriptor, write_bundle,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = Path::new("examples/demo-evidence");
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    write_bundle(
        destination,
        SourceDescriptor {
            repository: "examples/demo-target".into(),
            revision: "committed-demo-v1".into(),
            content_digest: "b1c897456f7ac10b1615b990c90ce1044e4a07d48c828d9b88c7d5cb04e131eb".into(),
        },
        BuilderDescriptor { id: "edsa:demo-generator".into(), version: env!("CARGO_PKG_VERSION").into() },
        vec![ReportFinding {
            id: "demo-path-traversal".into(),
            rule_id: "CWE-22".into(),
            title: "Path traversal demonstration".into(),
            message: "Committed evidence records a deterministic attack/control distinction.".into(),
            relative_path: "examples/demo-target/README.md".into(),
            start_line: 1,
            verdict: Verdict::Confirmed,
            confidence: FindingConfidence::High,
            evidence_digests: Vec::new(),
        }],
        vec![ReplayPlan {
            finding_id: "demo-path-traversal".into(),
            relative_source_root: "examples/demo-target".into(),
            image: "alpine:3.20".into(),
            command: vec![
                "sh".into(),
                "-c".into(),
                "if [ -n \"$EDSA_NEGATIVE_CONTROL\" ]; then echo EDSA_CONTROL_CLEAN; else test -r /workspace/README.md && echo EDSA_REPRODUCED; fi".into(),
            ],
            environment: BTreeMap::new(),
            oracle: Oracle { kind: OracleKind::StdoutPattern, expected: "EDSA_REPRODUCED".into() },
            negative_control: Oracle { kind: OracleKind::StdoutPattern, expected: "EDSA_CONTROL_CLEAN".into() },
        }],
        &[],
        Vec::new(),
    )?;
    println!("generated {}", destination.display());
    Ok(())
}
