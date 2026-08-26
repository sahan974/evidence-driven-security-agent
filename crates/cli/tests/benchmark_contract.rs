use std::path::{Path, PathBuf};

use edsa_cli::benchmark::{
    BenchmarkManifest, LiveBudget, case_mount, public_prompt, run_live_benchmark,
    run_mock_benchmark, write_report,
};
use edsa_model_providers::{MockProvider, ModelResponse, TokenUsage};
use serde_json::json;

#[test]
fn benchmark_has_eighteen_isolated_polyglot_cases_and_all_metrics() {
    let root = benchmark_root();
    let reports = run_mock_benchmark(&root).unwrap();
    assert_eq!(reports.len(), 3);
    assert!(reports.iter().all(|report| report.case_count == 18));
    for report in reports {
        let metrics = report.metrics;
        assert!((0.0..=1.0).contains(&metrics.precision));
        assert!((0.0..=1.0).contains(&metrics.recall));
        assert!((0.0..=1.0).contains(&metrics.false_confirmation_rate));
        assert!((0.0..=1.0).contains(&metrics.proof_stability));
        assert!((0.0..=1.0).contains(&metrics.patch_success_rate));
        assert!((0.0..=1.0).contains(&metrics.regression_escape_rate));
        assert!((0.0..=1.0).contains(&metrics.replay_success_rate));
    }
}

#[test]
fn benchmark_ground_truth_never_enters_case_mounts_or_prompts() {
    let root = benchmark_root();
    let manifest: BenchmarkManifest =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let ground_truth = root.join("ground-truth").canonicalize().unwrap();
    for case in &manifest.cases {
        let mount = case_mount(&root, case).unwrap().canonicalize().unwrap();
        assert!(!ground_truth.starts_with(&mount));
        assert!(!mount.starts_with(&ground_truth));
    }
    let prompt = public_prompt(&root, &manifest).unwrap();
    assert!(!prompt.contains("ground-truth"));
    assert!(!prompt.contains("incorrect_patch_trap"));
    assert!(!prompt.contains("vulnerable\":"));
}

#[tokio::test]
async fn benchmark_budgeted_live_mode_writes_versioned_machine_results() {
    let root = benchmark_root();
    let manifest: BenchmarkManifest =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let predictions = manifest
        .cases
        .iter()
        .map(|case| json!({"case_id":case.id,"state":"suspected"}))
        .collect::<Vec<_>>();
    let provider = MockProvider::with_responses(vec![Ok(ModelResponse {
        content: json!({"predictions":predictions}),
        usage: TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
        },
        estimated_cost_microusd: 25,
        provider_request_id: Some("live-budget-fixture".into()),
    })]);
    let report = run_live_benchmark(
        &root,
        &provider,
        "mock-live",
        LiveBudget {
            maximum_tokens: 500,
            maximum_cost_microusd: 100,
        },
    )
    .await
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("live-results-v1.json");
    write_report(&output, &report).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["mode"], "llm_only");
    assert!(json["metrics"]["model_tokens"].as_u64().unwrap() > 0);
    assert!(json["metrics"]["api_cost_microusd"].as_u64().unwrap() > 0);
}

fn benchmark_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks")
        .canonicalize()
        .unwrap()
}
