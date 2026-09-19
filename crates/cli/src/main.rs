use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use edsa_cli::{benchmark, patch, resume, run_report, scan};
use edsa_reporting::replay_finding;
use edsa_sandbox::{DockerRunner, SandboxPolicy};
use tokio_util::sync::CancellationToken;

const NAME: &str = "Evidence-Driven Security Agent";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn help() -> String {
    format!(
        "{NAME} {VERSION}\n\
         \n\
         Usage: edsa [OPTIONS] [COMMAND]\n\
         \n\
         Options:\n\
           -h, --help       Print help\n\
           -V, --version    Print version\n\
         \n\
         Commands:\n\
           scan <repository> [options]  Admit a repository and create a durable live run\n\
           resume <run-directory>  Continue unfinished durable work\n\
           inspect <run-or-bundle-path>  Verify every generated report and artifact\n\
           replay <finding-id> [run-or-bundle]  Replay verified evidence without an LLM\n\
           patch <run-directory> <finding-id> --approve  Propose and verify a live patch\n\
           benchmark mock [output]  Run deterministic three-mode evaluation\n\
           benchmark live <output> <token-budget> <cost-microusd>\n\
           benchmark external <output>  Run the installed external analyzer\n\
           benchmark full <output> <tokens> <cost> <turns> <experiments> <timeout-seconds>\n\
           help             Print help\n"
    )
}

async fn run<I>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None | Some("help" | "-h" | "--help") => Ok(help()),
        Some("-V" | "--version") => Ok(format!("edsa {VERSION}\n")),
        Some("scan") => scan_command(args.collect()).await,
        Some("resume") => {
            let path = args
                .next()
                .ok_or_else(|| "resume requires a run directory".to_owned())?;
            if args.next().is_some() {
                return Err("resume accepts exactly one run directory".into());
            }
            resume_command(Path::new(&path)).await
        }
        Some("inspect") => {
            let path = args
                .next()
                .ok_or_else(|| "inspect requires a bundle path".to_owned())?;
            if args.next().is_some() {
                return Err("inspect accepts exactly one bundle path".into());
            }
            let manifest =
                run_report::verify_run(Path::new(&path)).map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&manifest)
                .map(|json| format!("{json}\n"))
                .map_err(|error| error.to_string())
        }
        Some("replay") => {
            let finding_id = args
                .next()
                .ok_or_else(|| "replay requires a finding ID".to_owned())?;
            let bundle = args.next().map(PathBuf::from);
            if args.next().is_some() {
                return Err("replay accepts a finding ID and optional bundle path".into());
            }
            replay(&finding_id, bundle.as_deref()).await
        }
        Some("patch") => patch_command(args.collect()).await,
        Some("benchmark") => benchmark_command(args.collect()).await,
        Some(argument) => Err(format!(
            "unknown argument or command: {argument}\n\n{}",
            help()
        )),
    }
}

async fn patch_command(arguments: Vec<String>) -> Result<String, String> {
    let arguments = patch::parse(arguments).map_err(|error| error.to_string())?;
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    let outcome = patch::execute(arguments, cancellation)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&outcome)
        .map(|json| format!("{json}\n"))
        .map_err(|error| error.to_string())
}

async fn scan_command(arguments: Vec<String>) -> Result<String, String> {
    let arguments = scan::parse(arguments).map_err(|error| error.to_string())?;
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    let outcome = scan::execute(arguments, cancellation)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&outcome)
        .map(|json| format!("{json}\n"))
        .map_err(|error| error.to_string())
}

async fn resume_command(path: &Path) -> Result<String, String> {
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    let outcome = resume::execute(path, cancellation)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&outcome)
        .map(|json| format!("{json}\n"))
        .map_err(|error| error.to_string())
}

async fn benchmark_command(arguments: Vec<String>) -> Result<String, String> {
    let root = PathBuf::from("benchmarks");
    match arguments.as_slice() {
        [mode] if mode == "mock" => {
            let output = PathBuf::from(".edsa/benchmark/mock-results.json");
            let reports = benchmark::run_mock_benchmark(&root).map_err(|error| error.to_string())?;
            benchmark::write_report(&output, &reports).map_err(|error| error.to_string())?;
            Ok(format!("wrote {}\n", output.display()))
        }
        [mode, output] if mode == "mock" => {
            let reports = benchmark::run_mock_benchmark(&root).map_err(|error| error.to_string())?;
            benchmark::write_report(Path::new(output), &reports).map_err(|error| error.to_string())?;
            Ok(format!("wrote {output}\n"))
        }
        [mode, output] if mode == "external" => {
            let report = benchmark::run_external_analyzer_benchmark(&root)
                .await
                .map_err(|error| error.to_string())?;
            benchmark::write_report(Path::new(output), &report)
                .map_err(|error| error.to_string())?;
            Ok(format!("wrote {output}\n"))
        }
        [mode, output, tokens, cost] if mode == "live" => {
            use edsa_model_providers::ConfiguredProvider;
            let provider = ConfiguredProvider::from_environment().map_err(|error| error.to_string())?;
            let maximum_tokens = tokens.parse().map_err(|_| "token budget must be an integer".to_owned())?;
            let maximum_cost_microusd = cost.parse().map_err(|_| "cost budget must be an integer".to_owned())?;
            let report = benchmark::run_live_benchmark(&root, &provider, provider.model(), benchmark::LiveBudget { maximum_tokens, maximum_cost_microusd }).await.map_err(|error| error.to_string())?;
            benchmark::write_report(Path::new(output), &report).map_err(|error| error.to_string())?;
            Ok(format!("wrote {output}\n"))
        }
        [mode, output, tokens, cost, turns, experiments, timeout] if mode == "full" => {
            let budget = benchmark::FullSystemBudget {
                per_case: edsa_core::RunBudget {
                    maximum_model_tokens: tokens
                        .parse()
                        .map_err(|_| "token budget must be an integer")?,
                    maximum_cost_microusd: cost
                        .parse()
                        .map_err(|_| "cost budget must be an integer")?,
                    maximum_turns: turns
                        .parse()
                        .map_err(|_| "turn budget must be an integer")?,
                    maximum_experiments: experiments
                        .parse()
                        .map_err(|_| "experiment budget must be an integer")?,
                    maximum_wall_time_seconds: timeout
                        .parse()
                        .map_err(|_| "timeout must be an integer")?,
                },
                enable_semgrep: false,
            };
            let report = benchmark::run_full_system_benchmark(&root, Path::new(output), budget)
                .await
                .map_err(|error| error.to_string())?;
            let summary = Path::new(output).join("full-system-results.json");
            Ok(format!(
                "completed {} cases and wrote {}\n",
                report.case_count,
                summary.display()
            ))
        }
        _ => Err("usage: edsa benchmark mock [output] | edsa benchmark external <output> | edsa benchmark live <output> <token-budget> <cost-microusd> | edsa benchmark full <output> <tokens> <cost> <turns> <experiments> <timeout-seconds>".into()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1)).await {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

async fn replay(finding_id: &str, bundle: Option<&Path>) -> Result<String, String> {
    if finding_id.is_empty()
        || finding_id.contains(['/', '\\'])
        || finding_id == "."
        || finding_id == ".."
    {
        return Err("finding ID contains unsafe path characters".into());
    }
    let default_bundle = PathBuf::from(".edsa").join("cases").join(finding_id);
    let bundle = bundle.unwrap_or(&default_bundle);
    let repository = match run_report::repository_path(bundle).map_err(|error| error.to_string())? {
        Some(path) => path,
        None => env::current_dir().map_err(|error| error.to_string())?,
    };
    let verified_bundle = run_report::bundle_path(bundle);
    let manifest = run_report::verify_run(bundle).map_err(|error| error.to_string())?;
    let plan = manifest
        .replay_plans
        .iter()
        .find(|plan| plan.finding_id == finding_id)
        .ok_or_else(|| format!("finding was not found: {finding_id}"))?;
    let mut policy = SandboxPolicy::default();
    policy
        .allowed_environment
        .extend(plan.environment.keys().cloned());
    policy
        .allowed_environment
        .insert("EDSA_NEGATIVE_CONTROL".into());
    plan.sandbox_policy.apply_to(&mut policy);
    let evidence = replay_finding(
        &verified_bundle,
        &repository,
        finding_id,
        std::sync::Arc::new(DockerRunner::new(policy)),
        CancellationToken::new(),
    )
    .await
    .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&evidence)
        .map(|json| format!("{json}\n"))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{VERSION, benchmark, run};

    #[tokio::test]
    async fn help_is_the_default() {
        let output = run(Vec::new()).await.expect("help should succeed");
        assert!(output.contains("Usage: edsa"));
        assert!(output.contains("--version"));
    }

    #[tokio::test]
    async fn version_uses_package_metadata() {
        let output = run(["--version".to_owned()])
            .await
            .expect("version should succeed");
        assert_eq!(output, format!("edsa {VERSION}\n"));
    }

    #[tokio::test]
    async fn unknown_arguments_fail() {
        let error = run(["unknown".to_owned()])
            .await
            .expect_err("unknown command should fail");
        assert!(error.contains("unknown argument or command: unknown"));
    }

    #[test]
    fn benchmark_mock_reports_all_three_comparison_modes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks");
        let reports =
            benchmark::run_mock_benchmark(&root).expect("benchmark fixtures should evaluate");
        assert_eq!(reports.len(), 3);
        assert!(reports.iter().all(|report| report.case_count == 18));
        assert!(reports.iter().all(|report| report.schema_version == 1));
    }
}
