use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use edsa_reporting::{replay_finding, verify_bundle};
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
           inspect <bundle-path>  Verify and inspect an evidence case\n\
           replay <finding-id>    Replay .edsa/cases/<finding-id> without an LLM\n\
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
        Some("inspect") => {
            let path = args
                .next()
                .ok_or_else(|| "inspect requires a bundle path".to_owned())?;
            if args.next().is_some() {
                return Err("inspect accepts exactly one bundle path".into());
            }
            let manifest = verify_bundle(Path::new(&path)).map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&manifest)
                .map(|json| format!("{json}\n"))
                .map_err(|error| error.to_string())
        }
        Some("replay") => {
            let finding_id = args
                .next()
                .ok_or_else(|| "replay requires a finding ID".to_owned())?;
            if args.next().is_some() {
                return Err("replay accepts exactly one finding ID".into());
            }
            replay(&finding_id).await
        }
        Some(argument) => Err(format!(
            "unknown argument or command: {argument}\n\n{}",
            help()
        )),
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

async fn replay(finding_id: &str) -> Result<String, String> {
    if finding_id.is_empty()
        || finding_id.contains(['/', '\\'])
        || finding_id == "."
        || finding_id == ".."
    {
        return Err("finding ID contains unsafe path characters".into());
    }
    let repository = env::current_dir().map_err(|error| error.to_string())?;
    let bundle = PathBuf::from(".edsa").join("cases").join(finding_id);
    let manifest = verify_bundle(&bundle).map_err(|error| error.to_string())?;
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
    let evidence = replay_finding(
        &bundle,
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
    use super::{VERSION, run};

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
        let error = run(["scan".to_owned()])
            .await
            .expect_err("unknown command should fail");
        assert!(error.contains("unknown argument or command: scan"));
    }
}
