use std::env;
use std::process::ExitCode;

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
           help             Print help\n"
    )
}

fn run<I>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None | Some("help" | "-h" | "--help") => Ok(help()),
        Some("-V" | "--version") => Ok(format!("edsa {VERSION}\n")),
        Some(argument) => Err(format!(
            "unknown argument or command: {argument}\n\n{}",
            help()
        )),
    }
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
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

#[cfg(test)]
mod tests {
    use super::{VERSION, run};

    #[test]
    fn help_is_the_default() {
        let output = run(Vec::new()).expect("help should succeed");
        assert!(output.contains("Usage: edsa"));
        assert!(output.contains("--version"));
    }

    #[test]
    fn version_uses_package_metadata() {
        let output = run(["--version".to_owned()]).expect("version should succeed");
        assert_eq!(output, format!("edsa {VERSION}\n"));
    }

    #[test]
    fn unknown_arguments_fail() {
        let error = run(["scan".to_owned()]).expect_err("unknown command should fail");
        assert!(error.contains("unknown argument or command: scan"));
    }
}
