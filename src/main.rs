use std::{env, process::ExitCode};

const HELP: &str = "zminidump [--help | --version]\n\nProject skeleton. See the repository documentation for the implementation plan.";

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();

    match args.as_slice() {
        [] => println!("{HELP}"),
        [arg] if arg == "-h" || arg == "--help" => println!("{HELP}"),
        [arg] if arg == "-V" || arg == "--version" => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        }
        _ => {
            eprintln!("Unsupported arguments. Run zminidump --help for available options.");
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}
