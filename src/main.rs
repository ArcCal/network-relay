//! `network-relay`: the relay server and its helper commands.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use network_relay::config::{self, Config};
use network_relay::{cli, logging, server};

#[derive(Parser)]
#[command(
    version,
    about = "Relay server for Apple's Network Relay: HTTP CONNECT (TCP) and CONNECT-UDP (RFC 9298) over HTTP/3, HTTP/2 and HTTP/1.1"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// Parsed once, at start-up.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run the relay. SIGHUP reloads users, destination rules, the website and the certificate.
    Serve {
        /// Configuration file.
        #[arg(short, long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        /// Only check the configuration, certificate and website, then exit.
        #[arg(long)]
        check: bool,
    },
    #[command(flatten)]
    Tool(cli::Tools),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve { config, check } => return serve(config, check),
        Command::Tool(tool) => tool.run(&cli::NETWORK_RELAY),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("network-relay: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn serve(path: PathBuf, check_only: bool) -> ExitCode {
    // Until logging is set up, errors can only go to stderr.
    let fail = |e: anyhow::Error| {
        eprintln!("network-relay: {e:#}");
        ExitCode::FAILURE
    };
    let config = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    if check_only {
        let checked = (|| {
            network_relay::certs::CertStore::check_files(&config.tls.cert, &config.tls.key)?;
            cli::runtime()?.block_on(async { server::Relay::new(&config).map(|_| ()) })
        })();
        return match checked {
            Ok(()) => {
                println!(
                    "{}: configuration, certificate and website are fine; users: {}",
                    path.display(),
                    config.users.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        };
    }
    // Kept until exit, so buffered log lines are written out.
    let _logs = match logging::init("network-relay", config.log_dir.as_deref()) {
        Ok(guard) => guard,
        Err(e) => return fail(e),
    };
    let rt = match cli::runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(e),
    };
    match rt.block_on(server::run(path, config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
