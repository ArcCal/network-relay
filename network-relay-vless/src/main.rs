//! `network-relay-vless`: network-relay, with every tunnel carried through
//! a downstream VLESS server instead of the host's own network.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use network_relay::{cli, logging, server};
use network_relay_vless::{config, FileConfig, VlessEgress};

/// The relay settings of the configuration file, which is all `profile
/// --publish` needs.
fn relay_settings(path: &Path) -> anyhow::Result<network_relay::config::Config> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    config::relay_settings(&text).map_err(|e| e.context(format!("loading configuration {}", path.display())))
}

const NAME: &str = "network-relay-vless";
const DEFAULT_CONFIG: &str = "config/relay.toml";
const PROGRAM: cli::Program = cli::Program { name: NAME, default_config: DEFAULT_CONFIG, load_config: relay_settings };

#[derive(Parser)]
#[command(
    version,
    about = "Relay for Apple's Network Relay whose tunnels go through a VLESS server: HTTP CONNECT (TCP) and CONNECT-UDP (RFC 9298) over HTTP/3, HTTP/2 and HTTP/1.1"
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
        /// Configuration file: the relay settings, users and [vless], in one file.
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Only check the configuration, certificate and website, then exit.
        #[arg(long)]
        check: bool,
    },
    #[command(flatten)]
    Tool(cli::Tools),
}

/// network-relay's commands, with this program's name and configuration file
/// where they mention them.
fn command() -> clap::Command {
    Cli::command().mut_subcommand("profile", |profile| {
        profile
            .mut_arg("config", |a| a.default_value(DEFAULT_CONFIG))
            .mut_arg("user", |a| a.help(format!("User name, as created with `{NAME} passwd`")))
            .mut_arg("identity", |a| {
                a.help(format!(
                    "Authenticate with this client identity (PKCS#12 from `{NAME} identity`) instead of a password; \
                     with --password as well, the profile carries both"
                ))
            })
    })
}

fn main() -> ExitCode {
    let cli = match Cli::from_arg_matches(&command().get_matches()) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    let result = match cli.command {
        Command::Serve { config, check } => return serve(config, check),
        Command::Tool(tool) => tool.run(&PROGRAM),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("{NAME}: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn serve(path: PathBuf, check_only: bool) -> ExitCode {
    // Until logging is set up, errors can only go to stderr.
    let fail = |e: anyhow::Error| {
        eprintln!("{NAME}: {e:#}");
        ExitCode::FAILURE
    };
    let FileConfig { relay: config, vless: vless_config, vless_settings } = match FileConfig::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let warnings = [format!(
        "the connection to the VLESS server {}:{} is a plaintext WebSocket: its user ID, every destination and \
         all relayed traffic can be read and changed on the way; use it only over a network you trust",
        vless_config.server_host, vless_config.server_port
    )];
    for w in &warnings {
        eprintln!("{NAME}: warning: {w}");
    }
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
    let _logs = match logging::init(NAME, config.log_dir.as_deref()) {
        Ok(guard) => guard,
        Err(e) => return fail(e),
    };
    for w in &warnings {
        tracing::warn!("{w}");
    }
    let rt = match cli::runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(e),
    };
    let result = rt.block_on(async {
        let vless = Arc::new(VlessEgress::new(vless_config));
        // Tunnels open their own VLESS connections, so the relay starts even
        // when this fails; until the server answers, tunnels are refused.
        match vless.probe().await {
            Ok(()) => tracing::info!("VLESS egress ready (a DNS query went through it); no direct fallback"),
            Err(e) => tracing::warn!("VLESS egress check failed: {e}; tunnels fail until it works; no direct fallback"),
        }
        let reload = move |path: &Path| {
            let next = FileConfig::load(path)?;
            if next.vless_settings != vless_settings {
                tracing::warn!("[vless] changes take effect after a restart; keeping the VLESS settings in use");
            }
            Ok(next.relay)
        };
        let variant = server::Variant {
            name: NAME,
            version: env!("CARGO_PKG_VERSION"),
            egress: vless,
            load_config: Arc::new(reload),
        };
        server::run_variant(path, config, variant).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
