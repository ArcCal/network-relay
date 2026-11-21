//! `network-relay-cf-masque`: network-relay, with every tunnel carried
//! through Cloudflare WARP (MASQUE) instead of the host's own network.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use network_relay::{cli, logging, server};
use warp_masque_egress::WarpEgress;

mod gateway_config;

use gateway_config::GatewayConfig;

/// The relay settings of the configuration file, which is all `profile
/// --publish` needs.
fn relay_settings(path: &Path) -> anyhow::Result<network_relay::config::Config> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    gateway_config::relay_settings(&text).map_err(|e| e.context(format!("loading configuration {}", path.display())))
}

const NAME: &str = "network-relay-cf-masque";
const DEFAULT_CONFIG: &str = "config/relay.toml";
const PROGRAM: cli::Program = cli::Program { name: NAME, default_config: DEFAULT_CONFIG, load_config: relay_settings };

#[derive(Parser)]
#[command(
    version,
    about = "Experimental WARP-egress relay for Apple's Network Relay: HTTP CONNECT (TCP) and CONNECT-UDP (RFC 9298) over HTTP/3, HTTP/2 and HTTP/1.1"
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
        /// Configuration file: the relay settings, users and [warp], in one file.
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
    let GatewayConfig { relay: config, warp: warp_config, warp_settings } = match GatewayConfig::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let total = config.relay.max_tunnels();
    let per_user = config.relay.max_tunnels_per_user;
    let mut warnings = warp_config.warnings();
    if (total, per_user) == (48, 32) {
        warnings.push(
            "tunnel limits match the old example (48 total, 32 per user). If copied unintentionally, remove \
             both max_tunnels and max_tunnels_per_user from [relay], run serve --check and restart to use the defaults."
                .into(),
        );
    }
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
                    "{}: configuration, certificate and website are fine; users: {}; tunnel limits: {total} total, {per_user} per user",
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
        let warp = Arc::new(WarpEgress::connect(&warp_config).await?);
        tracing::info!(transport = %warp.status().transport, "WARP egress ready; no direct fallback");
        let reload = move |path: &Path| {
            let next = GatewayConfig::load(path)?;
            if next.warp_settings != warp_settings {
                tracing::warn!("[warp] changes take effect after a restart; keeping the WARP settings in use");
            }
            Ok(next.relay)
        };
        let variant = server::Variant {
            name: NAME,
            version: env!("CARGO_PKG_VERSION"),
            egress: warp.clone(),
            load_config: Arc::new(reload),
        };
        let result = server::run_variant(path, config, variant).await;
        if result.is_err() {
            if let Some(why) = warp.status().failure {
                tracing::error!("WARP egress closed: {why}");
            }
        }
        warp.shutdown().await;
        result
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
