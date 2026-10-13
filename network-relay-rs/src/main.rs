use anyhow::{Context, Result, bail};
use network_relay_rs::{
    controller::{Controller, Status},
    model::{Configuration, LogLevel, TransferScope, Transport},
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("network-relay-rs: {error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let mut config = None;
    let mut ca_file = None;
    let mut transport = None;
    let mut duration = None;
    let mut log_level = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" | "-V" => {
                println!(
                    "Network Relay RS {}; core {}; built {}; source {}",
                    network_relay_rs::VERSION,
                    network_relay_rs_core::VERSION,
                    network_relay_rs::BUILD_TIME,
                    network_relay_rs::SOURCE_REVISION
                );
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "Network Relay RS\n\nOn macOS, launch without arguments for the native application.\n\nHeadless SOCKS proxy:\n  network-relay-rs --config FILE [--transport auto|h3|h2|http/1.1]\n                   [--ca-file FILE] [--duration SECONDS] [--log-level LEVEL]\n\nSettings may be an NF-compatible TOML export or a core client.toml.\n--ca-file adds a certificate authority; verification stays enabled.\nHeadless runs do not read or write the application's saved settings.\nLog levels: errors, warnings, normal, detailed, everything.\nQuit a headless proxy with Control-C."
                );
                return Ok(());
            }
            "--config" => config = Some(PathBuf::from(arguments.next().context("--config needs a file path")?)),
            "--ca-file" => ca_file = Some(PathBuf::from(arguments.next().context("--ca-file needs a file path")?)),
            "--duration" => {
                duration = Some(
                    arguments.next().context("--duration needs seconds")?.parse::<u64>().context("invalid duration")?,
                )
            }
            "--transport" => {
                transport = Some(match arguments.next().context("--transport needs a value")?.as_str() {
                    "auto" => Transport::Auto,
                    "h3" => Transport::H3,
                    "h2" => Transport::H2,
                    "http/1.1" => Transport::Http1,
                    _ => bail!("transport must be auto, h3, h2 or http/1.1"),
                })
            }
            "--log-level" => {
                let value = arguments.next().context("--log-level needs a value")?;
                log_level = Some(
                    LogLevel::ALL
                        .into_iter()
                        .find(|level| level.as_str() == value)
                        .context("log level must be errors, warnings, normal, detailed or everything")?,
                );
            }
            _ => bail!("unknown argument {argument}; use --help"),
        }
    }
    if let Some(path) = config {
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut configuration = Configuration::importing(&text, TransferScope::All, &Configuration::default())?;
        if let Some(level) = log_level {
            configuration.log_level = level;
        }
        if let Some(transport) = transport {
            configuration.selected_server_mut().context("no selected server")?.transport = transport;
        }
        return headless(configuration, ca_file, duration);
    }
    if ca_file.is_some() || transport.is_some() || duration.is_some() || log_level.is_some() {
        bail!("headless options require --config FILE");
    }
    #[cfg(target_os = "macos")]
    {
        network_relay_rs::ui::run(Controller::new()?)
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("The graphical application runs on macOS. Use --config FILE for the headless Rust proxy on this host.")
    }
}
fn headless(config: Configuration, ca_file: Option<PathBuf>, duration: Option<u64>) -> Result<()> {
    let mut controller = Controller::with_configuration(config, None, ca_file);
    controller.connect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let started = Instant::now();
        let mut emitted = 0_u64;
        let signal = tokio::signal::ctrl_c();
        tokio::pin!(signal);
        #[cfg(unix)]
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            controller.poll();
            let lines = controller.logs();
            for line in lines.iter().filter(|line| line.sequence > emitted && controller.config.log_level.shows(&line.text)) { println!("{}", line.text); }
            if let Some(last) = lines.last() { emitted = last.sequence; }
            if let Status::Failed(error) = &controller.status { bail!("{error}"); }
            if duration.is_some_and(|seconds| started.elapsed() >= Duration::from_secs(seconds)) { break; }
            #[cfg(unix)]
            tokio::select! { _ = &mut signal => break, _ = terminate.recv() => break, _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
            #[cfg(not(unix))]
            tokio::select! { _ = &mut signal => break, _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
        }
        Ok(())
    });
    controller.stop();
    result
}
