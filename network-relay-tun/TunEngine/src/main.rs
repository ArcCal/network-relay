//! Unprivileged worker. Only an already-open utun descriptor is accepted.
#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use network_relay_tun_engine::{CancellationToken, run_with_mtu};
    use std::io::Write;
    if unsafe { libc::geteuid() } == 0 {
        return Err("the packet worker must not run as root".into());
    }
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 2 {
        return Err("expected local SOCKS port and MTU; utun is descriptor 3".into());
    }
    let port: u16 = arguments[0].parse()?;
    let mtu: u16 = arguments[1].parse()?;
    if port == 0 || !(1280..=9000).contains(&mtu) {
        return Err("invalid worker configuration".into());
    }
    let mut configuration = tun::Configuration::default();
    configuration.raw_fd(3).close_fd_on_drop(true).mtu(mtu);
    configuration.platform_config(|platform| {
        platform.packet_information(true);
    });
    let device = tun::create_as_async(&configuration)?;
    let stop = CancellationToken::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    println!("READY");
    std::io::stdout().flush()?;
    let work = run_with_mtu(device, ([127, 0, 0, 1], port).into(), mtu, stop.clone());
    tokio::pin!(work);
    let parent_stop = stop.clone();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut byte = [0u8; 1];
        let _ = std::io::stdin().read(&mut byte);
        parent_stop.cancel();
    });
    tokio::select! {
        result = &mut work => { result?; },
        _ = terminate.recv() => { stop.cancel(); work.await?; },
        _ = interrupt.recv() => { stop.cancel(); work.await?; },
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("The utun worker requires macOS; portable packet tests remain available.");
    std::process::exit(1);
}
