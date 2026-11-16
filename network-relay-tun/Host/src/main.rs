#[cfg(target_os = "macos")]
mod mac {
    use anyhow::{Context, Result, ensure};
    use network_relay_tun_host::{
        backend::{DIRECTORY, MacBackend},
        broker::{Broker, Status},
        ipc,
        protocol::Request,
    };
    use serde::Serialize;
    use std::{
        fs::OpenOptions,
        os::{
            fd::AsRawFd,
            unix::{
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
                net::UnixListener,
            },
        },
        path::Path,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn stop(_: i32) {
        STOP.store(true, Ordering::Relaxed);
    }
    #[derive(Serialize)]
    struct Reply {
        ok: bool,
        status: Status,
        error: String,
        version: &'static str,
    }
    pub fn control() -> Result<()> {
        use std::io::{BufRead, Read, Write};
        use std::os::unix::net::UnixStream;
        let mut socket = UnixStream::connect(Path::new(DIRECTORY).join("control.sock"))?;
        let mut uid = u32::MAX;
        let mut gid = u32::MAX;
        ensure!(
            unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } == 0 && uid == 0,
            "control peer is not the installed root helper"
        );
        socket.set_read_timeout(Some(Duration::from_secs(120)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut input = std::io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let count = (&mut input).take(4097).read_until(b'\n', &mut line)?;
            if count == 0 {
                break;
            }
            ensure!(count <= 4096 && line.last() == Some(&b'\n'), "invalid control frame");
            let request = network_relay_tun_host::protocol::decode(&line)?;
            ipc::write_reply(&mut socket, &request)?;
            let mut length = [0; 4];
            socket.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            ensure!(length > 0 && length <= 4096, "invalid helper reply");
            let mut reply = vec![0; length];
            socket.read_exact(&mut reply)?;
            let _: serde_json::Value = serde_json::from_slice(&reply)?;
            std::io::stdout().write_all(&reply)?;
            std::io::stdout().write_all(b"\n")?;
            std::io::stdout().flush()?;
        }
        Ok(())
    }
    pub fn run() -> Result<()> {
        ensure!(unsafe { libc::geteuid() } == 0, "the installed network helper requires root");
        let args: Vec<_> = std::env::args().skip(1).collect();
        ensure!(args.len() == 2 && args[0] == "serve", "expected: serve OWNER_UID");
        let owner: u32 = args[1].parse()?;
        ensure!(owner != 0, "invalid owner");
        let backend = MacBackend::new(owner)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new(DIRECTORY).join("helper.lock"))?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another helper owns the network state"
        );
        let mut broker = Broker::new(owner, backend)?;
        // Keep recovery errors visible through IPC instead of exiting a launchd loop.
        let _ = broker.handle(owner, Request::Recover, ipc::nonce);
        let socket = Path::new(DIRECTORY).join("control.sock");
        if let Ok(meta) = std::fs::symlink_metadata(&socket) {
            ensure!(meta.file_type().is_socket() && meta.uid() == owner, "unexpected control socket entry");
            std::fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let path = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())?;
        ensure!(unsafe { libc::chown(path.as_ptr(), owner, u32::MAX) } == 0, "cannot assign control socket");
        listener.set_nonblocking(true)?;
        unsafe {
            libc::signal(libc::SIGTERM, stop as *const () as usize);
            libc::signal(libc::SIGINT, stop as *const () as usize);
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        while !STOP.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if ipc::authenticate(&stream, owner).is_err() {
                continue;
            }
            let mut lease = None;
            while !STOP.load(Ordering::Relaxed) {
                let request = match ipc::read_request(&mut stream) {
                    Ok(request) => request,
                    Err(_) => break,
                };
                let result = broker.handle(owner, request, ipc::nonce);
                let status = broker.status();
                if status.lease.is_some() {
                    lease = status.lease.clone();
                }
                let reply = Reply {
                    ok: result.is_ok(),
                    status,
                    error: result.err().map(|error| format!("{error:#}")).unwrap_or_default(),
                    version: env!("CARGO_PKG_VERSION"),
                };
                if ipc::write_reply(&mut stream, &reply).is_err() {
                    break;
                }
            }
            if let Some(lease) = lease {
                let _ = broker.disconnected(owner, &lease);
            }
        }
        let recovery = broker.handle(owner, Request::Recover, ipc::nonce).context("helper shutdown recovery");
        drop(listener);
        std::fs::remove_file(socket)?;
        recovery?;
        Ok(())
    }
}
#[cfg(target_os = "macos")]
fn main() {
    let result = if std::env::args().nth(1).as_deref() == Some("control") { mac::control() } else { mac::run() };
    if let Err(error) = result {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("The network helper requires macOS.");
    std::process::exit(1);
}
