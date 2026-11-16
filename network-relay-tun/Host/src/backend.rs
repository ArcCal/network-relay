//! Concrete macOS backend. The worker runs as the installing user and only
//! receives a TUN descriptor, local SOCKS port and MTU, never relay credentials.
#![cfg(target_os = "macos")]
use crate::{
    broker::Backend,
    network::{Network, SystemCommands, default_route},
    protocol::Plan,
};
use anyhow::{Context, Result, ensure};
use std::{
    io::{BufRead, BufReader, Read},
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

pub const DIRECTORY: &str = "/Library/Application Support/NetworkRelayTun";
pub const WORKER: &str = "/Library/Application Support/NetworkRelayTun/packet-worker";
pub struct MacBackend {
    network: Network<SystemCommands>,
    owner: u32,
    device: Option<tun_rs::SyncDevice>,
    worker: Option<Child>,
    plan: Option<Plan>,
}
impl MacBackend {
    pub fn new(owner: u32) -> Result<Self> {
        let path = Path::new(DIRECTORY);
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0, "unsafe host state directory");
        let mut network = Network::new(SystemCommands, owner, path.join("network.json"));
        if network.load()? {
            ensure!(network.journal.owner == owner, "journal belongs to another account");
        }
        ensure!(network.journal.ipv6.is_empty(), "unexpected legacy IPv6 service mutations");
        let mut boot = [0u8; 128];
        let mut length = boot.len();
        ensure!(
            unsafe {
                libc::sysctlbyname(
                    c"kern.bootsessionuuid".as_ptr(),
                    boot.as_mut_ptr().cast(),
                    &mut length,
                    std::ptr::null_mut(),
                    0,
                )
            } == 0,
            "cannot read boot session identity"
        );
        ensure!(length > 0 && length <= boot.len(), "invalid boot identity length");
        let boot = std::str::from_utf8(&boot[..length])?.trim_end_matches('\0');
        network.begin_boot(boot)?;
        if let Some((name, _)) = &network.journal.capture_interface {
            let name = std::ffi::CString::new(name.as_str())?;
            let current = unsafe { libc::if_nametoindex(name.as_ptr()) };
            network.reconcile_capture_interface(current);
        }
        Ok(Self { network, owner, device: None, worker: None, plan: None })
    }
    fn endpoints(plan: &Plan) -> Result<Vec<Ipv4Addr>> {
        plan.endpoints
            .iter()
            .map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Ok(*ip),
                _ => anyhow::bail!("IPv6 relay endpoints are not yet supported; use a server IPv4 address"),
            })
            .collect()
    }
    fn launch_worker(&mut self, plan: &Plan) -> Result<()> {
        let meta = std::fs::symlink_metadata(WORKER)?;
        ensure!(meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0, "unsafe installed packet worker");
        let fd = self.device.as_ref().context("missing utun")?.as_raw_fd();
        let uid = self.owner;
        let user = unsafe { libc::getpwuid(uid) };
        ensure!(!user.is_null(), "installed account no longer exists");
        let gid = unsafe { (*user).pw_gid };
        let mut command = Command::new(WORKER);
        command
            .args([plan.socks_port.to_string(), plan.mtu.to_string()])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if fd != 3 && libc::dup2(fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0
                    || libc::setgroups(0, std::ptr::null()) < 0
                    || libc::setgid(gid) < 0
                    || libc::setuid(uid) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().context("starting unprivileged packet worker")?;
        let output = child.stdout.take().context("missing worker handshake pipe")?;
        self.worker = Some(child);
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            let result = BufReader::new(output).take(64).read_line(&mut text).map(|_| text);
            let _ = tx.send(result);
        });
        let result = rx.recv_timeout(Duration::from_secs(10));
        if !matches!(&result, Ok(Ok(line)) if line.trim() == "READY") {
            if let Some(child) = self.worker.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = reader.join();
            anyhow::bail!("packet worker did not become ready");
        }
        let _ = reader.join();
        Ok(())
    }
}
impl Backend for MacBackend {
    fn prepare(&mut self, plan: &Plan) -> Result<String> {
        let endpoints = Self::endpoints(plan)?;
        ensure!(plan.resolvers.iter().all(|ip| ip.is_ipv4()), "use IPv4 DNS resolver addresses for this version");
        let physical = default_route(&self.network.commands)?;
        // Bypass precedes both native outer connection creation and capture.
        self.network.endpoint_routes(&physical, &endpoints)?;
        let device = tun_rs::DeviceBuilder::new().mtu(plan.mtu).associate_route(false).build_sync()?;
        let name = device.name()?;
        self.device = Some(device);
        let c_name = std::ffi::CString::new(name.as_str())?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        ensure!(index != 0, "cannot identify prepared utun interface");
        self.network.journal.capture_interface = Some((name.clone(), index));
        self.network.save()?;
        let device = self.device.as_ref().unwrap();
        device.set_network_address(Ipv4Addr::new(198, 18, 0, 1), 32, Some(Ipv4Addr::new(198, 18, 0, 1)))?;
        device.add_address_v6("fd7a:115c:a1e0::1", 128)?;
        device.enabled(true)?;
        self.launch_worker(plan)?;
        self.plan = Some(plan.clone());
        Ok(name)
    }
    fn activate(&mut self, plan: &Plan, interface: &str) -> Result<()> {
        self.refresh()?;
        self.network.tunnel_routes(interface)?;
        self.network.tunnel_routes_v6(interface)?;
        let resolvers: Vec<_> = plan
            .resolvers
            .iter()
            .filter_map(|ip| if let std::net::IpAddr::V4(ip) = ip { Some(*ip) } else { None })
            .collect();
        self.network.dns(&resolvers)?;
        Ok(())
    }
    fn refresh(&mut self) -> Result<()> {
        let worker = self.worker.as_mut().context("packet worker is absent")?;
        ensure!(worker.try_wait()?.is_none(), "packet worker exited");
        let plan = self.plan.as_ref().context("capture is not prepared")?;
        let physical = default_route(&self.network.commands)?;
        self.network.endpoint_routes(&physical, &Self::endpoints(plan)?)?;
        Ok(())
    }
    fn cleanup(&mut self) -> Result<()> {
        // Restore routes and DNS while the interface still exists.
        let result = self.network.cleanup();
        if let Some(mut worker) = self.worker.take() {
            drop(worker.stdin.take()); // Parent death/EOF also stops the worker.
            let _ = worker.kill();
            let _ = worker.wait();
        }
        self.device = None;
        self.plan = None;
        result
    }
}
