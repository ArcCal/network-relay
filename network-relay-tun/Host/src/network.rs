//! macOS host configuration. No shell is used; every mutation is journaled.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub trait Commands: Send + Sync {
    fn run(&self, executable: &str, args: &[String], input: Option<&str>) -> Result<String>;
}

pub struct SystemCommands;
impl Commands for SystemCommands {
    fn run(&self, executable: &str, args: &[String], input: Option<&str>) -> Result<String> {
        if !ROUTINE.get() {
            debug!(executable, ?args, "network command starting");
        }
        let started = Instant::now();
        let mut child = Command::new(executable)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {executable}"))?;
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input.as_bytes())?;
        }
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let read = |reader: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut data = vec![];
                let _ = reader.take(65536).read_to_end(&mut data);
                String::from_utf8_lossy(&data).into_owned()
            })
        };
        let out = read(Box::new(stdout));
        let err = read(Box::new(stderr));
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() > Duration::from_secs(15) {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{executable} timed out after 15 seconds");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = out.join().unwrap_or_default();
        let error = err.join().unwrap_or_default();
        let result = validate_output(executable, status, &output, &error);
        log_command(executable, args, started.elapsed().as_millis(), status, &output, &error, result.is_ok());
        result?;
        Ok(output)
    }
}

thread_local! {
    static ROUTINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Periodic maintenance polls the same commands as activation. While it runs,
/// successful commands are not logged: they repeat every few seconds and bury
/// the events people read the log for. Failures are always logged.
pub struct Routine {
    previous: bool,
    // Commands are synchronous; this guard must be dropped on its own thread.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Routine {
    pub fn begin() -> Self {
        Self { previous: ROUTINE.replace(true), _thread: std::marker::PhantomData }
    }
}
impl Drop for Routine {
    fn drop(&mut self) {
        ROUTINE.set(self.previous);
    }
}

/// Multi-line output stays in one log record: continuation lines are indented,
/// so the viewer can fold, filter and search whole records.
fn indented(text: &str) -> String {
    text.trim().replace('\n', "\n    ")
}

fn log_command(
    executable: &str,
    args: &[String],
    elapsed_ms: u128,
    status: ExitStatus,
    output: &str,
    error: &str,
    valid: bool,
) {
    if valid && ROUTINE.get() {
        return;
    }
    debug!(executable, ?args, elapsed_ms, %status, stdout = %indented(output), stderr = %indented(error), "network command finished");
}

fn validate_output(executable: &str, status: ExitStatus, output: &str, error: &str) -> Result<()> {
    if executable == "/sbin/route" && status.code().is_some() {
        let exists_output = !output.trim().is_empty()
            && output.lines().all(|line| {
                ["add ", "change ", "delete "].iter().any(|prefix| line.starts_with(prefix))
                    && line.rsplit_once(": ").is_some_and(|(_, message)| message.trim() == "File exists")
            });
        let exists_error = error.trim() == "route: writing to routing socket: File exists";
        if (exists_error && (output.trim().is_empty() || exists_output)) || (error.trim().is_empty() && exists_output) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("route reported an error: {} {}", error.trim(), output.trim()),
            )
            .into());
        }
    }
    ensure!(status.success(), "{executable} failed ({status}): {}", error.trim());
    ensure!(
        executable != "/usr/sbin/networksetup"
            || !output.lines().any(|line| line.trim().starts_with("Error:") || line.trim().starts_with("** Error")),
        "networksetup reported an error: {}",
        output.trim()
    );
    if executable == "/sbin/route" {
        // Apple's route can exit zero after a failed routing-socket request.
        // Match known failures, rather than rejecting harmless stderr warnings.
        let failed = error.lines().any(|line| {
            [
                "route: writing to routing socket:",
                "route: read from routing socket",
                "route: message indicates error ",
                "route: routing message version ",
                "route: message length mismatch",
            ]
            .iter()
            .any(|prefix| line.trim().starts_with(prefix))
        }) || output.lines().any(|line| {
            ["add ", "change ", "delete "].iter().any(|prefix| line.starts_with(prefix))
                && line.rsplit_once(": ").is_some_and(|(_, message)| {
                    [
                        "not in table",
                        "entry in use",
                        "routing table overflow",
                        "File exists",
                        "Network is unreachable",
                        "No route to host",
                        "Invalid argument",
                        "Permission denied",
                        "Operation not permitted",
                        "Device not configured",
                        "Can't assign requested address",
                        "Cannot allocate memory",
                    ]
                    .contains(&message.trim())
                })
        });
        ensure!(!failed, "route reported an error: {} {}", error.trim(), output.trim());
    }
    Ok(())
}

/// Read-only diagnostics deliberately run without the network/journal lock.
pub fn diagnostics() {
    for (program, arguments) in [
        ("/sbin/ifconfig", vec![]),
        ("/usr/sbin/netstat", args(&["-nr", "-f", "inet"])),
        ("/usr/sbin/scutil", args(&["--dns"])),
    ] {
        if let Err(error) = SystemCommands.run(program, &arguments, None) {
            warn!(%error, "network diagnostics unavailable");
        }
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub gateway: Ipv4Addr,
    pub interface: String,
}

pub fn route_fields(output: &str) -> std::collections::BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            Some((key.trim().to_lowercase(), value.trim().to_string()))
        })
        .collect()
}

pub fn default_route(commands: &dyn Commands) -> Result<DefaultRoute> {
    // `route get default` can resolve our more-specific 0/1 route. Read the
    // actual unscoped default entry, as wg-quick does, even while utun owns /1.
    let output = route_snapshot(commands)?;
    physical_default(&output)
}

pub fn route_snapshot(commands: &dyn Commands) -> Result<String> {
    commands.run("/usr/sbin/netstat", &args(&["-nr", "-f", "inet"]), None)
}

#[derive(Debug, thiserror::Error)]
#[error("no unscoped IPv4 default route; connect Wi-Fi or Ethernet first")]
pub struct PhysicalNetworkUnavailable;

pub fn physical_default(output: &str) -> Result<DefaultRoute> {
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[0] != "default" || fields[2].contains('I') {
            continue;
        }
        ensure!(!fields[3].starts_with("utun"), "another VPN owns the default route; disconnect it first");
        let gateway: Ipv4Addr = fields[1].parse().context("no usable IPv4 default gateway")?;
        ensure!(!gateway.is_unspecified() && !gateway.is_multicast(), "invalid physical gateway");
        return Ok(DefaultRoute { gateway, interface: fields[3].into() });
    }
    Err(PhysicalNetworkUnavailable.into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv6Mode {
    Off,
    Automatic,
    LinkLocal,
    Manual { address: std::net::Ipv6Addr, prefix: u8, router: std::net::Ipv6Addr },
}

pub fn ipv6_mode(output: &str) -> Result<Ipv6Mode> {
    let fields = route_fields(output);
    match fields.get("ipv6").map(String::as_str) {
        Some("Off") => Ok(Ipv6Mode::Off),
        Some("Automatic") => Ok(Ipv6Mode::Automatic),
        Some("Link-local only") | Some("Link-local") => Ok(Ipv6Mode::LinkLocal),
        // networksetup omits the mode line when the IPv6 protocol is disabled.
        // Automatic with no lease still prints `IPv6: Automatic`; do not infer
        // Off from an absent address alone or from an otherwise unknown mode.
        None if fields.get("ipv6 ip address").is_some_and(|value| value == "none")
            && fields.get("ipv6 router").is_some_and(|value| value == "none") =>
        {
            Ok(Ipv6Mode::Off)
        }
        Some("Manual") => {
            let address = fields.get("ipv6 ip address").context("manual IPv6 address missing")?.parse()?;
            let prefix: u8 = fields
                .get("ipv6 prefix length")
                .context("manual IPv6 prefix missing; refusing to change settings that cannot be restored")?
                .parse()?;
            ensure!(prefix <= 128, "invalid IPv6 prefix");
            let router = fields.get("ipv6 router").context("manual IPv6 router missing")?.parse()?;
            Ok(Ipv6Mode::Manual { address, prefix, router })
        }
        _ => bail!("unrecognized IPv6 configuration; refusing to change it"),
    }
}

pub fn service_devices(output: &str) -> Result<std::collections::BTreeMap<String, String>> {
    let mut devices = std::collections::BTreeMap::new();
    let mut current = None;
    for line in output.lines().map(str::trim) {
        if line.starts_with("(Hardware Port:") {
            let name = current.take().context("hardware mapping without a network service")?;
            let device = line
                .rsplit_once(", Device:")
                .map(|(_, device)| device.trim().trim_end_matches(')').trim())
                .unwrap_or("");
            ensure!(!device.chars().any(char::is_control), "invalid network device mapping");
            devices.insert(name, device.to_string());
        } else if let Some((index, name)) = line.strip_prefix('(').and_then(|line| line.split_once(')')) {
            if !index.is_empty() && index.chars().all(|character| character.is_ascii_digit() || character == '*') {
                let name = name.trim().trim_start_matches('*').trim().to_string();
                ensure!(!name.is_empty(), "empty network service name");
                current = Some(name);
            }
        }
    }
    ensure!(!devices.is_empty(), "networksetup returned no hardware service mappings");
    Ok(devices)
}

pub(crate) fn hardware_device(device: &str) -> bool {
    // NetworkExtension/legacy VPN services either have no device here or a
    // virtual utun/ppp/ipsec device. Only macOS hardware-service devices support
    // networksetup's IPv6 setters. Names come from the OS, not app branding.
    ["en", "bridge", "fw", "anpi", "ap", "tb"].iter().any(|prefix| {
        device
            .strip_prefix(prefix)
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub original: Ipv6Mode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedRoute {
    pub destination: String,
    pub interface: String,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    #[serde(default)]
    pub capture_interface: Option<(String, u32)>,
    pub owner: u32,
    #[serde(default)]
    pub boot_session: Option<String>,
    pub routes: Vec<OwnedRoute>,
    #[serde(default)]
    pub ipv6_routes: Vec<crate::ipv6::CaptureRoute>,
    pub ipv6: Vec<Service>,
    pub dns_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_snapshot: Option<String>,
}

pub struct Network<C: Commands> {
    pub commands: C,
    pub journal: Journal,
    path: PathBuf,
    applied_dns: Option<(String, Vec<Ipv4Addr>, String)>,
}

impl<C: Commands> Network<C> {
    pub fn new(commands: C, owner: u32, path: PathBuf) -> Self {
        Self { commands, journal: Journal { owner, ..Default::default() }, path, applied_dns: None }
    }

    /// Routes and Dynamic Store DNS are ephemeral. A journal from another boot
    /// must never remove a new owner's coincidentally identical interface route.
    pub fn begin_boot(&mut self, boot: &str) -> Result<()> {
        ensure!(
            boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid boot session identifier"
        );
        ensure!(self.journal.ipv6.is_empty(), "persistent legacy service changes require explicit recovery");
        if self.journal.boot_session.as_deref().is_some_and(|previous| previous != boot) {
            self.journal = Journal { owner: self.journal.owner, ..Default::default() };
        } else if self.journal.boot_session.is_none() {
            ensure!(
                self.journal.routes.is_empty() && self.journal.ipv6_routes.is_empty() && self.journal.dns_key.is_none(),
                "journal has no boot identity; refusing ambiguous recovery"
            );
        }
        self.journal.boot_session = Some(boot.to_owned());
        Ok(())
    }

    /// Interface names can be reused after a helper crash within the same boot.
    /// Kernel interface indices distinguish the new interface from our old one.
    pub fn reconcile_capture_interface(&mut self, current_index: u32) {
        if self.journal.capture_interface.as_ref().is_some_and(|(_, index)| *index != current_index) {
            self.journal.routes.retain(|route| route.gateway.is_some());
            self.journal.ipv6_routes.clear();
            self.journal.capture_interface = None;
        }
    }

    pub fn save(&self) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let temp = self.path.with_extension("new");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(&self.journal)?)?;
        file.sync_all()?;
        std::fs::rename(&temp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            (|| -> Result<()> {
                let directory = std::fs::File::open(parent)?;
                #[cfg(test)]
                if tests::FAIL_PARENT_SYNC.with(|fail| fail.replace(false)) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
                directory.sync_all()?;
                Ok(())
            })()
            .context("network journal was replaced, but parent directory synchronization failed; durability is unconfirmed; verify current state before retrying")?;
        }
        Ok(())
    }

    pub fn load(&mut self) -> Result<bool> {
        self.applied_dns = None;
        if !self.path.exists() {
            return Ok(false);
        }
        self.journal = serde_json::from_slice(&std::fs::read(&self.path)?)?;
        Ok(true)
    }

    pub fn ipv6_services(&self) -> Result<Vec<Service>> {
        let started = Instant::now();
        let output = self.commands.run("/usr/sbin/networksetup", &args(&["-listallnetworkservices"]), None)?;
        let names: Vec<_> =
            output.lines().skip(1).map(str::trim).filter(|name| !name.is_empty() && !name.starts_with('*')).collect();
        let order = self.commands.run("/usr/sbin/networksetup", &args(&["-listnetworkserviceorder"]), None)?;
        let devices = service_devices(&order)?;
        let mut hardware = vec![];
        for name in names {
            ensure!(!name.starts_with('-') && !name.chars().any(char::is_control), "invalid network service name");
            let device = devices.get(name).map(String::as_str).unwrap_or("");
            if !hardware_device(device) {
                debug!(
                    service = name,
                    device, "skipping virtual/non-hardware network service; IPv6 settings left untouched"
                );
                continue;
            }
            hardware.push((name, device));
        }
        // Read independently, preserving service order and validating every
        // result before disable_ipv6 can journal or change any setting.
        let routine = ROUTINE.get();
        let services = std::thread::scope(|scope| {
            let mut services = Vec::with_capacity(hardware.len());
            for batch in hardware.chunks(4) {
                let reads: Vec<_> = batch
                    .iter()
                    .copied()
                    .map(|(name, device)| {
                        scope.spawn(move || {
                            let _routine = routine.then(Routine::begin);
                            let output =
                                self.commands.run("/usr/sbin/networksetup", &args(&["-getinfo", name]), None)?;
                            let mode =
                                ipv6_mode(&output).with_context(|| format!("reading IPv6 configuration for {name}"))?;
                            debug!(service = name, device, ?mode, "hardware service IPv6 configuration");
                            Ok(Service { name: name.into(), original: mode })
                        })
                    })
                    .collect();
                services.extend(
                    reads
                        .into_iter()
                        .map(|read| read.join().map_err(|_| anyhow::anyhow!("IPv6 inspection thread failed"))?)
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            Ok::<_, anyhow::Error>(services)
        })?;
        ensure!(
            !services.is_empty(),
            "no enabled hardware network services found; refusing to skip IPv6 configuration"
        );
        debug!(
            services = services.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "hardware IPv6 inspection complete"
        );
        Ok(services)
    }

    pub fn disable_ipv6(&mut self) -> Result<()> {
        // Inspect every new service before making any additional change.
        let mut pending = vec![];
        for service in self.ipv6_services()? {
            if service.original == Ipv6Mode::Off {
                continue;
            }
            if !self.journal.ipv6.iter().any(|saved| saved.name == service.name) {
                pending.push(service);
            } else {
                // An OS/network update re-enabled IPv6 while we were connected.
                self.commands.run("/usr/sbin/networksetup", &args(&["-setv6off", &service.name]), None)?;
            }
        }
        for service in pending {
            let name = service.name.clone();
            self.journal.ipv6.push(service);
            self.save()?; // Record BEFORE a command that may complete just before a crash.
            info!(service = %name, "disabling IPv6; original mode saved");
            self.commands.run("/usr/sbin/networksetup", &args(&["-setv6off", &name]), None)?;
        }
        Ok(())
    }

    /// IPv4 uses owned host routes. IPv6 uses the physical interface that the
    /// GUI requires on each outer connection, with no global IPv6 exception.
    pub fn relay_paths(
        &mut self,
        endpoints: &[IpAddr],
        v4_table: Option<&str>,
        ipv6_scope: Option<&str>,
    ) -> Result<Option<String>> {
        let mut v4 = Vec::new();
        let mut uplink = None;
        for endpoint in endpoints {
            match endpoint {
                IpAddr::V4(ip) => v4.push(*ip),
                IpAddr::V6(ip) => {
                    let name = crate::ipv6::endpoint_interface(&self.commands, *ip, ipv6_scope)?;
                    ensure!(
                        uplink.as_ref().is_none_or(|prior| prior == &name),
                        "relay endpoints need different uplinks"
                    );
                    uplink = Some(name);
                }
            }
        }
        if !v4.is_empty() {
            let physical = match v4_table {
                Some(table) => physical_default(table)?,
                None => default_route(&self.commands)?,
            };
            self.endpoint_routes(&physical, &v4)?;
        }
        Ok(uplink)
    }

    pub fn endpoint_routes(&mut self, route: &DefaultRoute, addresses: &[Ipv4Addr]) -> Result<()> {
        for ip in addresses.iter().copied().collect::<BTreeSet<_>>() {
            let ip_text = ip.to_string();
            let owned = OwnedRoute {
                destination: format!("{ip}/32"),
                interface: route.interface.clone(),
                gateway: Some(route.gateway),
            };
            let mut change = false;
            let output = match self.commands.run("/sbin/route", &args(&["-n", "get", "-inet", &ip_text]), None) {
                Ok(output) => Some(output),
                Err(error) if error.to_string().contains("not in table") || error.to_string().contains("not found") => {
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(output) = output {
                let mut fields = route_fields(&output);
                if fields.get("destination") == Some(&ip_text)
                    && fields.get("flags").is_some_and(|flags| flags.contains("WASCLONED") || flags.contains("IFSCOPE"))
                {
                    // A scoped cache can hide an existing unscoped static route
                    // from route get. Never journal or replace that other owner.
                    let snapshot = route_snapshot(&self.commands)?;
                    let mut permanent =
                        snapshot.lines().map(|line| line.split_whitespace().collect::<Vec<_>>()).filter(|row| {
                            row.len() >= 4
                                && (row[0] == ip_text || row[0] == owned.destination)
                                && row[2].contains('U')
                                && (row[2].contains('H') || row[0] == owned.destination)
                                && row[2].contains('S')
                                && !row[2].contains(['I', 'W'])
                        });
                    if let Some(row) = permanent.next() {
                        ensure!(permanent.next().is_none(), "server has ambiguous unscoped static host routes");
                        fields.insert("gateway".into(), row[1].into());
                        fields.insert("interface".into(), row[3].into());
                        fields.insert(
                            "flags".into(),
                            if row[2].contains('G') {
                                "<UP,GATEWAY,HOST,STATIC>".into()
                            } else {
                                "<UP,HOST,STATIC>".into()
                            },
                        );
                    }
                }
                if fields.get("flags").is_some_and(|flags| flags.contains("UP") && !flags.contains("GATEWAY"))
                    && fields.get("destination").is_some_and(|dest| dest != "default" && dest != "0.0.0.0")
                {
                    if let Some(interface) = fields.get("interface") {
                        let physical = interface == &route.interface
                            || (hardware_device(interface)
                                && fields.get("flags").is_some_and(|flags| !flags.contains("IFSCOPE"))
                                && service_devices(&self.commands.run(
                                    "/usr/sbin/networksetup",
                                    &args(&["-listnetworkserviceorder"]),
                                    None,
                                )?)?
                                .values()
                                .any(|device| device == interface));
                        if physical {
                            info!(%ip, "keeping existing directly connected LAN route for server");
                            continue;
                        }
                    }
                }
                if fields.get("destination") == Some(&ip_text)
                    && fields.get("flags").is_some_and(|flags| {
                        flags.contains("STATIC") && !flags.contains("WASCLONED") && !flags.contains("IFSCOPE")
                    })
                {
                    ensure!(
                        fields.get("interface").is_some_and(|iface| !iface.starts_with("utun")),
                        "server has an existing route through another tunnel"
                    );
                    let ours = self.journal.routes.iter().any(|saved| {
                        saved.destination == owned.destination
                            && fields.get("interface") == Some(&saved.interface)
                            && saved.gateway.is_some_and(|gateway| fields.get("gateway") == Some(&gateway.to_string()))
                    });
                    if !ours {
                        info!(%ip, "keeping pre-existing server host route");
                        continue;
                    }
                    if fields.get("interface") == Some(&route.interface)
                        && fields.get("gateway") == Some(&route.gateway.to_string())
                    {
                        continue;
                    }
                    change = true;
                }
                if !change && fields.get("destination") == Some(&ip_text) {
                    debug!(%ip, flags = ?fields.get("flags"), "cached/scoped host route is not a permanent endpoint bypass");
                }
            }
            let newly_recorded = !self.journal.routes.iter().any(|saved| {
                saved.destination == owned.destination
                    && saved.interface == owned.interface
                    && saved.gateway == owned.gateway
            });
            if newly_recorded {
                self.journal.routes.push(owned);
            }
            self.save()?;
            info!(%ip, gateway = %route.gateway, interface = %route.interface, change, "installing server bypass route");
            let mut arguments = args(&[
                "-n",
                if change { "change" } else { "add" },
                "-inet",
                "-host",
                &ip_text,
                &route.gateway.to_string(),
            ]);
            if change {
                arguments.extend(args(&["-ifp", &route.interface]));
            }
            if let Err(error) = self.commands.run("/sbin/route", &arguments, None) {
                if !change
                    && newly_recorded
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|cause| cause.kind() == std::io::ErrorKind::AlreadyExists)
                {
                    // EEXIST did not install this route. Retain earlier owners,
                    // but revoke this attempt's claim before any cleanup runs.
                    self.journal.routes.pop();
                    self.save().with_context(|| format!("revoking uninstalled endpoint route after {error:#}"))?;
                }
                // Unknown command failures may follow a committed mutation.
                // Keep their write-ahead record for the existing recovery path.
                return Err(error);
            }
        }
        Ok(())
    }

    /// Retires obsolete endpoint bypasses without changing the active tunnel.
    pub fn cleanup_endpoints(&mut self, keep: &[Ipv4Addr]) -> Result<()> {
        let obsolete = |route: &OwnedRoute| {
            route.gateway.is_some()
                && route
                    .destination
                    .strip_suffix("/32")
                    .and_then(|address| address.parse::<Ipv4Addr>().ok())
                    .is_some_and(|address| !keep.contains(&address))
        };
        if !self.journal.routes.iter().any(obsolete) {
            return Ok(());
        }
        let mut errors = vec![];
        let mut retained = vec![];
        for route in std::mem::take(&mut self.journal.routes).into_iter().rev() {
            if !obsolete(&route) {
                retained.push(route);
            } else if let Err(error) = self.remove_route(&route) {
                errors.push(format!("route {}: {error:#}", route.destination));
                retained.push(route);
            }
        }
        retained.reverse();
        self.journal.routes = retained;
        self.save()?;
        ensure!(errors.is_empty(), "endpoint cleanup incomplete: {}", errors.join("; "));
        Ok(())
    }

    pub fn tunnel_routes(&mut self, interface: &str) -> Result<()> {
        ensure!(
            interface.strip_prefix("utun").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
            "invalid utun name"
        );
        for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
            if self.journal.routes.iter().any(|route| route.destination == destination && route.interface == interface)
            {
                if let Ok(output) =
                    self.commands.run("/sbin/route", &args(&["-n", "get", "-inet", "-net", destination]), None)
                {
                    let fields = route_fields(&output);
                    let address = destination.split('/').next().unwrap();
                    if fields.get("interface").is_some_and(|name| name == interface)
                        && fields
                            .get("destination")
                            .is_some_and(|value| value == address || (address == "0.0.0.0" && value == "default"))
                        && fields.get("mask").is_some_and(|mask| mask == "128.0.0.0" || mask == "0x80000000")
                    {
                        info!(destination, interface, "keeping previously installed tunnel route during retry");
                        continue;
                    }
                }
            } else {
                self.journal.routes.push(OwnedRoute {
                    destination: destination.into(),
                    interface: interface.into(),
                    gateway: None,
                });
                self.save()?;
            }
            info!(destination, interface, "installing IPv4 full-tunnel route");
            self.commands.run(
                "/sbin/route",
                &args(&["-n", "add", "-inet", "-net", destination, "-interface", interface]),
                None,
            )?;
        }
        Ok(())
    }

    /// Updates the route's cached source address without removing capture.
    pub fn refresh_tunnel_routes(&mut self, interface: &str, address: Ipv4Addr) -> Result<()> {
        ensure!(
            interface.strip_prefix("utun").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
            "invalid utun name"
        );
        for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
            let output = self.commands.run("/sbin/route", &args(&["-n", "get", "-inet", "-net", destination]), None)?;
            let fields = route_fields(&output);
            let destination_address = destination.split('/').next().unwrap();
            let current = fields.get("interface").context("capture route has no interface")?;
            ensure!(
                fields
                    .get("destination")
                    .is_some_and(|value| value == destination_address
                        || (destination_address == "0.0.0.0" && value == "default"))
                    && fields.get("mask").is_some_and(|mask| mask == "128.0.0.0" || mask == "0x80000000")
                    && current == interface
                    && self.journal.routes.iter().any(|route| route.destination == destination
                        && &route.interface == current
                        && route.gateway.is_none()),
                "capture route {destination} no longer belongs to this connection: expected {interface}, actual {fields:?}"
            );
            info!(destination, interface, %address, "refreshing IPv4 tunnel source");
            let arguments = args(&[
                "-n",
                "change",
                "-inet",
                "-net",
                destination,
                "-interface",
                interface,
                "-ifp",
                interface,
                "-ifa",
                &address.to_string(),
            ]);
            self.commands.run("/sbin/route", &arguments, None)?;
        }
        Ok(())
    }

    pub fn dns(&mut self, servers: &[Ipv4Addr]) -> Result<()> {
        let key = format!("State:/Network/Service/NetworkRelayTun-{}/DNS", self.journal.owner);
        if self.applied_dns.as_ref().is_some_and(|(previous_key, previous_servers, snapshot)| {
            previous_key == &key
                && previous_servers == servers
                && self.journal.dns_key.as_ref() == Some(&key)
                && self.dns_snapshot().is_ok_and(|current| current == *snapshot)
        }) {
            return Ok(());
        }
        self.journal.dns_key = Some(key.clone());
        self.journal.dns_snapshot = None;
        self.save()?;
        let addresses = servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ");
        // Supply the per-domain numeric order as well as SearchOrder. On the
        // user's Mac, SearchOrder alone left us behind another VPN's resolver.
        // Lower values take precedence; specific split domains still win.
        let script = format!(
            "d.init\nd.add ServerAddresses * {addresses}\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchOrders * # 1000\nd.add SearchOrder # 1000\nset {key}\nquit\n"
        );
        info!(?servers, "installing temporary default DNS resolver");
        let output = self.commands.run("/usr/sbin/scutil", &[], Some(&script))?;
        ensure!(output.trim().is_empty(), "scutil DNS setup failed: {}", output.trim());
        let snapshot = self.dns_snapshot()?;
        self.journal.dns_snapshot = Some(snapshot.clone());
        self.save()?;
        self.applied_dns = Some((key, servers.to_vec(), snapshot));
        Ok(())
    }

    /// Checks existing ownership without adding or repairing system routes.
    /// Reuses the same netstat snapshot used to find the physical default.
    pub fn verify_capture(&self, interface: &str, snapshot: &str) -> Result<()> {
        for (destination, spellings) in [
            ("0.0.0.0/1", ["0/1", "0.0/1", "0.0.0/1", "0.0.0.0/1"]),
            ("128.0.0.0/1", ["128/1", "128.0/1", "128.0.0/1", "128.0.0.0/1"]),
        ] {
            ensure!(
                self.journal.routes.iter().any(|route| {
                    route.destination == destination && route.interface == interface && route.gateway.is_none()
                }),
                "capture route {destination} is not owned by this connection"
            );
            let entries: Vec<_> = snapshot
                .lines()
                .map(|line| line.split_whitespace().collect::<Vec<_>>())
                .filter(|fields| fields.len() >= 4 && spellings.contains(&fields[0]))
                .collect();
            let mut unscoped = entries.iter().filter(|fields| !fields[2].contains('I'));
            let entry = unscoped.next();
            ensure!(
                unscoped.next().is_none(),
                "capture route {destination} is ambiguous: expected {interface}, actual {entries:?}; Disconnect before retrying"
            );
            ensure!(
                entry.is_some_and(|fields| fields[2].contains('U')
                    && !fields[2].contains(['G', 'B', 'R'])
                    && fields[3] == interface),
                "capture route {destination} is missing or changed: expected {interface}, actual {entries:?}; Disconnect before retrying"
            );
        }
        Ok(())
    }

    /// Compare the product's Dynamic Store entry with the installed dictionary.
    /// Resolver display order and more specific split domains are independent.
    pub fn verify_dns(&self) -> Result<()> {
        let actual = self.dns_snapshot()?;
        ensure!(
            self.journal.dns_snapshot.as_ref().is_none_or(|saved| saved == &actual),
            "temporary DNS resolver changed"
        );
        Ok(())
    }

    pub fn verify_active(&self, interface: &str, v4_table: &str) -> Result<()> {
        self.verify_capture(interface, v4_table)?;
        let v6_table = crate::ipv6::snapshot(&self.commands)?;
        for prefix in ["::/1", "8000::/1"] {
            ensure!(
                self.journal.ipv6_routes.iter().any(|r| r.interface == interface && r.destination == prefix)
                    && crate::ipv6::owns_capture(&v6_table, prefix, interface)?,
                "IPv6 capture route {prefix} is missing or changed"
            );
        }
        self.verify_dns()
    }

    fn dns_snapshot(&self) -> Result<String> {
        let key = self.journal.dns_key.as_ref().context("temporary DNS resolver is not journaled")?;
        let output = self.commands.run("/usr/sbin/scutil", &[], Some(&format!("show {key}\nquit\n")))?;
        ensure!(
            output.trim().starts_with("<dictionary> {"),
            "temporary DNS resolver is missing or changed: {}",
            output.trim()
        );
        Ok(output.trim().to_owned())
    }

    /// Removes only routes that still match the recorded interface/gateway.
    /// Failed restorations remain in the journal for an explicit recovery.
    /// Add IPv6 capture without disabling any physical network service.
    pub fn tunnel_routes_v6(&mut self, interface: &str) -> Result<()> {
        for destination in ["::/1", "8000::/1"] {
            let route = crate::ipv6::CaptureRoute { destination: destination.into(), interface: interface.into() };
            route.validate()?;
            let table = crate::ipv6::snapshot(&self.commands)?;
            let recorded =
                self.journal.ipv6_routes.iter().any(|r| r.destination == destination && r.interface == interface);
            if let Some(existing) = crate::ipv6::interface_for(&table, destination)? {
                ensure!(recorded && existing == interface, "IPv6 capture route belongs to another owner");
                continue;
            }
            if !recorded {
                self.journal.ipv6_routes.push(route);
                self.save()?;
            }
            self.commands.run(
                "/sbin/route",
                &args(&["-n", "add", "-inet6", "-net", destination, "-interface", interface]),
                None,
            )?;
        }
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.journal.routes.is_empty()
            && self.journal.ipv6_routes.is_empty()
            && self.journal.ipv6.is_empty()
            && self.journal.dns_key.is_none()
            && !self.path.exists()
        {
            return Ok(());
        }
        let mut errors = vec![];
        if let Some(key) = self.journal.dns_key.clone() {
            match self.remove_dns(&key) {
                Ok(()) => {
                    self.journal.dns_key = None;
                    self.journal.dns_snapshot = None;
                    self.applied_dns = None;
                }
                Err(error) => errors.push(format!("DNS cleanup: {error:#}")),
            }
        }
        let mut v6_routes = vec![];
        for route in std::mem::take(&mut self.journal.ipv6_routes).into_iter().rev() {
            if let Err(error) = crate::ipv6::remove_owned(&self.commands, &route) {
                errors.push(format!("IPv6 route {}: {error:#}", route.destination));
                v6_routes.push(route);
            }
        }
        self.journal.ipv6_routes = v6_routes;
        let mut routes = vec![];
        for route in std::mem::take(&mut self.journal.routes).into_iter().rev() {
            match self.remove_route(&route) {
                Ok(()) => (),
                Err(error) => {
                    errors.push(format!("route {}: {error:#}", route.destination));
                    routes.push(route);
                }
            }
        }
        self.journal.routes = routes;
        let mut services = vec![];
        for service in std::mem::take(&mut self.journal.ipv6) {
            let mut arguments = match service.original {
                Ipv6Mode::Off => args(&["-setv6off", &service.name]),
                Ipv6Mode::Automatic => args(&["-setv6automatic", &service.name]),
                Ipv6Mode::LinkLocal => args(&["-setv6linklocal", &service.name]),
                Ipv6Mode::Manual { address, prefix, router } => args(&[
                    "-setv6manual",
                    &service.name,
                    &address.to_string(),
                    &prefix.to_string(),
                    &router.to_string(),
                ]),
            };
            info!(service = %service.name, mode = ?service.original, "restoring original IPv6 configuration");
            if let Err(error) = self.commands.run("/usr/sbin/networksetup", &std::mem::take(&mut arguments), None) {
                errors.push(format!("IPv6 {}: {error:#}", service.name));
                services.push(service);
            }
        }
        self.journal.ipv6 = services;
        self.save()?;
        if errors.is_empty() {
            if self.path.exists() {
                std::fs::remove_file(&self.path)?;
            }
            Ok(())
        } else {
            bail!("network recovery incomplete; retry Recover Network: {}", errors.join("; "))
        }
    }

    fn remove_dns(&self, key: &str) -> Result<()> {
        ensure!(
            key == format!("State:/Network/Service/NetworkRelayTun-{}/DNS", self.journal.owner),
            "unexpected journaled DNS key"
        );
        if let Some(installed) = &self.journal.dns_snapshot {
            let current = self.commands.run("/usr/sbin/scutil", &[], Some(&format!("show {key}\nquit\n")))?;
            if current.trim() == "No such key" {
                return Ok(());
            }
            ensure!(current.trim().starts_with("<dictionary> {"), "unrecognized DNS snapshot");
            if current.trim() != installed {
                return Ok(());
            } // Preserve a replacement.
        }
        let output = self.commands.run("/usr/sbin/scutil", &[], Some(&format!("remove {key}\nquit\n")))?;
        ensure!(output.trim().is_empty() || output.trim() == "No such key", "scutil DNS removal failed: {output}");
        Ok(())
    }

    fn remove_route(&self, route: &OwnedRoute) -> Result<()> {
        let (network, bits) = route.destination.split_once('/').context("invalid recovery route")?;
        let address: Ipv4Addr = network.parse()?;
        ensure!(
            bits == "32"
                || (bits == "1" && (address == Ipv4Addr::UNSPECIFIED || address == Ipv4Addr::new(128, 0, 0, 0))),
            "unexpected recovery route"
        );
        let flag = if bits == "32" { "-host" } else { "-net" };
        let destination = if bits == "32" { network } else { &route.destination };
        let output = match self.commands.run("/sbin/route", &args(&["-n", "get", "-inet", flag, destination]), None) {
            Ok(output) => output,
            Err(error) if error.to_string().contains("not in table") || error.to_string().contains("not found") => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let fields = route_fields(&output);
        let expected_mask = if bits == "32" { "255.255.255.255" } else { "128.0.0.0" };
        let exact = fields.get("destination").is_some_and(|s| s == network || (network == "0.0.0.0" && s == "default"))
            && (fields
                .get("mask")
                .is_some_and(|s| s == expected_mask || s == if bits == "32" { "0xffffffff" } else { "0x80000000" })
                || (bits == "32" && fields.get("flags").is_some_and(|s| s.contains("HOST"))));
        let direct_capture = bits != "1"
            || fields.get("flags").is_some_and(|flags| {
                let mut flags = flags.trim_matches(['<', '>']).split(',');
                flags.clone().any(|flag| flag == "UP")
                    && !flags.any(|flag| matches!(flag, "GATEWAY" | "BLACKHOLE" | "REJECT" | "IFSCOPE"))
            });
        let matches = exact
            && direct_capture
            && fields.get("interface") == Some(&route.interface)
            && route.gateway.is_none_or(|gateway| {
                fields.get("gateway") == Some(&gateway.to_string())
                    && fields.get("flags").is_some_and(|flags| {
                        flags.contains("STATIC") && !flags.contains("IFSCOPE") && !flags.contains("WASCLONED")
                    })
            });
        if !matches {
            if exact {
                warn!(destination = %route.destination, ?fields, "route replaced by another owner; leaving it untouched");
            } else {
                debug!(destination = %route.destination, "recorded route already absent");
            }
            return Ok(());
        }
        info!(destination = %route.destination, "removing owned route");
        self.commands.run("/sbin/route", &args(&["-n", "delete", "-inet", flag, destination]), None)?;
        Ok(())
    }
}

pub fn journal_path(root: &Path) -> PathBuf {
    root.join("network.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    // One-shot and thread-local so unrelated parallel journal saves are unaffected.
    thread_local! {
        pub(super) static FAIL_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[test]
    fn journal_post_replace_sync_failure_reports_the_committed_target_and_allows_retry() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = journal_path(directory.path());
        let mut net = Network::new(Fake::default(), 501, path.clone());
        net.journal.dns_key = Some("previous".into());
        net.save().unwrap();
        net.journal.dns_key = Some("replacement".into());
        FAIL_PARENT_SYNC.with(|fail| fail.set(true));

        let error = net.save().unwrap_err();

        assert!(!FAIL_PARENT_SYNC.with(|fail| fail.get()), "the injected fault must be one-shot");
        assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().raw_os_error(), Some(libc::EIO));
        assert!(error.to_string().contains("network journal was replaced"));
        assert!(error.to_string().contains("durability is unconfirmed"));
        assert!(error.to_string().contains("verify current state before retrying"));
        let saved: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.dns_key.as_deref(), Some("replacement"));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!path.with_extension("new").exists());
        assert!(net.commands.calls.lock().unwrap().is_empty(), "saving must not issue network commands");

        net.save().unwrap();
        let saved: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.dns_key.as_deref(), Some("replacement"));
    }

    #[test]
    fn route_zero_exit_does_not_hide_routing_socket_errors() {
        for (output, error) in [
            ("", "route: writing to routing socket: not in table\n"),
            ("delete net 0.0.0.0: not in table\n", ""),
            ("add host 198.51.100.8: gateway 192.0.2.1: File exists\n", ""),
            ("change net 128.0.0.0: gateway utun4: Invalid argument\n", ""),
            ("", "route: message indicates error 3: No such process\n"),
        ] {
            assert!(validate_output("/sbin/route", ExitStatus::from_raw(0), output, error).is_err());
        }
    }

    #[test]
    fn route_exists_is_typed_only_for_an_unambiguous_command_rejection() {
        let output = "add host 144.34.236.44: gateway 10.10.10.1: File exists\n";
        let error = "route: writing to routing socket: File exists\n";
        for (status, stdout, stderr, exists) in [
            (0, output, error, true),
            (256, output, error, true),
            (0, output, "", true),
            (0, "", error, true),
            (0, output, "route: read from routing socket: timed out\n", false),
            (0, "unexpected output\n", error, false),
            (9, output, error, false),
        ] {
            let failure = validate_output("/sbin/route", ExitStatus::from_raw(status), stdout, stderr).unwrap_err();
            assert_eq!(
                failure
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|cause| cause.kind() == std::io::ErrorKind::AlreadyExists),
                exists
            );
        }
    }

    #[test]
    fn route_success_and_nonfatal_warnings_are_accepted() {
        for output in ["add net 0.0.0.0: gateway utun4\n", "delete host 198.51.100.8\n", "interface: en0\n"] {
            assert!(
                validate_output(
                    "/sbin/route",
                    ExitStatus::from_raw(0),
                    output,
                    "route: no name for interface index: \"4\"\n",
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn routine_logging_is_nested_thread_local_and_keeps_zero_exit_errors() {
        use std::sync::Arc;
        #[derive(Clone)]
        struct Output(Arc<Mutex<Vec<u8>>>);
        impl Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Output(Arc::new(Mutex::new(vec![])));
        let writer = output.clone();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .without_time()
                .with_writer(move || writer.clone())
                .finish(),
        );
        tracing::dispatcher::with_default(&dispatch, || {
            let _routine = Routine::begin();
            {
                let _nested = Routine::begin();
                log_command("nested-success", &[], 0, ExitStatus::from_raw(0), "", "", true);
            }
            assert!(ROUTINE.get(), "a nested guard must preserve the outer scope");
            log_command("routine-success", &[], 0, ExitStatus::from_raw(0), "", "", true);
            let error = "route: writing to routing socket: File exists";
            let result = validate_output("/sbin/route", ExitStatus::from_raw(0), "", error);
            assert!(result.is_err());
            log_command("/sbin/route", &[], 0, ExitStatus::from_raw(0), "", error, result.is_ok());
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        tracing::dispatcher::with_default(&dispatch, || {
                            assert!(!ROUTINE.get(), "diagnostics on another thread must remain visible");
                            log_command(
                                "independent-diagnostics",
                                &[],
                                0,
                                ExitStatus::from_raw(0),
                                "snapshot",
                                "",
                                true,
                            );
                        })
                    })
                    .join()
                    .unwrap();
            });
        });
        assert!(!ROUTINE.get());
        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(!logs.contains("nested-success") && !logs.contains("routine-success"));
        assert!(logs.contains("File exists") && logs.contains("independent-diagnostics"));
    }

    #[test]
    fn capture_verification_reuses_snapshot_and_never_repairs_foreign_or_missing_routes() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(SystemCommands, 501, journal_path(dir.path()));
        net.journal.routes = ["0.0.0.0/1", "128.0.0.0/1"]
            .into_iter()
            .map(|destination| OwnedRoute { destination: destination.into(), interface: "utun9".into(), gateway: None })
            .collect();
        let snapshot = "default 192.0.2.1 UGScg en1\n0/1 link#20 UCS utun9\n128.0/1 link#20 UCS utun9\n";
        assert_eq!(physical_default(snapshot).unwrap().interface, "en1");
        net.verify_capture("utun9", snapshot).unwrap();
        let before = serde_json::to_value(&net.journal).unwrap();
        for changed in [
            snapshot.replace("128.0/1", "128.0/2"),
            snapshot.replace("utun9", "utun10"),
            snapshot.replace("UCS", "UCSI"),
            snapshot.replace("UCS", "UGS"),
            snapshot.replace("UCS", "UCB"),
            snapshot.replace("UCS", "UCR"),
            snapshot.replace("128.0/1 link#20 UCS utun9\n", ""),
            format!("{snapshot}128/1 link#21 UCS utun10\n"),
        ] {
            assert!(net.verify_capture("utun9", &changed).is_err());
            assert_eq!(serde_json::to_value(&net.journal).unwrap(), before);
        }
        net.verify_capture("utun9", &format!("{snapshot}128/1 link#21 UCSI utun10\n")).unwrap();
        net.journal.routes.pop();
        assert!(net.verify_capture("utun9", snapshot).is_err(), "an unjournaled route must not be claimed");
        assert!(!net.path.exists(), "read-only checks must not persist a journal");
    }

    #[test]
    fn dns_verification_only_reads_own_key_and_missing_key_does_not_mutate_journal() {
        struct ShowDns(Mutex<String>);
        impl Commands for ShowDns {
            fn run(&self, program: &str, arguments: &[String], input: Option<&str>) -> Result<String> {
                assert_eq!(program, "/usr/sbin/scutil");
                assert!(arguments.is_empty());
                assert_eq!(input, Some("show State:/Network/Service/NetworkRelayTun-501/DNS\nquit\n"));
                Ok(self.0.lock().unwrap().clone())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(
            ShowDns(Mutex::new("<dictionary> {\n ServerAddresses : <array> { 0 : 1.1.1.1 }\n}\n".into())),
            501,
            journal_path(dir.path()),
        );
        assert!(net.verify_dns().is_err(), "an unjournaled key must not be inspected");
        net.journal.dns_key = Some("State:/Network/Service/NetworkRelayTun-501/DNS".into());
        net.verify_dns().unwrap();
        *net.commands.0.lock().unwrap() = "No such key\n".into();
        assert!(net.verify_dns().is_err());
        assert!(net.journal.dns_key.is_some() && !net.path.exists());
    }

    #[test]
    fn unchanged_dns_skips_writes_only_while_the_actual_key_snapshot_matches() {
        const SNAPSHOT: &str = "<dictionary> {\n ServerAddresses : <array> {\n  0 : 1.1.1.1\n }\n SearchOrder : 1000\n SupplementalMatchDomains : <array> {\n  0 :\n }\n SupplementalMatchOrders : <array> {\n  0 : 1000\n }\n}\n";
        struct Dns {
            output: Mutex<String>,
            writes: Mutex<usize>,
            fail: Mutex<bool>,
        }
        impl Commands for Dns {
            fn run(&self, program: &str, arguments: &[String], input: Option<&str>) -> Result<String> {
                assert_eq!(program, "/usr/sbin/scutil");
                assert!(arguments.is_empty());
                let input = input.unwrap();
                if input.starts_with("show ") {
                    return Ok(self.output.lock().unwrap().clone());
                }
                assert!(input.contains("set State:/Network/Service/NetworkRelayTun-501/DNS"));
                *self.writes.lock().unwrap() += 1;
                if std::mem::take(&mut *self.fail.lock().unwrap()) {
                    bail!("injected DNS write failure");
                }
                *self.output.lock().unwrap() = SNAPSHOT.into();
                Ok(String::new())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(
            Dns { output: Mutex::new("No such key".into()), writes: Mutex::new(0), fail: Mutex::new(true) },
            501,
            journal_path(dir.path()),
        );
        let servers = [Ipv4Addr::new(1, 1, 1, 1)];
        assert!(net.dns(&servers).is_err());
        net.dns(&servers).unwrap();
        net.dns(&servers).unwrap();
        assert_eq!(*net.commands.writes.lock().unwrap(), 2, "a failed write must not enable skipping");
        for changed in
            ["No such key\n".into(), SNAPSHOT.replace("1000", "2000"), SNAPSHOT.replace("1.1.1.1", "8.8.8.8")]
        {
            let before = *net.commands.writes.lock().unwrap();
            *net.commands.output.lock().unwrap() = changed;
            net.dns(&servers).unwrap();
            assert_eq!(*net.commands.writes.lock().unwrap(), before + 1, "external DNS changes must be rewritten");
            net.dns(&servers).unwrap();
            assert_eq!(*net.commands.writes.lock().unwrap(), before + 1);
        }
    }

    #[test]
    fn empty_cleanup_without_a_journal_needs_no_commands_or_writable_parent() {
        struct NoCommands;
        impl Commands for NoCommands {
            fn run(&self, _: &str, _: &[String], _: Option<&str>) -> Result<String> {
                panic!("empty cleanup must not run a system command")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent-parent/network.json");
        let mut net = Network::new(NoCommands, 501, path.clone());
        net.cleanup().unwrap();
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn endpoint_keeps_direct_lan_on_another_hardware_nic_but_not_tunnel_or_scoped_routes() {
        struct Lan {
            interface: &'static str,
            flags: &'static str,
            adds: Mutex<usize>,
            reads: Mutex<usize>,
        }
        impl Commands for Lan {
            fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
                if program == "/usr/sbin/networksetup" {
                    assert_eq!(arguments, &["-listnetworkserviceorder"]);
                    *self.reads.lock().unwrap() += 1;
                    return Ok("(1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n(2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n".into());
                }
                assert_eq!(program, "/sbin/route");
                match arguments[1].as_str() {
                    "get" => Ok(format!(
                        "destination: 192.168.20.0\nmask: 255.255.255.0\ngateway: link#10\ninterface: {}\nflags: {}\n",
                        self.interface, self.flags
                    )),
                    "add" => {
                        *self.adds.lock().unwrap() += 1;
                        Ok(String::new())
                    }
                    _ => panic!("LAN verification must not change or delete existing routes"),
                }
            }
        }
        for (interface, flags, expected_adds, expected_reads) in [
            ("en0", "<UP,DONE>", 0, 1),
            ("en1", "<UP,DONE,IFSCOPE>", 0, 0),
            ("bridge0", "<UP,DONE>", 0, 1),
            ("en9", "<UP,DONE>", 1, 1),
            ("bridge9", "<UP,DONE>", 1, 1),
            ("utun9", "<UP,DONE>", 1, 0),
            ("en0", "<UP,DONE,IFSCOPE>", 1, 0),
            ("en0", "<DONE>", 1, 0),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut net = Network::new(
                Lan { interface, flags, adds: Mutex::new(0), reads: Mutex::new(0) },
                501,
                journal_path(dir.path()),
            );
            net.endpoint_routes(
                &DefaultRoute { interface: "en1".into(), gateway: "192.0.2.1".parse().unwrap() },
                &["192.168.20.8".parse().unwrap()],
            )
            .unwrap();
            assert_eq!(*net.commands.adds.lock().unwrap(), expected_adds);
            assert_eq!(*net.commands.reads.lock().unwrap(), expected_reads);
            assert_eq!(net.journal.routes.len(), expected_adds);
        }
    }

    #[test]
    fn failed_endpoint_lookup_does_not_claim_or_mutate_a_route() {
        struct FailedRead;
        impl Commands for FailedRead {
            fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
                assert_eq!(program, "/sbin/route");
                assert_eq!(arguments[1], "get", "a failed lookup must not attempt add/change");
                bail!("route: read from routing socket: Interrupted system call")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(FailedRead, 501, journal_path(dir.path()));
        let physical = DefaultRoute { interface: "en0".into(), gateway: Ipv4Addr::new(192, 0, 2, 1) };
        assert!(net.endpoint_routes(&physical, &[Ipv4Addr::new(198, 51, 100, 8)]).is_err());
        assert!(net.journal.routes.is_empty());
        assert!(!net.path.exists(), "failed lookup must not persist ownership");
    }

    struct RouteRefresh {
        path: PathBuf,
        interfaces: Mutex<std::collections::BTreeMap<String, String>>,
        sources: Mutex<std::collections::BTreeMap<String, Ipv4Addr>>,
        mask: Mutex<String>,
        fail_change: Mutex<Option<String>>,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl Commands for RouteRefresh {
        fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
            assert_eq!(program, "/sbin/route");
            self.calls.lock().unwrap().push(arguments.to_vec());
            let destination = &arguments[4];
            let mut interfaces = self.interfaces.lock().unwrap();
            if arguments[1] == "get" {
                let interface = interfaces.get(destination).context("not in table")?;
                return Ok(format!(
                    "destination: {}\nmask: {}\ninterface: {interface}\n",
                    destination.split('/').next().unwrap(),
                    self.mask.lock().unwrap()
                ));
            }
            assert_eq!(arguments[1], "change", "source refresh must not delete/add capture routes");
            assert_eq!(arguments[5], "-interface");
            assert_eq!(arguments[7], "-ifp");
            assert_eq!(arguments[6], arguments[8]);
            let saved: Journal = serde_json::from_slice(&std::fs::read(&self.path)?)?;
            assert!(saved.routes.iter().any(|route| &route.destination == destination
                && route.interface == arguments[6]
                && route.gateway.is_none()));
            if self.fail_change.lock().unwrap().as_ref() == Some(destination) {
                bail!("injected source refresh failure");
            }
            if arguments.len() > 9 {
                assert_eq!(arguments[9], "-ifa");
                self.sources.lock().unwrap().insert(destination.clone(), arguments[10].parse()?);
            }
            interfaces.insert(destination.clone(), arguments[6].clone());
            Ok(String::new())
        }
    }
    fn refresh_network(path: PathBuf) -> Network<RouteRefresh> {
        let commands = RouteRefresh {
            path: path.clone(),
            interfaces: Mutex::new(
                [("0.0.0.0/1".into(), "utun9".into()), ("128.0.0.0/1".into(), "utun9".into())].into(),
            ),
            sources: Mutex::new(std::collections::BTreeMap::new()),
            mask: Mutex::new("128.0.0.0".into()),
            fail_change: Mutex::new(None),
            calls: Mutex::new(vec![]),
        };
        let mut net = Network::new(commands, 501, path);
        net.journal.routes = ["0.0.0.0/1", "128.0.0.0/1"]
            .into_iter()
            .map(|destination| OwnedRoute { destination: destination.into(), interface: "utun9".into(), gateway: None })
            .collect();
        net.save().unwrap();
        net
    }

    #[test]
    fn endpoint_cleanup_without_changes_does_not_create_a_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.json");
        let mut network = Network::new(SystemCommands, 501, path.clone());
        network.cleanup_endpoints(&[]).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn tunnel_source_refresh_changes_owned_routes_in_place_and_partial_failure_is_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = refresh_network(journal_path(dir.path()));
        let address = Ipv4Addr::new(198, 18, 0, 3);
        *net.commands.fail_change.lock().unwrap() = Some("128.0.0.0/1".into());
        assert!(net.refresh_tunnel_routes("utun9", address).is_err());
        assert_eq!(net.commands.sources.lock().unwrap()["0.0.0.0/1"], address);
        assert!(!net.commands.sources.lock().unwrap().contains_key("128.0.0.0/1"));
        assert!(net.commands.interfaces.lock().unwrap().values().all(|interface| interface == "utun9"));
        assert_eq!(net.journal.routes.len(), 2);
        *net.commands.fail_change.lock().unwrap() = None;
        net.refresh_tunnel_routes("utun9", address).unwrap();
        assert!(net.commands.sources.lock().unwrap().values().all(|source| *source == address));
        assert_eq!(net.commands.sources.lock().unwrap().len(), 2);
        assert_eq!(net.journal.routes.len(), 2);
        assert!(net.commands.calls.lock().unwrap().iter().all(|call| call[1] == "get" || call[1] == "change"));
        net.commands.interfaces.lock().unwrap().insert("0.0.0.0/1".into(), "utun99".into());
        assert!(net.refresh_tunnel_routes("utun9", address).is_err(), "foreign routes remain untouched");
    }

    #[test]
    fn source_refresh_refuses_foreign_routes_invalid_masks_and_interface_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = refresh_network(journal_path(dir.path()));
        let address = Ipv4Addr::new(198, 18, 0, 3);
        for invalid in ["en0", "utun", "utun9;anything"] {
            assert!(net.refresh_tunnel_routes(invalid, address).is_err());
        }
        assert!(net.commands.calls.lock().unwrap().is_empty());
        net.commands.interfaces.lock().unwrap().insert("0.0.0.0/1".into(), "utun99".into());
        assert!(net.refresh_tunnel_routes("utun9", address).is_err());
        net.commands.interfaces.lock().unwrap().insert("0.0.0.0/1".into(), "utun9".into());
        *net.commands.mask.lock().unwrap() = "255.255.255.0".into();
        assert!(net.refresh_tunnel_routes("utun9", address).is_err());
        *net.commands.mask.lock().unwrap() = "128.0.0.0".into();
        net.journal.routes.clear();
        assert!(net.refresh_tunnel_routes("utun9", address).is_err());
        assert!(net.commands.calls.lock().unwrap().iter().all(|call| call[1] == "get"));
    }

    struct EndpointMaintenance {
        path: PathBuf,
        routes: Mutex<std::collections::BTreeMap<String, DefaultRoute>>,
        calls: Mutex<Vec<Vec<String>>>,
        fail_change: Mutex<bool>,
        fail_delete: Mutex<Option<String>>,
    }
    impl Commands for EndpointMaintenance {
        fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
            assert_eq!(program, "/sbin/route", "endpoint maintenance must not alter DNS or IPv6");
            self.calls.lock().unwrap().push(arguments.to_vec());
            let destination = &arguments[if arguments[3] == "-host" { 4 } else { 3 }];
            let mut routes = self.routes.lock().unwrap();
            match arguments[1].as_str() {
                "get" => {
                    let route = routes.get(destination).context("not in table")?;
                    Ok(format!(
                        "destination: {destination}\ngateway: {}\ninterface: {}\nflags: <UP,GATEWAY,HOST,DONE,STATIC>\n",
                        route.gateway, route.interface
                    ))
                }
                "change" => {
                    assert_eq!(arguments[6], "-ifp");
                    let replacement = DefaultRoute { gateway: arguments[5].parse()?, interface: arguments[7].clone() };
                    let saved: Journal = serde_json::from_slice(&std::fs::read(&self.path)?)?;
                    assert!(saved.routes.iter().any(|route| route.destination == format!("{destination}/32")
                        && route.gateway == Some(replacement.gateway)
                        && route.interface == replacement.interface));
                    if *self.fail_change.lock().unwrap() {
                        bail!("injected change failure");
                    }
                    routes.insert(destination.clone(), replacement);
                    Ok(String::new())
                }
                "delete" => {
                    if self.fail_delete.lock().unwrap().as_ref() == Some(destination) {
                        bail!("injected delete failure");
                    }
                    routes.remove(destination);
                    Ok(String::new())
                }
                operation => panic!("unexpected endpoint operation {operation}"),
            }
        }
    }
    fn endpoint_network(path: PathBuf, ip: &str, current: DefaultRoute) -> Network<EndpointMaintenance> {
        let commands = EndpointMaintenance {
            path: path.clone(),
            routes: Mutex::new([(ip.into(), current.clone())].into()),
            calls: Mutex::new(vec![]),
            fail_change: Mutex::new(false),
            fail_delete: Mutex::new(None),
        };
        let mut network = Network::new(commands, 501, path);
        network.journal.routes.push(OwnedRoute {
            destination: format!("{ip}/32"),
            interface: current.interface,
            gateway: Some(current.gateway),
        });
        network
    }

    #[test]
    fn owned_endpoint_gateway_change_is_journaled_before_change_and_retry_does_not_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let ip = "203.0.113.10";
        let old = DefaultRoute { gateway: "192.168.1.1".parse().unwrap(), interface: "en0".into() };
        let mut net = endpoint_network(journal_path(dir.path()), ip, old.clone());
        let mut replacement = DefaultRoute { gateway: "192.168.2.1".parse().unwrap(), interface: "en1".into() };
        *net.commands.fail_change.lock().unwrap() = true;
        assert!(net.endpoint_routes(&replacement, &[ip.parse().unwrap()]).is_err());
        let saved: Journal = serde_json::from_slice(&std::fs::read(&net.path).unwrap()).unwrap();
        assert_eq!(saved.routes.len(), 2, "both possible owners remain recoverable after failure");
        assert_eq!(net.commands.routes.lock().unwrap()[ip], old);
        *net.commands.fail_change.lock().unwrap() = false;
        net.endpoint_routes(&replacement, &[ip.parse().unwrap()]).unwrap();
        net.endpoint_routes(&replacement, &[ip.parse().unwrap()]).unwrap();
        assert_eq!(net.journal.routes.len(), 2);
        assert_eq!(net.commands.routes.lock().unwrap()[ip], replacement);
        replacement.interface = "en2".into(); // Same gateway, new physical interface.
        net.endpoint_routes(&replacement, &[ip.parse().unwrap()]).unwrap();
        assert_eq!(net.commands.routes.lock().unwrap()[ip], replacement);
        let calls = net.commands.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|call| call[1] == "change").count(), 3);
        assert!(!calls.iter().any(|call| call[1] == "add" || call[1] == "delete"));
        drop(calls);
        net.cleanup_endpoints(&[]).unwrap();
        assert!(net.journal.routes.is_empty(), "all recorded gateway versions remain recoverable");
        assert!(net.commands.routes.lock().unwrap().is_empty());
    }

    #[test]
    fn endpoint_change_does_not_overwrite_a_route_replaced_by_another_owner() {
        let dir = tempfile::tempdir().unwrap();
        let ip = "203.0.113.10";
        let mut net = endpoint_network(
            journal_path(dir.path()),
            ip,
            DefaultRoute { gateway: "192.168.1.1".parse().unwrap(), interface: "en0".into() },
        );
        let foreign = DefaultRoute { gateway: "192.168.3.1".parse().unwrap(), interface: "en7".into() };
        net.commands.routes.lock().unwrap().insert(ip.into(), foreign.clone());
        net.endpoint_routes(
            &DefaultRoute { gateway: "192.168.2.1".parse().unwrap(), interface: "en1".into() },
            &[ip.parse().unwrap()],
        )
        .unwrap();
        assert_eq!(net.commands.routes.lock().unwrap()[ip], foreign);
        assert_eq!(net.journal.routes.len(), 1);
        assert!(net.commands.calls.lock().unwrap().iter().all(|call| call[1] == "get"));
    }

    #[test]
    fn endpoint_cleanup_preserves_capture_dns_ipv6_and_retains_failed_deletes_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let keep = "203.0.113.10";
        let obsolete = "203.0.113.11";
        let physical = DefaultRoute { gateway: "192.168.1.1".parse().unwrap(), interface: "en0".into() };
        let mut net = endpoint_network(journal_path(dir.path()), keep, physical.clone());
        net.commands.routes.lock().unwrap().insert(obsolete.into(), physical.clone());
        net.journal.routes.extend([
            OwnedRoute { destination: "0.0.0.0/1".into(), interface: "utun9".into(), gateway: None },
            OwnedRoute { destination: "128.0.0.0/1".into(), interface: "utun9".into(), gateway: None },
            OwnedRoute {
                destination: format!("{obsolete}/32"),
                interface: physical.interface,
                gateway: Some(physical.gateway),
            },
        ]);
        net.journal.ipv6.push(Service { name: "Wi-Fi".into(), original: Ipv6Mode::Automatic });
        net.journal.dns_key = Some("State:/Network/Service/NetworkRelayTun-501/DNS".into());
        let before = serde_json::to_value(&net.journal).unwrap();
        *net.commands.fail_delete.lock().unwrap() = Some(obsolete.into());
        assert!(net.cleanup_endpoints(&[keep.parse().unwrap()]).is_err());
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&net.path).unwrap()).unwrap();
        assert_eq!(saved, before, "a failed deletion must remain journaled");
        *net.commands.fail_delete.lock().unwrap() = None;
        net.cleanup_endpoints(&[keep.parse().unwrap()]).unwrap();
        assert_eq!(net.journal.routes.len(), 3);
        assert_eq!(net.journal.routes[0].destination, format!("{keep}/32"));
        assert_eq!(serde_json::to_value(&net.journal.ipv6).unwrap(), before["ipv6"]);
        assert_eq!(net.journal.dns_key.as_deref(), before["dns_key"].as_str());
        net.cleanup_endpoints(&[]).unwrap();
        assert_eq!(net.journal.routes.len(), 2);
        assert!(net.journal.routes.iter().all(|route| route.destination.ends_with("/1")));
        assert!(net.path.exists());
        assert!(net.commands.calls.lock().unwrap().iter().all(|call| !call.iter().any(|arg| arg.ends_with("/1"))));
    }

    #[test]
    fn endpoint_cache_cannot_claim_static_routes_or_routes_rejected_with_exists() {
        // Portable fixtures model the paired field outputs, not native Darwin
        // route selection or kernel command execution.
        struct Endpoint {
            path: PathBuf,
            snapshot: String,
            failure: Option<bool>, // Some(true): EEXIST; Some(false): unknown outcome.
            installed: Mutex<bool>,
            calls: Mutex<Vec<String>>,
        }
        impl Commands for Endpoint {
            fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
                if program == "/usr/sbin/netstat" {
                    assert_eq!(arguments, &["-nr", "-f", "inet"]);
                    ensure!(self.snapshot != "unavailable", "route snapshot unavailable");
                    return Ok(self.snapshot.clone());
                }
                assert_eq!(program, "/sbin/route");
                let operation = arguments[1].as_str();
                self.calls.lock().unwrap().push(operation.into());
                match operation {
                    "get" => {
                        let flags = if *self.installed.lock().unwrap()
                            || (arguments.get(3).is_some_and(|arg| arg == "-host")
                                && self.snapshot == "144.34.236.44 10.10.10.1 UGHS en1\n")
                        {
                            "<UP,GATEWAY,HOST,DONE,STATIC>"
                        } else {
                            "<UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>"
                        };
                        Ok(format!("destination: 144.34.236.44\ngateway: 10.10.10.1\ninterface: en1\nflags: {flags}\n"))
                    }
                    "add" => {
                        let saved: Journal = serde_json::from_slice(&std::fs::read(&self.path)?)?;
                        assert!(
                            saved.routes.iter().any(|route| route.destination == "144.34.236.44/32"),
                            "the recovery record must precede the command"
                        );
                        match self.failure {
                            Some(true) => {
                                Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "File exists").into())
                            }
                            Some(false) => {
                                *self.installed.lock().unwrap() = true;
                                bail!("command outcome unavailable");
                            }
                            None => {
                                *self.installed.lock().unwrap() = true;
                                Ok(String::new())
                            }
                        }
                    }
                    "delete" => {
                        *self.installed.lock().unwrap() = false;
                        Ok(String::new())
                    }
                    other => panic!("unexpected endpoint operation {other}"),
                }
            }
        }
        for (snapshot, failure, already_owned, expected_error, expected_routes, expected_adds, expected_deletes) in [
            ("144.34.236.44 10.10.10.1 UGHS en1\n", Some(false), false, false, 0, 0, 0),
            ("144.34.236.44 10.10.10.1 UGHS en1\n", Some(true), true, false, 1, 0, 1),
            ("unavailable", Some(true), false, true, 0, 0, 0),
            ("144.34.236.44/32 10.10.10.2 UGHS en7\n", Some(true), false, false, 0, 0, 0),
            ("144.34.236.44/32 10.10.10.2 UGS en7\n", Some(true), false, false, 0, 0, 0),
            (
                "144.34.236.44 10.10.10.1 UGHS en1\n144.34.236.44 10.10.10.2 UGHS en7\n",
                Some(true),
                false,
                true,
                0,
                0,
                0,
            ),
            ("144.34.236.44 link#8 UHS utun8\n", Some(true), false, true, 0, 0, 0),
            ("", Some(true), false, true, 0, 1, 0),
            ("144.34.236.44 10.10.10.1 UGHWI en1\n", Some(true), false, true, 0, 1, 0),
            ("", Some(true), true, true, 1, 1, 0),
            ("", Some(false), false, true, 1, 1, 1),
            ("", None, false, false, 1, 1, 1),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = journal_path(dir.path());
            let commands = Endpoint {
                path: path.clone(),
                snapshot: snapshot.into(),
                failure,
                installed: Mutex::new(false),
                calls: Mutex::new(vec![]),
            };
            let mut net = Network::new(commands, 501, path);
            if already_owned {
                net.journal.routes.push(OwnedRoute {
                    destination: "144.34.236.44/32".into(),
                    gateway: Some("10.10.10.1".parse().unwrap()),
                    interface: "en1".into(),
                });
            }
            let result = net.endpoint_routes(
                &DefaultRoute { gateway: "10.10.10.1".parse().unwrap(), interface: "en1".into() },
                &["144.34.236.44".parse().unwrap()],
            );
            assert_eq!(result.is_err(), expected_error, "{snapshot:?}, {failure:?}, owned={already_owned}");
            assert_eq!(net.journal.routes.len(), expected_routes);
            if net.path.exists() {
                let saved: Journal = serde_json::from_slice(&std::fs::read(&net.path).unwrap()).unwrap();
                assert_eq!(saved.routes.len(), expected_routes, "ownership changes must be persisted");
            }
            net.cleanup_endpoints(&[]).unwrap();
            let calls = net.commands.calls.lock().unwrap();
            assert_eq!(calls.iter().filter(|call| *call == "add").count(), expected_adds);
            assert_eq!(calls.iter().filter(|call| *call == "delete").count(), expected_deletes);
        }
    }

    #[test]
    fn cached_or_scoped_endpoint_route_gets_a_fixed_bypass_but_existing_static_route_is_preserved() {
        struct Endpoint {
            flags: String,
            installed: Mutex<bool>,
            adds: Mutex<usize>,
            deletes: Mutex<usize>,
        }
        impl Commands for Endpoint {
            fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
                if program == "/usr/sbin/netstat" {
                    return Ok(String::new());
                }
                if arguments[1] == "add" {
                    *self.installed.lock().unwrap() = true;
                    *self.adds.lock().unwrap() += 1;
                    return Ok(String::new());
                }
                if arguments[1] == "delete" {
                    *self.deletes.lock().unwrap() += 1;
                    return Ok(String::new());
                }
                let flags = if *self.installed.lock().unwrap() { "<UP,GATEWAY,HOST,DONE,STATIC>" } else { &self.flags };
                Ok(format!("destination: 34.4.108.158\ngateway: 10.90.95.12\ninterface: en0\nflags: {flags}\n"))
            }
        }
        for (flags, expected_adds) in [
            ("<UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>", 1),
            ("<UP,GATEWAY,HOST,DONE,STATIC,IFSCOPE>", 1),
            ("<UP,GATEWAY,HOST,DONE,STATIC>", 0),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let commands = Endpoint {
                flags: flags.into(),
                installed: Mutex::new(false),
                adds: Mutex::new(0),
                deletes: Mutex::new(0),
            };
            let mut net = Network::new(commands, 501, journal_path(dir.path()));
            net.endpoint_routes(
                &DefaultRoute { gateway: "10.90.95.12".parse().unwrap(), interface: "en0".into() },
                &["34.4.108.158".parse().unwrap()],
            )
            .unwrap();
            assert_eq!(*net.commands.adds.lock().unwrap(), expected_adds);
            net.cleanup().unwrap();
            assert_eq!(*net.commands.deletes.lock().unwrap(), expected_adds);
        }
    }
    #[test]
    fn dns_setup_does_not_gate_forwarding_on_resolver_display_order() {
        struct DnsCommands;
        impl Commands for DnsCommands {
            fn run(&self, program: &str, arguments: &[String], input: Option<&str>) -> Result<String> {
                assert_eq!(program, "/usr/sbin/scutil");
                assert!(arguments.is_empty(), "DNS setup must not poll resolver enumeration");
                let script = input.unwrap();
                if script.starts_with("show ") {
                    return Ok("<dictionary> {\n}\n".into());
                }
                assert!(script.contains("SupplementalMatchOrders * # 1000"));
                assert!(script.contains("set State:/Network/Service/NetworkRelayTun-501/DNS"));
                Ok(String::new())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut network = Network::new(DnsCommands, 501, journal_path(dir.path()));
        network.dns(&[Ipv4Addr::new(1, 1, 1, 1)]).unwrap();
        assert_eq!(network.journal.dns_key.as_deref(), Some("State:/Network/Service/NetworkRelayTun-501/DNS"));
    }
    use std::sync::Mutex;

    #[test]
    fn parallel_ipv6_inspection_failure_preserves_existing_journal_and_never_runs_setters() {
        struct Reads {
            fake: Fake,
            started: Mutex<usize>,
            ready: std::sync::Condvar,
            malformed: bool,
            routine: bool,
        }
        impl Commands for Reads {
            fn run(&self, executable: &str, arguments: &[String], input: Option<&str>) -> Result<String> {
                assert_eq!(ROUTINE.get(), self.routine, "IPv6 readers must inherit the caller's logging scope");
                let output = self.fake.run(executable, arguments, input)?;
                if arguments.first().is_some_and(|argument| argument == "-getinfo") {
                    let mut started = self.started.lock().unwrap();
                    *started += 1;
                    self.ready.notify_all();
                    let (started, _) =
                        self.ready.wait_timeout_while(started, Duration::from_secs(2), |n| *n < 2).unwrap();
                    ensure!(*started == 2, "the independent service reads did not run concurrently");
                    if arguments[1] == "USB Ethernet" {
                        if self.malformed {
                            return Ok("IPv6: Manual\nIPv6 IP address: 2001:db8::2\n".into());
                        }
                        bail!("injected IPv6 read failure");
                    }
                }
                Ok(output)
            }
        }
        for (malformed, routine) in [(false, false), (true, false), (false, true), (true, true)] {
            let _routine = routine.then(Routine::begin);
            let dir = tempfile::tempdir().unwrap();
            let mut network = Network::new(
                Reads {
                    fake: Fake::default(),
                    started: Mutex::new(0),
                    ready: std::sync::Condvar::new(),
                    malformed,
                    routine,
                },
                501,
                journal_path(dir.path()),
            );
            // A failed inspection must not re-disable even a previously saved
            // service whose IPv6 settings have since been re-enabled by macOS.
            network.journal.ipv6.push(Service { name: "Wi-Fi".into(), original: Ipv6Mode::LinkLocal });
            network.save().unwrap();
            let before = std::fs::read(&network.path).unwrap();
            let error = network.disable_ipv6().unwrap_err().to_string();
            assert!(error.contains(if malformed {
                "reading IPv6 configuration"
            } else {
                "injected IPv6 read failure"
            }));
            assert_eq!(*network.commands.started.lock().unwrap(), 2);
            assert_eq!(std::fs::read(&network.path).unwrap(), before);
            assert_eq!(network.journal.ipv6.len(), 1);
            assert!(network.commands.fake.calls.lock().unwrap().iter().all(|call| !call[1].starts_with("-setv6")));
        }
    }

    #[test]
    fn macos_wifi_off_output_without_mode_line_is_recognized() {
        let output = "DHCP Configuration\nIP address: 192.0.2.10\nSubnet mask: 255.255.255.0\nRouter: 192.0.2.1\nClient ID: \nIPv6 IP address: none\nIPv6 Router: none\nWi-Fi ID: 00:11:22:33:44:55\n";
        assert_eq!(ipv6_mode(output).unwrap(), Ipv6Mode::Off);
        assert_eq!(
            ipv6_mode("IPv6: Automatic\nIPv6 IP address: none\nIPv6 Router: none\n").unwrap(),
            Ipv6Mode::Automatic
        );
        assert!(ipv6_mode("IPv6: Unknown\nIPv6 IP address: none\nIPv6 Router: none\n").is_err());
        assert!(ipv6_mode("IPv6 IP address: none\n").is_err());
        assert!(ipv6_mode("IPv6 IP address: 2001:db8::1\nIPv6 Router: none\n").is_err());
    }

    #[test]
    fn hardware_mappings_distinguish_devices_from_service_branding() {
        let output = "An asterisk denotes disabled services.\n(1) Office Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(2) Stash\n(Hardware Port: VPN, Device: )\n(3) Shadowrocket\n(Hardware Port: VPN, Device: utun4)\n";
        let devices = service_devices(output).unwrap();
        assert!(hardware_device(&devices["Office Wi-Fi"]));
        assert!(!hardware_device(&devices["Stash"]));
        assert!(!hardware_device(&devices["Shadowrocket"]));
        assert!(service_devices("unrecognized output").is_err());
    }

    #[test]
    fn physical_default_ignores_split_tunnel_and_scoped_routes() {
        let table = "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n0/1 link#22 UCS utun9\n128.0/1 link#22 UCS utun9\ndefault 10.0.0.2 UGScIg en7\ndefault 192.168.1.1 UGScg en0\n";
        assert_eq!(
            physical_default(table).unwrap(),
            DefaultRoute { gateway: Ipv4Addr::new(192, 168, 1, 1), interface: "en0".into() }
        );
        assert!(physical_default("default link#22 UCS utun9\ndefault 192.168.1.1 UGScg en0\n").is_err());
        assert!(physical_default("default 10.0.0.2 UGScIg en7\n").is_err());
    }

    #[test]
    fn partial_tunnel_route_install_is_journaled_and_retryable() {
        struct PartialRoutes {
            path: PathBuf,
            installed: Mutex<BTreeSet<String>>,
            fail_second: Mutex<bool>,
            first_adds: Mutex<usize>,
        }
        impl Commands for PartialRoutes {
            fn run(&self, _: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
                let destination = arguments.get(4).context("missing route destination")?;
                if arguments[1] == "get" {
                    if self.installed.lock().unwrap().contains(destination) {
                        return Ok(format!(
                            "destination: {}\nmask: 128.0.0.0\ninterface: utun9\nflags: <UP,STATIC>\n",
                            destination.split('/').next().unwrap()
                        ));
                    }
                    return Ok("destination: default\nmask: default\ninterface: en0\n".into());
                }
                if arguments[1] == "add" {
                    let saved: Journal = serde_json::from_slice(&std::fs::read(&self.path)?)?;
                    assert!(saved.routes.iter().any(|route| &route.destination == destination));
                    if destination == "0.0.0.0/1" {
                        *self.first_adds.lock().unwrap() += 1;
                    }
                    if destination == "128.0.0.0/1" && *self.fail_second.lock().unwrap() {
                        *self.fail_second.lock().unwrap() = false;
                        bail!("injected failure installing second route");
                    }
                    self.installed.lock().unwrap().insert(destination.clone());
                }
                if arguments[1] == "delete" {
                    self.installed.lock().unwrap().remove(destination);
                }
                Ok(String::new())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = journal_path(dir.path());
        let commands = PartialRoutes {
            path: path.clone(),
            installed: Mutex::new(BTreeSet::new()),
            fail_second: Mutex::new(true),
            first_adds: Mutex::new(0),
        };
        let mut net = Network::new(commands, 501, path);
        assert!(net.tunnel_routes("utun9").is_err());
        assert_eq!(net.journal.routes.len(), 2);
        net.tunnel_routes("utun9").unwrap();
        assert_eq!(net.journal.routes.len(), 2);
        assert_eq!(*net.commands.first_adds.lock().unwrap(), 1);
        net.cleanup().unwrap();
        assert!(net.commands.installed.lock().unwrap().is_empty());
        assert!(!net.path.exists());
    }

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        fail_restore: bool,
        real_log_services: bool,
    }
    impl Commands for Fake {
        fn run(&self, program: &str, arguments: &[String], _input: Option<&str>) -> Result<String> {
            self.calls.lock().unwrap().push(std::iter::once(program.into()).chain(arguments.iter().cloned()).collect());
            if arguments.first().is_some_and(|s| s == "-listallnetworkservices") {
                if self.real_log_services {
                    return Ok("An asterisk denotes disabled services.\nThunderbolt Bridge\nWi-Fi\nShadowrocket\nStash\n*Disabled\n".into());
                }
                return Ok("An asterisk denotes disabled services.\nWi-Fi\nUSB Ethernet\n*Disabled\n".into());
            }
            if arguments.first().is_some_and(|s| s == "-listnetworkserviceorder") {
                return Ok(if self.real_log_services {
                    "(1) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(3) Shadowrocket\n(Hardware Port: VPN, Device: )\n(4) Stash\n(Hardware Port: VPN, Device: utun4)\n"
                } else {
                    "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(2) USB Ethernet\n(Hardware Port: USB Ethernet, Device: en1)\n(3) *Disabled\n(Hardware Port: Disabled, Device: en2)\n"
                }.into());
            }
            if arguments.first().is_some_and(|s| s == "-getinfo") {
                if self.real_log_services {
                    return Ok(if arguments[1] == "Wi-Fi" {
                        "DHCP Configuration\nIPv6 IP address: none\nIPv6 Router: none\n"
                    } else {
                        "DHCP Configuration\nIPv6: Automatic\nIPv6 IP address: none\nIPv6 Router: none\n"
                    }
                    .into());
                }
                return Ok(if arguments[1] == "Wi-Fi" { "IPv6: Automatic\n" } else { "IPv6: Link-local only\n" }.into());
            }
            if arguments.first().is_some_and(|s| s == "-setv6automatic") && self.fail_restore {
                bail!("injected restoration failure");
            }
            if program == "/sbin/route" && arguments.iter().any(|s| s == "get") {
                return Ok("destination: 128.0.0.0\nmask: 128.0.0.0\ninterface: utun9\nflags: <UP,STATIC>\n".into());
            }
            Ok(String::new())
        }
    }

    #[test]
    fn real_log_shape_preserves_wifi_off_and_never_queries_or_changes_vpn_services() {
        let dir = tempfile::tempdir().unwrap();
        let mut net =
            Network::new(Fake { real_log_services: true, ..Default::default() }, 501, journal_path(dir.path()));
        net.disable_ipv6().unwrap();
        assert_eq!(net.journal.ipv6.len(), 1);
        assert_eq!(net.journal.ipv6[0].name, "Thunderbolt Bridge");
        net.cleanup().unwrap();
        let calls = net.commands.calls.lock().unwrap();
        assert!(calls.iter().any(|call| call[1..] == ["-getinfo", "Wi-Fi"]));
        assert!(calls.iter().any(|call| call[1..] == ["-setv6off", "Thunderbolt Bridge"]));
        assert!(calls.iter().any(|call| call[1..] == ["-setv6automatic", "Thunderbolt Bridge"]));
        assert!(!calls.iter().any(|call| call.last().is_some_and(|name| name == "Shadowrocket" || name == "Stash")));
        assert!(!calls.iter().any(|call| call.get(1).is_some_and(|arg| arg.starts_with("-setv6"))
            && call.last().is_some_and(|name| name == "Wi-Fi")));
    }

    #[test]
    fn restores_original_service_modes_and_skips_disabled_services() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(Fake::default(), 501, journal_path(dir.path()));
        net.disable_ipv6().unwrap();
        assert_eq!(net.journal.ipv6.len(), 2);
        let recorded: Journal = serde_json::from_slice(&std::fs::read(&net.path).unwrap()).unwrap();
        assert_eq!(recorded.ipv6[0].original, Ipv6Mode::Automatic);
        net.cleanup().unwrap();
        let calls = net.commands.calls.lock().unwrap();
        assert!(calls.iter().any(|c| c[1..] == ["-setv6automatic", "Wi-Fi"]));
        assert!(calls.iter().any(|c| c[1..] == ["-setv6linklocal", "USB Ethernet"]));
        assert!(!calls.iter().flatten().any(|c| c.contains("Disabled")));
        assert!(!net.path.exists());
    }

    #[test]
    fn restoration_failure_keeps_only_unrestored_state_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(Fake { fail_restore: true, ..Default::default() }, 501, journal_path(dir.path()));
        net.disable_ipv6().unwrap();
        assert!(net.cleanup().is_err());
        assert_eq!(net.journal.ipv6.len(), 1);
        assert_eq!(net.journal.ipv6[0].name, "Wi-Fi");
        net.commands.fail_restore = false;
        net.cleanup().unwrap();
        assert!(!net.path.exists());
    }

    #[test]
    fn cleanup_does_not_delete_a_replaced_route() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(Fake::default(), 501, journal_path(dir.path()));
        net.journal.routes.push(OwnedRoute {
            destination: "128.0.0.0/1".into(),
            interface: "utun8".into(),
            gateway: None,
        });
        net.cleanup().unwrap();
        assert!(!net.commands.calls.lock().unwrap().iter().any(|c| c.iter().any(|a| a == "delete")));
    }

    #[test]
    fn active_capture_checks_both_route_tables_and_preserves_a_replaced_dns_entry() {
        struct Observations {
            v6: String,
            dns: String,
        }
        impl Commands for Observations {
            fn run(&self, program: &str, arguments: &[String], input: Option<&str>) -> Result<String> {
                match program {
                    "/usr/sbin/netstat" if arguments == ["-rn", "-f", "inet6"] => Ok(self.v6.clone()),
                    "/usr/sbin/scutil"
                        if input == Some("show State:/Network/Service/NetworkRelayTun-501/DNS\nquit\n") =>
                    {
                        Ok(self.dns.clone())
                    }
                    _ => bail!("unexpected mutation or query: {program} {arguments:?} {input:?}"),
                }
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let v4 = "0/1 link#1 US utun8\n128/1 link#1 US utun8\n";
        let v6 = "Destination Gateway Flags Netif\n::/1 utun8 US utun8\n8000::/1 utun8 US utun8\n";
        let dns = "<dictionary> {\n  SearchOrder : 1000\n}";
        let key = "State:/Network/Service/NetworkRelayTun-501/DNS";
        let commands = Observations { v6: v6.into(), dns: dns.into() };
        let mut net = Network::new(commands, 501, journal_path(directory.path()));
        for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
            net.journal.routes.push(OwnedRoute {
                destination: destination.into(),
                gateway: None,
                interface: "utun8".into(),
            });
        }
        for destination in ["::/1", "8000::/1"] {
            net.journal
                .ipv6_routes
                .push(crate::ipv6::CaptureRoute { destination: destination.into(), interface: "utun8".into() });
        }
        net.journal.dns_key = Some(key.into());
        net.journal.dns_snapshot = Some(dns.into());
        net.verify_active("utun8", v4).unwrap();
        assert!(net.verify_active("utun8", &v4.replace("128/1", "default")).is_err());
        assert!(net.verify_active("utun8", &v4.replace(" US ", " UGS ")).is_err());
        net.commands.v6 = v6.replace("8000::/1", "default");
        assert!(net.verify_active("utun8", v4).is_err());
        net.commands.v6 = v6.into();
        net.commands.dns = dns.replace("1000", "2000");
        assert!(net.verify_active("utun8", v4).is_err());
        net.remove_dns(key).unwrap();
    }

    #[test]
    fn ipv6_only_relay_uses_the_physical_scope_without_reading_ipv4_defaults() {
        struct Route(&'static str);
        impl Commands for Route {
            fn run(&self, program: &str, arguments: &[String], _: Option<&str>) -> Result<String> {
                ensure!(
                    program == "/sbin/route"
                        && (arguments == ["-n", "get", "-inet6", "2001:db8::4"]
                            || arguments == ["-n", "get", "-inet6", "-ifscope", "en3", "2001:db8::4"]),
                    "unexpected route lookup"
                );
                Ok(format!("interface: {}\nflags: <UP,GATEWAY,STATIC>\n", self.0))
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let mut net = Network::new(Route("en3"), 501, journal_path(directory.path()));
        let endpoints = ["2001:db8::4".parse().unwrap()];
        assert_eq!(net.relay_paths(&endpoints, None, None).unwrap().as_deref(), Some("en3"));
        assert_eq!(net.relay_paths(&endpoints, None, Some("en3")).unwrap().as_deref(), Some("en3"));
        net.commands.0 = "en0";
        assert!(net.relay_paths(&endpoints, None, Some("en3")).is_err());
        net.commands.0 = "utun8";
        assert!(net.relay_paths(&endpoints, None, None).is_err());
        assert!(!net.path.exists());
    }

    #[test]
    fn cleanup_removes_an_exact_owned_route() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = Network::new(Fake::default(), 501, journal_path(dir.path()));
        net.journal.routes.push(OwnedRoute {
            destination: "128.0.0.0/1".into(),
            interface: "utun9".into(),
            gateway: None,
        });
        net.cleanup().unwrap();
        assert!(net.commands.calls.lock().unwrap().iter().any(|c| c.iter().any(|a| a == "delete")));
    }

    #[test]
    fn manual_ipv6_without_a_restorable_prefix_is_rejected() {
        assert!(ipv6_mode("IPv6: Manual\nIPv6 IP address: 2001:db8::1\nIPv6 Router: 2001:db8::2\n").is_err());
        assert_eq!(ipv6_mode("IPv6: Off\n").unwrap(), Ipv6Mode::Off);
    }
}

#[cfg(test)]
mod boot_tests {
    use super::*;
    struct NoCommands;
    impl Commands for NoCommands {
        fn run(&self, _: &str, _: &[String], _: Option<&str>) -> Result<String> {
            panic!("old boot must not mutate current networking")
        }
    }
    #[test]
    fn old_boot_journal_is_retired_without_network_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = Network::new(NoCommands, 501, dir.path().join("network.json"));
        n.begin_boot("11111111-1111-1111-1111-111111111111").unwrap();
        n.journal.routes.push(OwnedRoute { destination: "0.0.0.0/1".into(), interface: "utun4".into(), gateway: None });
        n.journal.dns_key = Some("State:/Network/Service/NetworkRelayTun/DNS".into());
        n.save().unwrap();
        n.begin_boot("22222222-2222-2222-2222-222222222222").unwrap();
        n.cleanup().unwrap();
        assert!(n.journal.routes.is_empty());
        assert!(!dir.path().join("network.json").exists());
    }
    #[test]
    fn reused_interface_name_preserves_foreign_capture_routes() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = Network::new(NoCommands, 501, dir.path().join("network.json"));
        n.journal.capture_interface = Some(("utun4".into(), 17));
        n.journal.routes.push(OwnedRoute { destination: "0.0.0.0/1".into(), interface: "utun4".into(), gateway: None });
        n.journal.ipv6_routes.push(crate::ipv6::CaptureRoute { destination: "::/1".into(), interface: "utun4".into() });
        n.reconcile_capture_interface(17);
        assert_eq!(n.journal.routes.len(), 1);
        n.reconcile_capture_interface(18);
        assert!(n.journal.routes.is_empty() && n.journal.ipv6_routes.is_empty());
        n.cleanup().unwrap();
    }

    #[test]
    fn same_boot_keeps_recovery_and_missing_identity_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = Network::new(NoCommands, 501, dir.path().join("network.json"));
        let boot = "11111111-1111-1111-1111-111111111111";
        n.begin_boot(boot).unwrap();
        n.journal.dns_key = Some("owned".into());
        n.begin_boot(boot).unwrap();
        assert!(n.journal.dns_key.is_some());
        n.journal.boot_session = None;
        assert!(n.begin_boot(boot).is_err());
        assert!(n.begin_boot("invalid").is_err());
    }
}
