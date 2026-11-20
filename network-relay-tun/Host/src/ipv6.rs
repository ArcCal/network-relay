//! Ownership checks for IPv6 capture routes. IPv6 service settings stay intact.
use crate::network::{Commands, route_fields};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRoute {
    pub destination: String,
    pub interface: String,
}
impl CaptureRoute {
    pub fn validate(&self) -> Result<()> {
        ensure!(matches!(self.destination.as_str(), "::/1" | "8000::/1"), "invalid IPv6 capture destination");
        ensure!(
            self.interface.strip_prefix("utun").is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
            "invalid utun interface"
        );
        Ok(())
    }
}

pub fn snapshot(commands: &dyn Commands) -> Result<String> {
    commands.run("/usr/sbin/netstat", &["-rn".into(), "-f".into(), "inet6".into()], None)
}

/// The kernel selects the IPv6 uplink before capture. During capture ask for
/// the route scoped to the same interface as the outer Network.framework socket.
pub fn endpoint_interface(commands: &dyn Commands, address: Ipv6Addr, scope: Option<&str>) -> Result<String> {
    let mut args = vec!["-n".into(), "get".into(), "-inet6".into()];
    if let Some(interface) = scope {
        args.extend(["-ifscope".into(), interface.into()]);
    }
    args.push(address.to_string());
    let fields = route_fields(&commands.run("/sbin/route", &args, None)?);
    let interface = fields.get("interface").context("IPv6 route has no interface")?;
    let flags = fields.get("flags").context("IPv6 route has no flags")?;
    let mut flags = flags.trim_matches(['<', '>']).split(',');
    ensure!(
        flags.clone().any(|f| f == "UP")
            && !flags.any(|f| matches!(f, "REJECT" | "BLACKHOLE" | "LOCAL"))
            && !interface.starts_with("utun")
            && !interface.starts_with("lo")
            && !interface.is_empty()
            && interface.bytes().all(|b| b.is_ascii_alphanumeric())
            && scope.is_none_or(|expected| interface == expected),
        "IPv6 relay has no usable physical interface"
    );
    Ok(interface.clone())
}

/// Require a recognized header, unique exact prefix and unscoped route.
/// A default or more-specific route is never mistaken for our capture route.
fn capture_row<'a>(table: &'a str, prefix: &str) -> Result<Option<(&'a str, &'a str)>> {
    let mut columns = None;
    let mut found = None;
    for line in table.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"Destination") {
            let interface = fields
                .iter()
                .position(|s| *s == "Netif")
                .ok_or_else(|| anyhow::anyhow!("unrecognized IPv6 route table"))?;
            let flags = fields
                .iter()
                .position(|s| *s == "Flags")
                .ok_or_else(|| anyhow::anyhow!("unrecognized IPv6 route table"))?;
            columns = Some((interface, flags));
            continue;
        }
        let Some((interface, flags)) = columns else { continue };
        if fields.first() != Some(&prefix) {
            continue;
        }
        ensure!(fields.len() > interface.max(flags), "truncated IPv6 route record");
        if fields[flags].contains('I') {
            continue;
        }
        ensure!(found.is_none(), "ambiguous IPv6 capture route");
        found = Some((fields[interface], fields[flags]));
    }
    ensure!(columns.is_some(), "missing IPv6 route table header");
    Ok(found)
}

pub fn interface_for<'a>(table: &'a str, prefix: &str) -> Result<Option<&'a str>> {
    Ok(capture_row(table, prefix)?.map(|(interface, _)| interface))
}

pub fn owns_capture(table: &str, prefix: &str, interface: &str) -> Result<bool> {
    Ok(capture_row(table, prefix)?
        .is_some_and(|(name, flags)| name == interface && flags.contains('U') && !flags.contains(['G', 'B', 'R'])))
}

pub fn remove_owned(commands: &dyn Commands, route: &CaptureRoute) -> Result<()> {
    route.validate()?;
    let table = snapshot(commands)?;
    if !owns_capture(&table, &route.destination, &route.interface)? {
        return Ok(());
    }
    commands.run(
        "/sbin/route",
        &[
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "-net".into(),
            route.destination.clone(),
            "-interface".into(),
            route.interface.clone(),
        ],
        None,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake {
        table: String,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl Commands for Fake {
        fn run(&self, executable: &str, args: &[String], _: Option<&str>) -> Result<String> {
            if executable == "/usr/sbin/netstat" {
                return Ok(self.table.clone());
            }
            self.calls.lock().unwrap().push(args.to_vec());
            Ok(String::new())
        }
    }
    #[test]
    fn cleanup_does_not_remove_replacement_or_default_routes() {
        let route = CaptureRoute { destination: "::/1".into(), interface: "utun8".into() };
        for (rows, count) in [
            ("default fe80::1%en0 UG en0\n", 0),
            ("::/1 utun9 US utun9\n", 0),
            ("::/1 utun8 US utun8\n", 1),
            ("::/1 utun8 USI utun8\n", 0),
            ("::/1 fe80::1 UGS utun8\n", 0),
            ("::/1 utun8 UR utun8\n", 0),
            ("::/1 utun8 UB utun8\n", 0),
        ] {
            let commands = Fake {
                table: format!("Routing tables\nInternet6:\nDestination Gateway Flags Netif Expire\n{rows}"),
                calls: Mutex::default(),
            };
            remove_owned(&commands, &route).unwrap();
            assert_eq!(commands.calls.lock().unwrap().len(), count);
        }
    }
    #[test]
    fn ambiguous_or_unrecognized_snapshots_fail_before_mutation() {
        for table in ["garbage", "Destination Gateway Flags Netif\n::/1 utun8 US utun8\n::/1 utun9 US utun9\n"] {
            assert!(interface_for(table, "::/1").is_err());
        }
        assert!(CaptureRoute { destination: "::/0".into(), interface: "utun8".into() }.validate().is_err());
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;
    use crate::network::{Journal, Network};
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };
    struct Fake {
        path: PathBuf,
        installed: Arc<Mutex<Vec<String>>>,
        fail_add_upper: bool,
        fail_delete: Arc<Mutex<bool>>,
    }
    impl Commands for Fake {
        fn run(&self, executable: &str, args: &[String], _: Option<&str>) -> Result<String> {
            if executable == "/usr/sbin/netstat" {
                let rows =
                    self.installed.lock().unwrap().iter().map(|d| format!("{d} utun8 US utun8\n")).collect::<String>();
                return Ok(format!("Destination Gateway Flags Netif Expire\n{rows}"));
            }
            ensure!(executable == "/sbin/route", "unexpected command");
            let destination = args[4].clone();
            let saved: Journal = serde_json::from_slice(&std::fs::read(&self.path)?)?;
            ensure!(
                saved.ipv6_routes.iter().any(|r| r.destination == destination),
                "mutation preceded durable journal"
            );
            if args[1] == "add" {
                ensure!(!(self.fail_add_upper && destination == "8000::/1"), "injected add failure");
                self.installed.lock().unwrap().push(destination);
            } else {
                ensure!(!*self.fail_delete.lock().unwrap(), "injected removal failure");
                self.installed.lock().unwrap().retain(|r| *r != destination);
            }
            Ok(String::new())
        }
    }
    #[test]
    fn partial_activation_and_failed_recovery_keep_retryable_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.json");
        let installed = Arc::new(Mutex::new(Vec::new()));
        let fail_delete = Arc::new(Mutex::new(false));
        let fake = Fake {
            path: path.clone(),
            installed: installed.clone(),
            fail_add_upper: true,
            fail_delete: fail_delete.clone(),
        };
        let mut network = Network::new(fake, 501, path.clone());
        assert!(network.tunnel_routes_v6("utun8").is_err());
        assert_eq!(*installed.lock().unwrap(), ["::/1"]);
        *fail_delete.lock().unwrap() = true;
        assert!(network.cleanup().is_err());
        let journal: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(journal.ipv6_routes.len(), 1);
        assert_eq!(journal.ipv6_routes[0].destination, "::/1");
        *fail_delete.lock().unwrap() = false;
        network.cleanup().unwrap();
        assert!(installed.lock().unwrap().is_empty());
        assert!(!path.exists());
    }
}
