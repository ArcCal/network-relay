//! Independent application settings and NF-compatible explicit imports.
//!
//! This module never reads another application's private settings. Exported
//! TOML remains compatible with Network Realy NF, including omitted passwords.
use network_relay_rs_core as core;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const UDP_PATH: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Transport {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "h3")]
    H3,
    #[serde(rename = "h2")]
    H2,
    #[serde(rename = "http/1.1")]
    Http1,
}
impl Transport {
    pub const ALL: [Self; 4] = [Self::Auto, Self::H3, Self::H2, Self::Http1];
    pub fn title(self) -> &'static str {
        match self {
            Self::Auto => "Automatic (HTTP/3 first, TCP if it cannot connect)",
            Self::H3 => "HTTP/3 (QUIC, UDP)",
            Self::H2 => "HTTP/2 (TCP)",
            Self::Http1 => "HTTP/1.1 (TCP)",
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::H3 => "h3",
            Self::H2 => "h2",
            Self::Http1 => "http/1.1",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Errors,
    Warnings,
    #[default]
    Normal,
    Detailed,
    Everything,
}
impl LogLevel {
    pub const ALL: [Self; 5] = [Self::Errors, Self::Warnings, Self::Normal, Self::Detailed, Self::Everything];
    pub fn title(self) -> &'static str {
        match self {
            Self::Errors => "Errors Only",
            Self::Warnings => "Warnings and Errors",
            Self::Normal => "Normal",
            Self::Detailed => "Detailed",
            Self::Everything => "Everything",
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Errors => "errors",
            Self::Warnings => "warnings",
            Self::Normal => "normal",
            Self::Detailed => "detailed",
            Self::Everything => "everything",
        }
    }
    pub fn value(self) -> u32 {
        match self {
            Self::Errors => 0,
            Self::Warnings => 1,
            Self::Normal => 2,
            Self::Detailed => 3,
            Self::Everything => 4,
        }
    }
    /// Keep third-party packet/header traces off, including at Everything.
    pub fn tracing_filter(self) -> &'static str {
        match self {
            Self::Errors => "error",
            Self::Warnings => "warn",
            Self::Normal => "info",
            Self::Detailed => "info,network_relay_rs_core=debug,network_relay_rs=debug",
            Self::Everything => "info,network_relay_rs_core=trace,network_relay_rs=trace",
        }
    }
    pub fn shows(self, line: &str) -> bool {
        log_rank(line).is_none_or(|rank| rank <= self.value())
    }
}

fn new_id() -> Uuid {
    Uuid::new_v4()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Server {
    #[serde(default = "new_id")]
    pub id: Uuid,
    pub name: String,
    pub domain: String,
    #[serde(alias = "serverIP")]
    pub server_ip: String,
    pub username: String,
    pub password: String,
    pub transport: Transport,
}
impl Default for Server {
    fn default() -> Self {
        Self {
            id: new_id(),
            name: String::new(),
            domain: String::new(),
            server_ip: String::new(),
            username: String::new(),
            password: String::new(),
            transport: Transport::Auto,
        }
    }
}
impl Server {
    pub fn title(&self) -> &str {
        if !self.name.trim().is_empty() {
            self.name.trim()
        } else if !self.domain.trim().is_empty() {
            self.domain.trim()
        } else {
            "New Server"
        }
    }
    /// Empty drafts may be saved, but never become a connection to another server.
    pub fn is_blank(&self) -> bool {
        self.name.trim().is_empty()
            && self.domain.trim().is_empty()
            && self.server_ip.trim().is_empty()
            && self.username.trim().is_empty()
            && self.password.is_empty()
            && self.transport == Transport::Auto
    }
    fn same_without_id(&self, other: &Self) -> bool {
        self.name == other.name
            && self.domain == other.domain
            && self.server_ip == other.server_ip
            && self.username == other.username
            && self.password == other.password
            && self.transport == other.transport
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Configuration {
    pub servers: Vec<Server>,
    pub selected_server_id: Option<Uuid>,
    pub listen_address: String,
    pub port: u16,
    pub connect_on_launch: bool,
    pub log_level: LogLevel,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            selected_server_id: None,
            listen_address: "127.0.0.1".into(),
            port: 1080,
            connect_on_launch: false,
            log_level: LogLevel::Normal,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelError(pub String);
impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for ModelError {}
impl From<io::Error> for ModelError {
    fn from(e: io::Error) -> Self {
        Self(e.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferScope {
    All,
    Servers,
    Application,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientChange {
    None,
    Reconnect,
    Disconnect,
}

impl Configuration {
    fn selected_index(&self) -> Option<usize> {
        self.selected_server_id
            .and_then(|id| self.servers.iter().position(|s| s.id == id))
            .or_else(|| (!self.servers.is_empty()).then_some(0))
    }
    pub fn selected_server(&self) -> Option<&Server> {
        self.selected_index().map(|i| &self.servers[i])
    }
    pub fn selected_server_mut(&mut self) -> Option<&mut Server> {
        self.selected_index().map(|i| &mut self.servers[i])
    }
    pub fn proxy_address(&self) -> String {
        socket_address(self.listen_address.trim(), self.port)
    }
    pub fn listens_only_locally(&self) -> bool {
        self.listen_address.trim().parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
    fn listen(&self) -> Result<SocketAddr, ModelError> {
        let ip = self
            .listen_address
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| ModelError("The listen address must be an IP address, such as 127.0.0.1.".into()))?;
        if self.port == 0 {
            return Err(ModelError("The port must be between 1 and 65535.".into()));
        }
        Ok(SocketAddr::new(ip, self.port))
    }
    pub fn check(&self) -> Result<(), ModelError> {
        self.listen()?;
        let mut ids = HashSet::new();
        for server in &self.servers {
            if !ids.insert(server.id) {
                return Err(ModelError("Each server must have a unique UUID.".into()));
            }
            if !server.is_blank() {
                self.config_for(server).map_err(|e| ModelError(format!("{}: {e}", server.title())))?;
            }
        }
        Ok(())
    }
    pub fn core_config(&self) -> Result<core::Config, ModelError> {
        self.config_for(self.selected_server().ok_or_else(|| ModelError("Add a server before connecting.".into()))?)
    }
    pub fn config_for(&self, server: &Server) -> Result<core::Config, ModelError> {
        let (host, port) = parse_domain(&server.domain)?;
        let address = server.server_ip.trim();
        if !address.is_empty() && address.parse::<IpAddr>().is_err() {
            return Err(ModelError(
                "The server IP is not valid. Example: 203.0.113.5; leave it empty if you do not know it.".into(),
            ));
        }
        let username = server.username.trim();
        if username.is_empty() {
            return Err(ModelError("Enter the username.".into()));
        }
        if username.len() > 64
            || username.starts_with('.')
            || !username.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(ModelError("The username may contain only letters, digits, '-', '_' and '.', up to 64 characters, and must not start with '.'.".into()));
        }
        if server.password.is_empty() {
            return Err(ModelError("Enter the password.".into()));
        }
        if server.password.chars().any(char::is_control) {
            return Err(ModelError("The password must not contain control characters such as line breaks.".into()));
        }
        Ok(core::Config {
            uri_template: format!(
                "https://{}{UDP_PATH}",
                socket_address(if address.is_empty() { &host } else { address }, port)
            ),
            server_name: (!address.is_empty()).then_some(host),
            username: username.into(),
            password: server.password.clone(),
            transport: server.transport.as_str().into(),
            probe_target: "1.1.1.1:53".parse().expect("literal address"),
            mode: "socks".into(),
            socks: core::Socks { listen: vec![self.listen()?] },
        })
    }
    pub fn client_config_toml(&self) -> Result<String, ModelError> {
        let config = self.core_config()?;
        let mut lines = vec![format!("uri_template = {}", toml_string(&config.uri_template))];
        if let Some(name) = config.server_name {
            lines.push(format!("server_name = {}", toml_string(&name)));
        }
        lines.push(format!("username = {}", toml_string(&config.username)));
        lines.push(format!("password = {}", toml_string(&config.password)));
        if config.transport != "auto" {
            lines.push(format!("transport = {}", toml_string(&config.transport)));
        }
        lines.extend([
            "mode = \"socks\"".into(),
            "".into(),
            "[socks]".into(),
            format!("listen = [{}]", toml_string(&config.socks.listen[0].to_string())),
        ]);
        Ok(lines.join("\n") + "\n")
    }
    pub fn default_path() -> PathBuf {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join("Library/Application Support/NetworkRelayRS/configuration.json")
    }
    /// Missing files return defaults; malformed files remain untouched on disk.
    pub fn load(path: impl AsRef<Path>) -> Self {
        Self::try_load(path).unwrap_or_default()
    }
    pub fn try_load(path: impl AsRef<Path>) -> Result<Self, ModelError> {
        let bytes = fs::read(path)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(ModelError("The settings file is too large.".into()));
        }
        let mut config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| ModelError("The saved settings file is not valid JSON settings.".into()))?;
        let mut ids = HashSet::new();
        for server in &mut config.servers {
            if !ids.insert(server.id) {
                server.id = new_id();
                ids.insert(server.id);
            }
        }
        if !config.servers.iter().any(|s| Some(s.id) == config.selected_server_id) {
            config.selected_server_id = config.servers.first().map(|s| s.id);
        }
        Ok(config)
    }
    /// A private temporary file and atomic rename preserve the previous save.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ModelError> {
        let path = path.as_ref();
        let folder = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(folder)?;
        if fs::symlink_metadata(folder)?.file_type().is_symlink() {
            return Err(ModelError("The settings directory must not be a symbolic link.".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(folder, fs::Permissions::from_mode(0o700))?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| ModelError(e.to_string()))?;
        write_privately(&bytes, path)
    }

    pub fn exported_toml(&self, with_passwords: bool, scope: TransferScope) -> String {
        let mut lines = vec![
            "# Network Relay RS settings; compatible with Network Realy NF imports.".into(),
            if scope == TransferScope::Application {
                "# Application settings only; servers and passwords are left out.".into()
            } else if with_passwords {
                "# The file holds passwords: keep it private.".into()
            } else {
                "# Passwords are left out: enter them after importing.".into()
            },
        ];
        if scope != TransferScope::Servers {
            lines.extend([
                "".into(),
                "[proxy]".into(),
                format!("listen_address = {}", toml_string(&self.listen_address)),
                format!("port = {}", self.port),
                format!("connect_on_launch = {}", self.connect_on_launch),
                format!("log_level = {}", toml_string(self.log_level.as_str())),
            ]);
        }
        if scope != TransferScope::Application {
            for server in &self.servers {
                lines.extend(["".into(), "[[server]]".into(), format!("id = {}", toml_string(&server.id.to_string()))]);
                if !server.name.is_empty() {
                    lines.push(format!("name = {}", toml_string(&server.name)));
                }
                lines.push(format!("domain = {}", toml_string(&server.domain)));
                if !server.server_ip.is_empty() {
                    lines.push(format!("ip = {}", toml_string(&server.server_ip)));
                }
                lines.push(format!("username = {}", toml_string(&server.username)));
                if with_passwords && !server.password.is_empty() {
                    lines.push(format!("password = {}", toml_string(&server.password)));
                }
                lines.push(format!("transport = {}", toml_string(server.transport.as_str())));
                if self.selected_server().is_some_and(|s| s.id == server.id) {
                    lines.push("selected = true".into());
                }
            }
        }
        lines.join("\n") + "\n"
    }

    pub fn importing(text: &str, scope: TransferScope, base: &Self) -> Result<Self, ModelError> {
        if text.len() > 4 * 1024 * 1024 {
            return Err(ModelError("The settings file is too large.".into()));
        }
        let doc: toml::Table =
            toml::from_str(text).map_err(|_| ModelError("The file is not a TOML settings file.".into()))?;
        if doc.contains_key("uri_template") && !doc.contains_key("server") {
            return Self::import_core(&doc, scope, base);
        }
        if !doc.contains_key("server") && !doc.contains_key("proxy") {
            return Err(ModelError("The file holds neither app settings nor a relay client configuration.".into()));
        }
        let mut config = base.clone();
        let mut application_present = false;
        if scope != TransferScope::Servers
            && let Some(proxy) = table(&doc, "proxy", "")?
        {
            application_present =
                ["listen_address", "port", "connect_on_launch", "log_level"].iter().any(|key| proxy.contains_key(*key));
            if let Some(address) = string(proxy, "listen_address", "[proxy]")? {
                config.listen_address = address.into();
            }
            if let Some(port) = integer(proxy, "port", "[proxy]")? {
                config.port = checked_port(port)?;
            }
            if let Some(flag) = boolean(proxy, "connect_on_launch", "[proxy]")? {
                config.connect_on_launch = flag;
            }
            if let Some(level) = string(proxy, "log_level", "[proxy]")? {
                config.log_level = LogLevel::ALL.into_iter().find(|l| l.as_str() == level).ok_or_else(|| {
                    ModelError("'log_level' must be errors, warnings, normal, detailed or everything.".into())
                })?;
            }
            if proxy.contains_key("listen_address") || proxy.contains_key("port") {
                config.listen()?;
            }
        }
        if scope == TransferScope::Application {
            if !application_present {
                return Err(ModelError("The file has no application settings.".into()));
            }
            return Ok(config);
        }
        // Importing a proxy-only file must not silently remove existing servers.
        if !doc.contains_key("server") && scope == TransferScope::All && application_present {
            return Ok(config);
        }
        let values = doc
            .get("server")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| ModelError("The file has no server ([[server]]).".into()))?;
        if values.is_empty() {
            return Err(ModelError("The file has no server ([[server]]).".into()));
        }
        config.servers.clear();
        config.selected_server_id = None;
        let mut ids = HashSet::new();
        for (index, value) in values.iter().enumerate() {
            let place = format!("server {}", index + 1);
            let t = value.as_table().ok_or_else(|| ModelError(format!("'{place}' must be a server table.")))?;
            let mut server = Server::default();
            if let Some(id) = string(t, "id", &place)? {
                server.id = Uuid::parse_str(id)
                    .map_err(|_| ModelError(format!("'id' in {place} must be a valid, unique UUID.")))?;
            }
            if !ids.insert(server.id) {
                return Err(ModelError(format!("'id' in {place} must be a valid, unique UUID.")));
            }
            server.name = string(t, "name", &place)?.unwrap_or("").into();
            server.domain = string(t, "domain", &place)?.unwrap_or("").into();
            server.server_ip = string(t, "ip", &place)?.unwrap_or("").into();
            server.username = string(t, "username", &place)?.unwrap_or("").into();
            server.password = string(t, "password", &place)?.unwrap_or("").into();
            server.transport = read_transport(t, &place)?;
            if boolean(t, "selected", &place)? == Some(true) && config.selected_server_id.is_none() {
                config.selected_server_id = Some(server.id);
            }
            config.servers.push(server);
        }
        config.selected_server_id = config.selected_server().map(|s| s.id);
        Ok(config)
    }

    fn import_core(doc: &toml::Table, scope: TransferScope, base: &Self) -> Result<Self, ModelError> {
        let mut config = base.clone();
        if scope != TransferScope::Application {
            let template =
                string(doc, "uri_template", "")?.ok_or_else(|| ModelError("The file has no URI template.".into()))?;
            let authority = template.strip_prefix("https://").and_then(|s| s.strip_suffix(UDP_PATH)).ok_or_else(|| ModelError("The URI template must be https://<domain>/.well-known/masque/udp/{target_host}/{target_port}/.".into()))?;
            if authority.is_empty() || authority.contains(['/', '@', '?', '#']) {
                return Err(ModelError("The relay URI authority is not valid.".into()));
            }
            let (host, port) = parse_authority(authority)?;
            let domain = string(doc, "server_name", "")?;
            let mut server = Server::default();
            if let Some(name) = domain {
                server.domain = domain_with_port(name, port);
                server.server_ip = host;
            } else {
                server.domain = domain_with_port(&host, port);
            }
            server.username = string(doc, "username", "")?.unwrap_or("").into();
            server.password = string(doc, "password", "")?.unwrap_or("").into();
            server.transport = read_transport(doc, "")?;
            config.selected_server_id = Some(server.id);
            config.servers = vec![server];
        }
        let socks = if scope != TransferScope::Servers { table(doc, "socks", "")? } else { None };
        if let Some(socks) = socks.filter(|s| s.contains_key("listen")) {
            let v = socks.get("listen").expect("present");
            let listens: Vec<&str> = if let Some(s) = v.as_str() {
                vec![s]
            } else {
                v.as_array()
                    .ok_or_else(|| {
                        ModelError("'listen' in [socks] must be an IP address and port or a list of them.".into())
                    })?
                    .iter()
                    .map(|item| {
                        item.as_str().ok_or_else(|| ModelError("Every SOCKS listener must be a string.".into()))
                    })
                    .collect::<Result<_, _>>()?
            };
            if listens.is_empty() {
                return Err(ModelError("'listen' in [socks] must contain an IP address and port.".into()));
            }
            for (i, listen) in listens.into_iter().enumerate() {
                let address: SocketAddr = listen
                    .parse()
                    .map_err(|_| ModelError("'listen' in [socks] must contain an IP address and port.".into()))?;
                if address.port() == 0 {
                    return Err(ModelError("The port must be between 1 and 65535.".into()));
                }
                if i == 0 {
                    config.listen_address = address.ip().to_string();
                    config.port = address.port();
                }
            }
        } else if scope == TransferScope::Application {
            return Err(ModelError("The file has no application settings.".into()));
        }
        Ok(config)
    }

    /// Add keeps the current selection; Replace follows the imported selection.
    /// UUID matches allow updates. Legacy imports match complete server fields.
    /// An omitted/empty password keeps a matching account's existing password.
    pub fn import_servers(&mut self, other: &Self, replacing: bool) -> usize {
        let previous = self.servers.clone();
        let selected = self.selected_server().map(|s| s.id);
        let retained: HashSet<Uuid> =
            previous.iter().map(|s| s.id).filter(|id| other.servers.iter().any(|s| s.id == *id)).collect();
        let mut merged = if replacing { Vec::new() } else { previous.clone() };
        let mut mapped = HashMap::new();
        let mut added = 0;
        for incoming in &other.servers {
            let mut server = incoming.clone();
            let candidates = merged.iter().chain(previous.iter().filter(|old| !merged.iter().any(|s| s.id == old.id)));
            let candidates: Vec<&Server> = candidates.collect();
            let existing = candidates.iter().copied().find(|old| old.id == server.id).or_else(|| {
                candidates.iter().copied().find(|old| {
                    let mut normalized = server.clone();
                    if normalized.password.is_empty() {
                        normalized.password = old.password.clone();
                    }
                    if retained.contains(&old.id)
                        && let Some(update) = other.servers.iter().find(|s| s.id == old.id)
                    {
                        let mut update = update.clone();
                        if update.password.is_empty() {
                            update.password = old.password.clone();
                        }
                        if !update.same_without_id(&normalized) {
                            return false;
                        }
                    }
                    old.same_without_id(&normalized)
                })
            });
            if let Some(existing) = existing {
                server.id = existing.id;
                if server.password.is_empty() {
                    server.password = existing.password.clone();
                }
            } else {
                added += 1;
            }
            mapped.insert(incoming.id, server.id);
            if let Some(index) = merged.iter().position(|s| s.id == server.id) {
                merged[index] = server;
            } else {
                merged.push(server);
            }
        }
        self.servers = merged;
        self.selected_server_id = if replacing || selected.is_none() {
            other.selected_server().and_then(|s| mapped.get(&s.id).copied())
        } else {
            selected
        };
        added
    }
}

pub fn client_change(old: &Configuration, new: &Configuration) -> ClientChange {
    let Ok(after) = new.client_config_toml() else {
        return ClientChange::Disconnect;
    };
    if old.client_config_toml().is_ok_and(|before| before == after) {
        ClientChange::None
    } else {
        ClientChange::Reconnect
    }
}

pub fn parse_domain(text: &str) -> Result<(String, u16), ModelError> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Err(ModelError("Enter the server's domain.".into()));
    }
    let (host, port) = if let Some((host, port)) = text.rsplit_once(':') {
        (host, port.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(invalid_domain)?)
    } else {
        (text.as_str(), 443)
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || host.parse::<IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(invalid_domain());
    }
    Ok((host.into(), port))
}
fn invalid_domain() -> ModelError {
    ModelError(
        "The server's domain is not valid. Example: vpn.example.com (vpn.example.com:8443 when the port is not 443)."
            .into(),
    )
}
fn parse_authority(authority: &str) -> Result<(String, u16), ModelError> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or_else(invalid_domain)?;
        let host = &authority[1..end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid_domain());
        }
        let suffix = &authority[end + 1..];
        let port = if suffix.is_empty() {
            443
        } else {
            suffix
                .strip_prefix(':')
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|p| *p != 0)
                .ok_or_else(invalid_domain)?
        };
        Ok((host.into(), port))
    } else {
        if let Some((host, port)) = authority.rsplit_once(':') {
            let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(invalid_domain)?;
            if host.is_empty() || host.contains(':') {
                return Err(invalid_domain());
            }
            Ok((host.into(), port))
        } else {
            Ok((authority.into(), 443))
        }
    }
}
fn domain_with_port(host: &str, port: u16) -> String {
    if port == 443 { host.into() } else { format!("{host}:{port}") }
}
fn socket_address(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}
fn toml_string(text: &str) -> String {
    // JSON escapes all C0 controls; TOML additionally forbids literal DEL.
    serde_json::to_string(text).expect("strings can be encoded").replace('\u{007f}', "\\u007F")
}
fn wrong(key: &str, place: &str, expected: &str) -> ModelError {
    ModelError(format!(
        "'{key}'{} must be {expected}.",
        if place.is_empty() { String::new() } else { format!(" in {place}") }
    ))
}
fn string<'a>(t: &'a toml::Table, key: &str, place: &str) -> Result<Option<&'a str>, ModelError> {
    t.get(key).map(|v| v.as_str().ok_or_else(|| wrong(key, place, "a string in quotes"))).transpose()
}
fn integer(t: &toml::Table, key: &str, place: &str) -> Result<Option<i64>, ModelError> {
    t.get(key).map(|v| v.as_integer().ok_or_else(|| wrong(key, place, "a whole number"))).transpose()
}
fn boolean(t: &toml::Table, key: &str, place: &str) -> Result<Option<bool>, ModelError> {
    t.get(key).map(|v| v.as_bool().ok_or_else(|| wrong(key, place, "true or false"))).transpose()
}
fn table<'a>(t: &'a toml::Table, key: &str, place: &str) -> Result<Option<&'a toml::Table>, ModelError> {
    t.get(key).map(|v| v.as_table().ok_or_else(|| wrong(key, place, "a table"))).transpose()
}
fn read_transport(t: &toml::Table, place: &str) -> Result<Transport, ModelError> {
    let Some(text) = string(t, "transport", place)? else {
        return Ok(Transport::Auto);
    };
    Transport::ALL
        .into_iter()
        .find(|v| v.as_str() == text)
        .ok_or_else(|| wrong("transport", place, "auto, h3, h2 or http/1.1"))
}
fn checked_port(port: i64) -> Result<u16, ModelError> {
    u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| ModelError("The port must be between 1 and 65535.".into()))
}

pub fn write_privately(data: &[u8], path: impl AsRef<Path>) -> Result<(), ModelError> {
    let path = path.as_ref();
    let folder = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(folder)?;
    if fs::symlink_metadata(folder)?.file_type().is_symlink() {
        return Err(ModelError("The settings directory must not be a symbolic link.".into()));
    }
    let temporary = folder.join(format!(".network-relay-rs-{}.tmp", Uuid::new_v4()));
    let result = (|| -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            fs::File::open(folder)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Into::into)
}

fn log_rank(line: &str) -> Option<u32> {
    line.split_whitespace().take(4).find_map(|word| match word {
        "ERROR" => Some(0),
        "WARN" => Some(1),
        "INFO" => Some(2),
        "DEBUG" => Some(3),
        "TRACE" => Some(4),
        _ => None,
    })
}
/// Keep chronological important records when verbose I/O fills the buffer.
pub fn append_client_log(log: &mut Vec<String>, incoming: impl IntoIterator<Item = String>, limit: usize) {
    assert!(limit > 0, "a log buffer needs a positive limit");
    log.extend(incoming);
    let mut excess = log.len().saturating_sub(limit);
    if excess == 0 {
        return;
    }
    log.retain(|line| {
        if excess > 0 && log_rank(line).is_some_and(|rank| rank >= 3) {
            excess -= 1;
            false
        } else {
            true
        }
    });
    if excess > 0 {
        log.drain(..excess);
    }
}
