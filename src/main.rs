//! `network-relay`: the relay server and its helper commands.

use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use network_relay::config::{self, Config};
use network_relay::profile::{self, IdentityPayload, ProfileOptions};
use network_relay::proto::DEFAULT_UDP_PATH_TEMPLATE;
use network_relay::{auth, check, logging, server};

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
    /// Create a user: a random password and the lines for the configuration file.
    Passwd {
        /// User name: 1-64 letters, digits, '-', '_' or '.'. One per device is easiest to manage.
        #[arg(long)]
        name: String,
        /// Read the password from standard input instead of generating one (hashed with Argon2id).
        #[arg(long)]
        stdin: bool,
        /// With --stdin: the password is a random secret of at least 24 characters, so it gets the
        /// fast hash generated passwords use.
        #[arg(long, requires = "stdin")]
        fast_hash: bool,
        /// The account stops working at this time (RFC 3339, e.g. 2027-01-31T00:00:00Z).
        #[arg(long)]
        expires: Option<String>,
    },
    /// Create a client certificate for a user: a PKCS#12 file for the device profile and the
    /// lines for the configuration file (needs [tls] client_certificates = true).
    Identity {
        /// User name, as in the configuration file.
        #[arg(long)]
        name: String,
        /// Days the certificate is valid.
        #[arg(long, default_value_t = 825)]
        days: u32,
        /// Output file (default: <name>.p12).
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Write a configuration profile (.mobileconfig) for an iPhone, iPad or Mac.
    Profile {
        /// The relay's domain name, as in its certificate.
        #[arg(long)]
        host: String,
        /// User name, as created with `network-relay passwd`.
        #[arg(long)]
        user: String,
        /// The user's password; asked for when left out (unless --identity is given). Prefer the
        /// prompt: a password on the command line is visible to other users of the machine.
        #[arg(long)]
        password: Option<String>,
        /// Authenticate with this client identity (PKCS#12 from `network-relay identity`)
        /// instead of a password; with --password as well, the profile carries both.
        #[arg(long, value_name = "FILE.p12")]
        identity: Option<PathBuf>,
        /// Put the identity's password into the profile (asked for). Without it, the device asks
        /// for it during installation, so the profile file alone does not unlock the key.
        #[arg(long, requires = "identity")]
        embed_identity_password: bool,
        /// With --ddm: identifier of the MDM's identity asset declaration to authenticate with.
        #[arg(long, requires = "ddm")]
        identity_asset: Option<String>,
        /// Write a declarative device management (DDM) declaration (JSON) for an MDM server instead
        /// of a .mobileconfig (iOS/macOS 27+).
        #[arg(long, conflicts_with = "publish")]
        ddm: bool,
        /// Port, if not 443.
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Relay this domain and its subdomains (repeatable). Without match-domain or match-fqdn, relay all traffic.
        #[arg(long = "match-domain", value_name = "DOMAIN")]
        match_domains: Vec<String>,
        /// Never relay this domain and its subdomains (repeatable).
        #[arg(long = "exclude-domain", value_name = "DOMAIN")]
        excluded_domains: Vec<String>,
        /// Relay exactly this hostname, without its subdomains (iOS 18.4+, macOS 15.4+).
        #[arg(long = "match-fqdn", value_name = "HOST")]
        match_fqdns: Vec<String>,
        /// Exclude exactly this hostname (repeatable).
        #[arg(long = "exclude-fqdn", value_name = "HOST")]
        excluded_fqdns: Vec<String>,
        /// Allow the user to disable the relay in Settings (iOS/macOS 26+).
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        ui_toggle_enabled: Option<bool>,
        /// Allow failover to the device's system DNS resolver (iOS/macOS 26+).
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        allow_dns_failover: Option<bool>,
        /// Relay UUID for managed-app/user-enrollment routing (not supported by macOS).
        #[arg(long)]
        relay_uuid: Option<String>,
        /// Name shown in Settings (default: the domain).
        #[arg(long)]
        name: Option<String>,
        /// Path of the CONNECT-UDP template, if relay.udp_template is not the default.
        #[arg(long, default_value = DEFAULT_UDP_PATH_TEMPLATE)]
        udp_template: String,
        /// Leave out HTTP/3 (QUIC); the device then uses HTTP/2 over TCP only.
        #[arg(long)]
        no_http3: bool,
        /// Leave out HTTP/2; the device then uses HTTP/3 only.
        #[arg(long)]
        no_http2: bool,
        /// Output file (default: <domain>-<user>.mobileconfig).
        #[arg(long, short, conflicts_with = "publish")]
        out: Option<PathBuf>,
        /// Put the profile on the relay's website under a random name and print its link, to open on
        /// the device. The link works once, for 15 minutes. Needs [web] in the configuration.
        #[arg(long)]
        publish: bool,
        /// Configuration file, for --publish.
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Test a running relay over HTTP/3, HTTP/2 and HTTP/1.1, as a device uses it.
    Check {
        /// The relay's domain name.
        #[arg(long)]
        server: String,
        /// Connect to this IP address instead of looking up the domain (repeatable).
        #[arg(long = "address", value_name = "IP")]
        addresses: Vec<IpAddr>,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long)]
        user: String,
        /// The user's password; asked for when left out. Prefer the prompt: a password on the
        /// command line is visible to other users of the machine.
        #[arg(long)]
        password: Option<String>,
        /// Web server to fetch through the TCP tunnel.
        #[arg(long, default_value = "example.com:80")]
        tcp_target: String,
        /// DNS server to query through the UDP tunnel.
        #[arg(long, default_value = "1.1.1.1:53")]
        udp_target: String,
        /// Name to look up through the UDP tunnel.
        #[arg(long, default_value = "example.com")]
        dns_name: String,
        #[arg(long, default_value = DEFAULT_UDP_PATH_TEMPLATE)]
        udp_template: String,
        /// Trust only this CA certificate (PEM) instead of the system's.
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Present this client certificate (PEM) to the relay; with --client-key.
        #[arg(long, requires = "client_key")]
        client_cert: Option<PathBuf>,
        /// Key (PEM) of --client-cert.
        #[arg(long, requires = "client_cert")]
        client_key: Option<PathBuf>,
        /// Seconds to wait for each step.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve { config, check } => return serve(config, check),
        Command::Passwd { name, stdin, fast_hash, expires } => passwd(&name, stdin, fast_hash, expires.as_deref()),
        Command::Identity { name, days, out } => identity(&name, days, out),
        Command::Profile {
            host,
            user,
            password,
            identity,
            embed_identity_password,
            identity_asset,
            ddm,
            port,
            match_domains,
            excluded_domains,
            match_fqdns,
            excluded_fqdns,
            ui_toggle_enabled,
            allow_dns_failover,
            relay_uuid,
            name,
            udp_template,
            no_http3,
            no_http2,
            out,
            publish,
            config,
        } => (|| {
            warn_command_line_password(password.is_some());
            let has_identity = identity.is_some() || identity_asset.is_some();
            let password = match password {
                Some(p) => Some(p),
                None if has_identity => None,
                None => Some(password_or_prompt(None)?),
            };
            let identity = identity
                .map(|path| -> Result<IdentityPayload> {
                    let p12 = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                    let password =
                        if embed_identity_password { Some(read_secret("PKCS#12 password: ")?) } else { None };
                    Ok(IdentityPayload { p12, password })
                })
                .transpose()?;
            let opts = ProfileOptions {
                host: host.strip_suffix('.').unwrap_or(&host).to_ascii_lowercase(),
                port,
                user,
                password,
                identity,
                identity_asset,
                udp_template,
                match_domains,
                excluded_domains,
                match_fqdns,
                excluded_fqdns,
                ui_toggle_enabled,
                allow_dns_failover,
                relay_uuid,
                name,
                http3: !no_http3,
                http2: !no_http2,
            };
            for w in profile::warnings(&opts) {
                eprintln!("warning: {w}");
            }
            if publish {
                publish_profile(&opts, &config)
            } else {
                write_profile(&opts, out, ddm)
            }
        })(),
        Command::Check {
            server,
            addresses,
            port,
            user,
            password,
            tcp_target,
            udp_target,
            dns_name,
            udp_template,
            ca,
            client_cert,
            client_key,
            timeout,
        } => (|| {
            warn_command_line_password(password.is_some());
            let client_cert = client_cert.zip(client_key);
            // With a client certificate, the password is optional.
            let password = match password {
                None if client_cert.is_some() => String::new(),
                p => password_or_prompt(p)?,
            };
            let udp_target = network_relay::policy::Target::from_authority(&udp_target)
                .context("--udp-target must be host:port, IPv6 in brackets")?;
            network_relay::policy::Target::from_authority(&tcp_target)
                .context("--tcp-target must be host:port, IPv6 in brackets")?;
            let opts = check::Options {
                host: server.trim_end_matches('.').to_string(),
                port,
                addresses: addresses.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(),
                user,
                password,
                udp_template,
                tcp_target,
                udp_target: (udp_target.host, udp_target.port),
                dns_name,
                ca,
                client_cert,
                timeout: Duration::from_secs(timeout),
            };
            run_check(&opts)
        })(),
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

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
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
            runtime()?.block_on(async { server::Relay::new(&config).map(|_| ()) })
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
    let rt = match runtime() {
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

/// Reads a line from standard input. On a terminal the prompt is shown and
/// what is typed is not echoed, as it is a password.
fn read_secret(prompt: &str) -> Result<String> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
    let stdin = std::io::stdin();
    let mut echo = None;
    if std::io::IsTerminal::is_terminal(&stdin) {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        if let Ok(saved) = tcgetattr(&stdin) {
            let mut quiet = saved.clone();
            quiet.local_flags.remove(LocalFlags::ECHO);
            if tcsetattr(&stdin, SetArg::TCSANOW, &quiet).is_ok() {
                echo = Some(saved);
            }
        }
    }
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    if let Some(saved) = echo {
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &saved);
        eprintln!();
    }
    read.context("reading standard input")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn warn_command_line_password(given: bool) {
    if given {
        eprintln!(
            "warning: a password on the command line is visible to other users of this machine and stays in \
             shell history; leave out --password to be asked for it"
        );
    }
}

fn password_or_prompt(password: Option<String>) -> Result<String> {
    let password = match password {
        Some(p) => p,
        None => read_secret("Password: ")?,
    };
    if password.is_empty() {
        bail!("no password given");
    }
    Ok(password)
}

fn passwd(name: &str, from_stdin: bool, fast_hash: bool, expires: Option<&str>) -> Result<bool> {
    auth::validate_user_name(name)?;
    let (password, generated) = if from_stdin {
        let password = read_secret("Password: ")?;
        if password.chars().count() < auth::MIN_PASSWORD_LEN {
            bail!("the password must have at least {} characters", auth::MIN_PASSWORD_LEN);
        }
        if password.chars().any(char::is_control) {
            bail!("the password must not contain control characters");
        }
        (password, false)
    } else {
        (auth::generate_password(), true)
    };
    // Random secrets need no slow hash: their strength is their randomness.
    // Passwords people choose get Argon2id.
    let hash =
        if generated || fast_hash { auth::hash_generated_secret(&password)? } else { auth::hash_password(&password)? };
    let entry = config::UserEntry {
        name: name.to_string(),
        password_hash: Some(hash.clone()),
        certificate_sha256: None,
        expires: expires.map(str::to_string),
    };
    auth::validate_entry(&entry)?;
    println!("# 1. Add these lines to the end of {}, then: sudo systemctl reload network-relay", config::DEFAULT_PATH);
    println!("[[user]]");
    println!("name = \"{name}\"");
    println!("password_hash = \"{hash}\"");
    if let Some(e) = expires {
        println!("expires = \"{e}\"");
    }
    println!();
    if generated {
        println!("# 2. The password (shown only now; the server keeps only the hash):");
        println!("{password}");
        println!();
    }
    println!("# 3. Make the profile for the device:");
    println!("#    network-relay profile --host <your relay domain> --user {name}");
    Ok(true)
}

/// Writes a client identity and prints the configuration lines for it.
fn identity(name: &str, days: u32, out: Option<PathBuf>) -> Result<bool> {
    let id = network_relay::identity::generate(name, days)?;
    let out = out.unwrap_or_else(|| PathBuf::from(format!("{name}.p12")));
    network_relay::private_file::write(&out, &id.p12)?;
    println!("Wrote {} (the key and certificate; keep it private and delete it once installed).", out.display());
    println!();
    println!("# 1. In {}: set client_certificates = true under [tls], and add", config::DEFAULT_PATH);
    println!("#    to the [[user]] section of {name} (or a new one), then: sudo systemctl reload network-relay");
    println!("[[user]]");
    println!("name = \"{name}\"");
    println!("certificate_sha256 = \"{}\"", auth::fingerprint_hex(&id.fingerprint));
    println!();
    println!("# 2. The PKCS#12 password (shown only now; the device asks for it when installing the profile):");
    println!("{}", id.password);
    println!();
    println!("# 3. Make the profile for the device:");
    println!("#    network-relay profile --host <your relay domain> --user {name} --identity {}", out.display());
    Ok(true)
}

fn write_profile(opts: &ProfileOptions, out: Option<PathBuf>, ddm: bool) -> Result<bool> {
    let (text, extension) =
        if ddm { (profile::generate_ddm(opts)?, "json") } else { (profile::generate(opts)?, "mobileconfig") };
    let out = out.unwrap_or_else(|| PathBuf::from(format!("{}-{}.{extension}", opts.host, opts.user)));
    network_relay::private_file::write(&out, text.as_bytes())?;
    println!("Wrote {} (it contains the credentials; delete it once installed).", out.display());
    println!("Relay URL: {}", opts.relay_url());
    println!(
        "Relayed: {}",
        if opts.match_domains.is_empty() && opts.match_fqdns.is_empty() {
            "all traffic".to_string()
        } else {
            opts.match_domains.iter().chain(&opts.match_fqdns).cloned().collect::<Vec<_>>().join(", ")
        }
    );
    Ok(true)
}

/// Writes the profile where the relay serves it once, for a limited time,
/// under a random name; removes earlier published profiles that expired.
fn publish_profile(opts: &ProfileOptions, config_path: &std::path::Path) -> Result<bool> {
    use network_relay::web::{PUBLISH_DIR, PUBLISH_TTL};
    use std::os::unix::fs::DirBuilderExt;
    let config = Config::load(config_path)?;
    let web = config.web.as_ref().context("--publish needs a [web] section with the website directory")?;
    let text = profile::generate(opts)?;
    let dir = web.root.join(PUBLISH_DIR);
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let expired = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t.elapsed().unwrap_or_default() > PUBLISH_TTL);
            if expired && entry.file_name().to_string_lossy().ends_with(".mobileconfig") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let name = format!("{}.mobileconfig", auth::generate_password());
    let path = dir.join(&name);
    network_relay::private_file::write(&path, text.as_bytes())?;
    let port = if opts.port == 443 { String::new() } else { format!(":{}", opts.port) };
    println!("Wrote {}", path.display());
    println!();
    println!("1. Let the relay serve it:   systemctl reload network-relay");
    println!(
        "2. Within {} minutes, open this link in Safari on the iPhone, iPad or Mac, and install the profile:",
        PUBLISH_TTL.as_secs() / 60
    );
    println!("   https://{}{port}/{name}", opts.host);
    println!(
        "   The link works only once; after that, or after {} minutes, it shows the website.",
        PUBLISH_TTL.as_secs() / 60
    );
    println!("3. Then delete the file (it contains the credentials):");
    println!("   rm {}", path.display());
    Ok(true)
}

fn run_check(opts: &check::Options) -> Result<bool> {
    let outcomes = runtime()?.block_on(check::run(opts));
    let mut ok = true;
    for o in &outcomes {
        let ms = o.elapsed.as_millis();
        match &o.result {
            Ok(detail) => println!("✓ {:<36} {detail} ({ms} ms)", o.name),
            Err(e) => {
                ok = false;
                println!("✗ {:<36} {e:#}", o.name);
            }
        }
    }
    println!();
    if ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed. HTTP/3 failing alone usually means UDP port {} is blocked.", opts.port);
    }
    Ok(ok)
}
