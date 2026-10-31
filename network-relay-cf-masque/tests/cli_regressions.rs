//! Preserve standard CLI profile behavior in the independent application.
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};
const ALICE: (&str, &str) = ("alice", "ephemeral-cli-password");
struct Env {
    dir: PathBuf,
}
impl Env {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-runtime").join(format!(
            "cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("site")).unwrap();
        std::fs::write(dir.join("site/index.html"), "<!doctype html><title>cover</title>").unwrap();
        Self { dir }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
#[test]
fn profile_cli_writes_private_files_and_apple_controls() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let env = Env::new();
    let output = env.path("existing.mobileconfig");
    std::fs::write(&output, "old").unwrap();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o644)).unwrap();
    let run = |extra: &[&std::ffi::OsStr]| {
        let result = Command::new(env!("CARGO_BIN_EXE_network-relay-cf-masque"))
            .args([
                "profile",
                "--host",
                "relay.test",
                "--user",
                ALICE.0,
                "--password",
                ALICE.1,
                "--match-fqdn",
                "Api.Example.com.",
                "--exclude-fqdn",
                "direct.example.com",
                "--ui-toggle-enabled",
                "false",
                "--allow-dns-failover",
                "--relay-uuid",
                "01234567-89ab-4cde-8012-3456789abcde",
            ])
            .args(extra)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    };
    run(&["--out".as_ref(), output.as_os_str()]);
    let text = std::fs::read_to_string(&output).unwrap();
    for field in ["MatchFQDNs", "ExcludedFQDNs", "UIToggleEnabled", "AllowDNSFailover", "RelayUUID"] {
        assert!(text.contains(&format!("<key>{field}</key>")), "{field}");
    }
    assert!(text.contains("<string>api.example.com</string>"));
    assert!(text.contains("<key>UIToggleEnabled</key>\n      <false/>"));
    assert!(text.contains("<key>AllowDNSFailover</key>\n      <true/>"));
    assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);

    let config = env.path("relay.toml");
    std::fs::write(
        &config,
        format!(
            "[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n",
            env.path("fullchain.pem"),
            env.path("privkey.pem"),
            env.path("site")
        ),
    )
    .unwrap();
    run(&["--publish".as_ref(), "--config".as_ref(), config.as_os_str()]);
    let published: Vec<_> = std::fs::read_dir(env.path("site").join(network_relay::web::PUBLISH_DIR))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "mobileconfig"))
        .collect();
    assert_eq!(published.len(), 1);
    assert_eq!(std::fs::metadata(&published[0]).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn published_profiles_belong_to_the_publish_directory_owner() {
    use std::os::unix::fs::MetadataExt;
    let env = Env::new();
    let site = env.path("site");
    let publish = site.join(network_relay::web::PUBLISH_DIR);
    std::fs::create_dir_all(&publish).unwrap();
    let (uid, gid) = (65_534, 65_534);
    if std::os::unix::fs::chown(&publish, Some(uid), Some(gid)).is_err() {
        return; // not root
    }
    let config = env.path("relay.toml");
    std::fs::write(
        &config,
        format!(
            "[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n",
            env.path("fullchain.pem"),
            env.path("privkey.pem"),
            site
        ),
    )
    .unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_network-relay-cf-masque"))
        .args(["profile", "--host", "relay.test", "--user", ALICE.0, "--password", ALICE.1, "--publish", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let published: Vec<_> = std::fs::read_dir(&publish).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(published.len(), 1);
    let meta = std::fs::metadata(&published[0]).unwrap();
    assert_eq!((meta.uid(), meta.gid(), meta.mode() & 0o777), (uid, gid, 0o600));
}
