//! The program's configuration checks, without a VLESS server.

use std::path::PathBuf;
use std::process::Command;

const PROGRAM: &str = env!("CARGO_BIN_EXE_network-relay-vless");
const UUID: &str = "b4e4fad1-c320-428e-92dc-f8f6944a7dec";
const WS_PATH: &str = "/J2kV4jxviMDXceRQYVXiv6YwCc462T6P0Dayx5JYR8R";

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(label: &str) -> Dir {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-runtime")
        .join(format!("cli-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.example.com".into()]).unwrap().self_signed(&key).unwrap();
    std::fs::write(path.join("fullchain.pem"), cert.pem()).unwrap();
    std::fs::write(path.join("privkey.pem"), key.serialize_pem()).unwrap();
    Dir(path)
}

/// The shipped example, with this directory's certificate.
fn example(dir: &Dir) -> String {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/relay.toml")).unwrap();
    text.replace("/etc/letsencrypt/live/relay.example.com/fullchain.pem", dir.0.join("fullchain.pem").to_str().unwrap())
        .replace("/etc/letsencrypt/live/relay.example.com/privkey.pem", dir.0.join("privkey.pem").to_str().unwrap())
        .replace("listen = \"[::]:443\"", "listen = \"127.0.0.1:0\"")
}

fn serve_check(dir: &Dir, text: &str) -> (bool, String) {
    let path = dir.0.join("relay.toml");
    std::fs::write(&path, text).unwrap();
    let output = Command::new(PROGRAM).arg("serve").arg("--check").arg("--config").arg(&path).output().unwrap();
    let shown = String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), shown)
}

#[test]
fn the_example_configuration_is_valid() {
    let dir = dir("example");
    let text = example(&dir);
    assert!(text.contains(UUID) && text.contains(WS_PATH), "the example uses the documented server values");
    let (ok, shown) = serve_check(&dir, &text);
    assert!(ok, "{shown}");
    assert!(shown.contains("plaintext WebSocket"), "{shown}");
    assert!(!shown.contains(UUID) && !shown.contains(WS_PATH), "{shown}");
}

#[test]
fn unsupported_downstream_settings_stop_the_program() {
    let dir = dir("unsupported");
    let text = example(&dir);
    for (from, to, named) in [
        ("security = \"none\"", "security = \"tls\"", "vless.security"),
        ("transport = \"ws\"", "transport = \"tcp\"", "vless.transport"),
        ("[vless]\n", "[vless]\nflow = \"xtls-rprx-vision\"\n", "vless.flow"),
        ("[vless]\n", "[vless]\nallow_insecure = true\n", "invalid [vless]"),
    ] {
        assert!(text.contains(from), "{from}");
        let (ok, shown) = serve_check(&dir, &text.replacen(from, to, 1));
        assert!(!ok, "{to} was accepted");
        assert!(shown.contains(named), "{to}: {shown}");
        assert!(!shown.contains(UUID), "{shown}");
    }
    let (ok, shown) = serve_check(&dir, &text.replace("[vless]", "[vless_typo]"));
    assert!(!ok && shown.contains("invalid relay settings"), "{shown}");
}

#[test]
fn the_helper_commands_read_the_same_file() {
    let dir = dir("profile");
    let path = dir.0.join("relay.toml");
    std::fs::write(&path, example(&dir)).unwrap();
    let out = dir.0.join("device.mobileconfig");
    let output = Command::new(PROGRAM)
        .args(["profile", "--host", "relay.example.com", "--user", "iphone", "--password", "pw-Fixture-1"])
        .arg("--config")
        .arg(&path)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let profile = std::fs::read_to_string(&out).unwrap();
    assert!(profile.contains("com.apple.relay.managed"));
    assert!(!profile.contains(UUID), "the downstream user ID never reaches a device profile");
}
