use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=APP_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=APP_BUILD_TIME");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Core/src");
    println!("cargo:rerun-if-changed=Core/vendor/h3/src");
    println!("cargo:rerun-if-changed=Core/Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    let value = |name: &str, program: &str, args: &[&str]| {
        std::env::var(name)
            .ok()
            .or_else(|| {
                Command::new(program)
                    .args(args)
                    .output()
                    .ok()
                    .filter(|r| r.status.success())
                    .and_then(|r| String::from_utf8(r.stdout).ok())
                    .map(|s| s.trim().into())
            })
            .unwrap_or_else(|| "Unknown".into())
    };
    let mut source = value("APP_SOURCE_REVISION", "git", &["rev-parse", "HEAD"]);
    if std::env::var_os("APP_SOURCE_REVISION").is_none()
        && source != "Unknown"
        && Command::new("git")
            .args(["status", "--porcelain", "--", "."])
            .output()
            .is_ok_and(|result| result.status.success() && !result.stdout.is_empty())
    {
        source.push_str("-dirty");
    }
    println!("cargo:rustc-env=APP_SOURCE_REVISION={source}");
    println!("cargo:rustc-env=APP_BUILD_TIME={}", value("APP_BUILD_TIME", "date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]));
}
