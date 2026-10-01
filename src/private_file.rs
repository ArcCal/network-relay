//! Atomic, owner-only output for files containing relay credentials.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{ensure, Context, Result};

pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        ensure!(meta.file_type().is_file(), "{} is not a regular file", path.display());
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".network-relay-{}.tmp", crate::auth::generate_password()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating private output in {}", parent.display()))?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path).with_context(|| format!("saving {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn replaces_public_file_privately_and_rejects_symlinks() {
        let dir = std::env::temp_dir().join(format!("relay-private-{}", crate::auth::generate_password()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write(&path, b"new").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(write(&link, b"leak").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
