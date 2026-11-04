//! Bound foreground SOCKS work by the process descriptor allowance.

pub(crate) fn socks_sessions() -> usize {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: limit points to a valid writable rlimit. This reads the
        // current process allowance and never changes process or system limits.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            // Reserve space for accepted/pending connections, the GUI,
            // readiness, resolver attempts and runtime descriptors. HTTP/1.1
            // needs both a local socket and a separate relay socket per flow.
            let sessions = (limit.rlim_cur.saturating_sub(128) / 2).clamp(1, 256) as usize;
            tracing::debug!(
                sessions,
                file_limit = limit.rlim_cur,
                "SOCKS concurrency follows process descriptor limit"
            );
            return sessions;
        }
        tracing::warn!("Could not read the process descriptor limit; limiting SOCKS concurrency");
        16
    }
    #[cfg(not(unix))]
    {
        256
    }
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn low_process_limit_leaves_headroom_for_active_socks_sessions() {
        if std::env::var_os("RELAY_LOW_FD_TEST_CHILD").is_none() {
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", "ulimit -n 256 && exec \"$@\"", "fd-budget-test"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "limits::tests::low_process_limit_leaves_headroom_for_active_socks_sessions",
                    "--nocapture",
                ])
                .env("RELAY_LOW_FD_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Two socket descriptors per admitted foreground session must still
        // leave real descriptor capacity for pending I/O and the application.
        let sockets: Vec<_> = (0..super::socks_sessions())
            .map(|_| std::os::unix::net::UnixStream::pair().unwrap())
            .collect();
        let spare: Vec<_> = (0..64)
            .map(|_| {
                std::fs::File::open("/dev/null")
                    .expect("session admission exhausted descriptor headroom")
            })
            .collect();
        drop((spare, sockets));
    }
}
