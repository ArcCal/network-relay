# Debian 12/13 x64: automatic install from a prebuilt binary

For a Debian 12 or 13, x86_64, systemd VPS (the script is still called `install-debian13.sh`). Upload the extracted Linux x86_64 release binary as `/tmp/network-relay`. The installer uses that file by default, without installing Rust, Cargo, Git or build tools. It never falls back to compilation if the file is missing or invalid. Installation needs the Debian package mirrors and, for automatic certificates, access to Let's Encrypt.

Keep the deployment files together: `deploy/install-debian13.sh`, `deploy/install.py`, `deploy/global-profile.py`, `deploy/network-relay.service`, `deploy/certbot-hook.sh`, `deploy/domains/google-ai-social.txt` and `deploy/domains/public-suffix-icann.dat`. No Rust source or Cargo files are needed. These files can come from a deployment bundle or the current source ZIP. A self-contained `network-relay-install.sh` bundles these files and refreshes the device profile as well as installing the binary; upload it alongside the binary and run:

```bash
sudo bash /tmp/network-relay-install.sh
```

On a new installation it asks for the relay domain. To supply it directly:

```bash
sudo bash /tmp/network-relay-install.sh --domain relay.example.com --email you@example.com
```

The script installs Python if needed, then runtime tools, obtains the certificate, sets up renewal, creates the service account and configuration, generates a matching device profile, enables the systemd service and checks startup. The email is optional. Prepare DNS and the cloud firewall as described below; the script cannot change the domain registrar or cloud provider's security group.

The default generated routing list combines `google-ai-social.txt`, [gfwlist](https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/list.txt) and [Loyalsoldier proxy.txt](https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt). The two remote lists are fetched when a profile is generated. All extracted names are widened to registered root domains using the bundled ICANN public suffix snapshot, sorted and deduplicated; for example `accounts.google.com` becomes `google.com` and `api.example.co.uk` becomes `example.co.uk`. Private hosting suffixes are deliberately ignored: a tenant under `github.io` matches the whole `github.io` domain, and shared CDN domains may match unrelated services. Explicit top-level rules such as `+.adult` keep their entire suffix scope. The relay's own hostname and subdomains are always excluded. Other domains do not match this Relay configuration.

gfwlist regular expressions, IP/unsupported patterns and `@@` exceptions are reported but cannot be represented by this domain conversion; path-specific rules widen to the whole domain. All domain entries in the published proxy payload format, including `+.` suffix rules and plain hosts, are parsed. A failed download, empty source or unrecognized proxy rule aborts rather than silently issuing an incomplete profile. For a VPS unable to fetch GitHub, pass downloaded files with `--gfwlist-file /path/list.txt --proxy-list-file /path/proxy.txt`. `--no-gfwlist` and `--no-proxy-list` are explicit opt-outs.

For an existing installation, the standalone script automatically regenerates a profile with the current lists, preserving the account and its password. It first looks for the previous delivery profile on the VPS; if it is gone, it prompts for the existing password locally. Alternatively pass `--profile /path/original.mobileconfig`. The running relay authenticates the password over verified local TLS before anything is changed. Install the newly generated profile on the device; an installed profile does not update automatically. The extracted installer requires `--refresh-profile` for this operation; without it, an ordinary upgrade leaves profiles alone.

If you do not know the old password, reset the installation account and generate a matching profile in one command:

```bash
sudo bash /tmp/network-relay-install.sh --reset-password
```

The installer generates a new random password, stores only its hash, preserves other users and hand-edited settings, and hands over the new profile without printing the password. Old profiles for this account no longer authenticate. Install the new profile on every device using this account. The reset is part of the normal installation transaction: a failed service startup restores the previous hash and files. `--reset-password` cannot be combined with `--profile`.

## You already have a profile for your relay

Replace `relay.example.com` with your own domain throughout these examples.

1. Point the A record of `relay.example.com` at the VPS's public IPv4 address. Set an AAAA record only if IPv6 works; in Cloudflare choose "DNS only".
2. In the cloud provider's security group, allow TCP 80, TCP 443 and UDP 443, and keep the SSH port.
3. Upload `/tmp/network-relay`, extract the deployment files (or source ZIP), and upload your existing profile as `/root/iphone.mobileconfig` on the VPS. It contains your relay credentials; keep it private and do not commit it to Git.
4. In the extracted source directory, run:

```bash
sudo bash deploy/install-debian13.sh --profile /root/iphone.mobileconfig
```

You can add `--email you@example.com` to receive mail about the certificate account; without it, an ACME account with no email is created. The automatic certificate step calls certbot with `--agree-tos`, which means accepting the Let's Encrypt terms of service. If you already have a certificate from a public CA, use `--cert /path/fullchain.pem --key /path/privkey.pem` instead: the paths are written into the configuration as given, without resolving symlinks, so Let's Encrypt `live/` paths keep working after renewal. Later upgrades do not need these two options again; the script keeps the certificate in the configuration and does not switch to certbot. Different paths are refused; to change the certificate, first edit `[tls]` in `/etc/network-relay/relay.toml`.

After installation, install **the same** mobileconfig on the iPhone/iPad/Mac. Do not replace it with a separately generated file with a different password; the device and the server must use the same credentials. The server keeps no copy (only the password's hash), so delete `/root/iphone.mobileconfig` once the device has it.

## No pre-generated mobileconfig

```bash
sudo bash deploy/install-debian13.sh --domain relay.example.com
```

The script generates a new random password, creates the `iphone` user, and puts a matching profile on the relay's website behind a link that it prints. Open the link in Safari on the device within 15 minutes and install the profile; the link works once. Then delete the file the script names (under `/var/www/relay/.publish/`). The password is not printed and not kept anywhere else on the server, which stores only its hash.

To get the profile as a file instead, add `--profile-out /root/iphone.mobileconfig`, copy it to the device, and delete it.

By default a newly generated profile matches the combined root-domain list described above, using a non-empty `MatchDomains`. `--domains your-list.txt` replaces the Google/AI/X base list, while the remote lists are still included unless explicitly disabled. An imported file keeps its own rules in the extracted installer's normal mode; with `--refresh-profile` (always enabled by the standalone script), its credentials are reused to generate the combined routing profile.

## What the script does

- Checks the system, the lock against concurrent installs, the domain and port usage; it does not stop other services that hold the ports.
- Installs runtime dependencies and uses `/tmp/network-relay` (or `--binary /path/network-relay`). Checks that it is an extracted Linux x86_64 ELF executable. Copies it to a private staging directory under `/usr/local/bin` for validation, password hashing and profile generation, so a missing execute bit or a `noexec` `/tmp` does not prevent installation. Leaves the uploaded file unchanged and cleans up the staged copy on success or failure.
- Creates the system user `network-relay`, which the relay runs as, instead of root. The configuration and a copy of the certificate in `/etc/network-relay/tls` are readable by its group; `install.json` and the backups stay root's. An installation from an earlier version, which read certbot's files directly as root, is moved to the copy. A certificate given with `--cert`/`--key` is read in place and must be readable by the user (the script stops and says how if it is not).
- Obtains or reuses a Let's Encrypt certificate, enables `certbot.timer`, and installs `deploy/certbot-hook.sh` as certbot's deploy hook, which copies each renewed certificate and reloads the relay. TCP 80 must stay open for renewals.
- If UFW is enabled, adds rules for TCP 80 and the relay's TCP/UDP port; it never flushes firewall rules. You still need to open the ports in your own nftables/iptables rules and in the cloud security group.
- Creates the default website and a server configuration that stores only the password's hash (PBKDF2-SHA256 for the generated password, Argon2id for an imported one), and records the domain, port and user name, no secret, in `/etc/network-relay/install.json`; keeps the program's default destination restrictions.
- For a new account, generates the device profile before committing the account, then hands it over once (a link, or `--profile-out`). Generation failure leaves the account uninstalled. The published profile is present when the service starts.
- Generates a small seed profile with the existing binary, then fills in the complete normalized domain list as compact XML, avoiding command-line length limits. If a future list exceeds the binary's 1 MiB website publishing limit, it delivers the entire profile privately as `/etc/network-relay/profile-USER.mobileconfig` instead of omitting domains; copy that file to the device. Profiles over 16 MiB are refused. No binary recompilation is needed.
- Installs the systemd unit, enables it at boot, and installs the UDP buffer settings. Existing larger buffer settings are not lowered.
- Validates the staged certificate pair, replaces the program atomically and checks HTTPS on the local machine; on failure, restores the program, configuration, certificate copies, device profile and original file ownership/modes, along with the previous running/enabled state. Backups are kept in `/etc/network-relay/backups/timestamp/`, with the original paths recorded in `manifest.json`. Package installation, certificate issuance and UFW rules are not undone by this rollback.
- Runs the networked TCP/UDP self-check over all three HTTP versions when it knows the password (a new installation, or `--profile`). If the external test targets are unreachable, the self-check fails but the started service is left running for diagnosis; passing locally does not replace checking UDP 443 from an outside network.

To compile explicitly, extract the complete source ZIP and use `--build-from-source`. Only that mode installs the Rust toolchain and build dependencies and builds as pinned by `Cargo.lock`; it defaults to one build job and disables LTO to reduce peak memory. At least 2 GiB of memory and 3 GiB of free disk are recommended for compilation; `--jobs 2` builds in parallel. `--binary` and `--build-from-source` cannot be combined. The self-contained deployment script has no Rust source; use the source ZIP for compilation.

## Updating and re-running

For an installation this script created, upload the new release binary to `/tmp/network-relay`, then run the same command again. It keeps the password and the configuration, including users or settings added by hand. With the self-contained script, run `sudo bash /tmp/network-relay-install.sh` again; it also regenerates the device profile with the latest lists. With extracted deployment files, a binary-only upgrade is:

```bash
sudo bash deploy/install-debian13.sh
```

It reads the installation's domain, port and user name from `/etc/network-relay/install.json` and installs the uploaded binary. A binary-only upgrade needs neither the profile nor the password. To regenerate the routing profile as well, add `--refresh-profile`; the password is reused from the old delivery file or prompted for. It refuses to overwrite an account with a different domain, port or user name. Upload again after a reboot if `/tmp` was cleared.

To reproduce the standalone download file without compiling anything, run `python3 deploy/package-installer.py` from the repository; it writes `dist/network-relay-install.sh` and its SHA-256 file.

Installations made by earlier versions of the script have no `install.json`; the script reads their identity from `/etc/network-relay/device.mobileconfig` instead, writes `install.json`, and reminds you that the old file holds the password. Delete it once your devices have the profile.

The script does not take over an older manual installation that has neither file. An older installation can keep its configuration and update only the binary; back it up before changing anything:

```bash
cargo build --locked --release
sudo target/release/network-relay serve --config /etc/network-relay/relay.toml --check
sudo install -m 755 target/release/network-relay /usr/local/bin/network-relay.new
sudo mv /usr/local/bin/network-relay.new /usr/local/bin/network-relay
sudo systemctl restart network-relay
```

## Another device

The installer makes one account. For another device, or a new profile for the same one (because the link expired, say), make a new password and profile by hand:

```bash
network-relay passwd --name ipad
```

Append the printed `[[user]]` lines to `/etc/network-relay/relay.toml` (for an existing user, replace only its `password_hash` line), then:

```bash
network-relay serve --check
systemctl reload network-relay
network-relay profile --host relay.example.com --user ipad --match-domain google.com --publish
systemctl reload network-relay
```

Enter the password `passwd` printed. `profile --publish` prints a link that works once within 15 minutes; the profile then has the domains given with `--match-domain` (use `deploy/global-profile.py` or the list in `deploy/domains/` for more). Delete the published file afterwards. Instead of a password, a device can also get a client certificate (`network-relay identity`); see [config.md](config.md#client-certificates).

## Checking that it runs

```bash
systemctl status network-relay --no-pager
journalctl -u network-relay -n 80 --no-pager
systemctl list-timers certbot.timer
```

The script, generating, publishing and parsing real profiles and configurations, re-running and upgrading from earlier versions, port conflicts and rollback on startup failure all have automated tests; package management, ACME and systemd operations use mock commands so that the test machine's system is not changed. Actual certificate issuance and cloud firewall connectivity must be verified on your VPS.
