# Debian 12/13 x64: automatic install from the downloaded source

For a Debian 12 or 13, x86_64, systemd VPS (the script is still called `install-debian13.sh`). The source can be downloaded from GitHub as a ZIP, uploaded and extracted; the VPS does not need to log in to GitHub. Building still needs access to the Debian package mirrors, the official Rust download site, crates.io and the public dependency repositories.

## You already have the mobileconfig delivered with this release

1. Point the A record of `relay.qolita.com` at the VPS's public IPv4 address. Set an AAAA record only if IPv6 works; in Cloudflare choose "DNS only".
2. In the cloud provider's security group, allow TCP 80, TCP 443 and UDP 443, and keep the SSH port.
3. Extract the source ZIP, and upload the separately delivered `relay.qolita.com-iphone.mobileconfig` to `/root/` on the VPS. That file contains a random user name and password and is not in the Git repository.
4. In the extracted source directory, run:

```bash
sudo bash deploy/install-debian13.sh --profile /root/relay.qolita.com-iphone.mobileconfig
```

You can add `--email you@example.com` to receive mail about the certificate account; without it, an ACME account with no email is created. The automatic certificate step calls certbot with `--agree-tos`, which means accepting the Let's Encrypt terms of service. If you already have a certificate from a public CA, use `--cert /path/fullchain.pem --key /path/privkey.pem` instead: the paths are written into the configuration as given, without resolving symlinks, so Let's Encrypt `live/` paths keep working after renewal. Later upgrades do not need these two options again; the script keeps the certificate in the configuration and does not switch to certbot. Different paths are refused; to change the certificate, first edit `[tls]` in `/etc/network-relay/relay.toml`.

After installation, install **the same** mobileconfig on the iPhone/iPad/Mac. Do not replace it with a separately generated file with a different password; the device and the server must use the same credentials. The server keeps no copy (only the password's hash), so delete `/root/relay.qolita.com-iphone.mobileconfig` once the device has it.

## No pre-generated mobileconfig

```bash
sudo bash deploy/install-debian13.sh --domain relay.qolita.com
```

The script generates a new random password, creates the `iphone` user, and puts a matching profile on the relay's website behind a link that it prints. Open the link in Safari on the device within 15 minutes and install the profile; the link works once. Then delete the file the script names (under `/var/www/relay/.publish/`). The password is not printed and not kept anywhere else on the server, which stores only its hash.

To get the profile as a file instead, add `--profile-out /root/iphone.mobileconfig`, copy it to the device, and delete it.

By default it relays Google/Gemini (including Gmail, Drive and YouTube), Claude, X/Grok, ChatGPT and similar services, with a non-empty `MatchDomains`; see the [domain list notes](../deploy/domains/README.md) for the rules and their limits. For a newly generated file, adjust the list with `--domains your-list.txt`; an imported file keeps its own rules.

## What the script does

- Checks the system, the lock against concurrent installs, the domain and port usage; it does not stop other services that hold the ports.
- Installs the dependencies and the Rust toolchain and builds the source as pinned by `Cargo.lock`. By default it builds with one job and turns off LTO to lower the peak memory need on small VPSes; at least 2 GiB of memory and 3 GiB of free disk are recommended. Use `--jobs 2` to build in parallel.
- Creates the system user `network-relay`, which the relay runs as, instead of root. The configuration and a copy of the certificate in `/etc/network-relay/tls` are readable by its group; `install.json` and the backups stay root's. An installation from an earlier version, which read certbot's files directly as root, is moved to the copy. A certificate given with `--cert`/`--key` is read in place and must be readable by the user (the script stops and says how if it is not).
- Obtains or reuses a Let's Encrypt certificate, enables `certbot.timer`, and installs `deploy/certbot-hook.sh` as certbot's deploy hook, which copies each renewed certificate and reloads the relay. TCP 80 must stay open for renewals.
- If UFW is enabled, adds rules for TCP 80 and the relay's TCP/UDP port; it never flushes firewall rules. You still need to open the ports in your own nftables/iptables rules and in the cloud security group.
- Creates the default website and a server configuration that stores only the password's hash (PBKDF2-SHA256 for the generated password, Argon2id for an imported one), and records the domain, port and user name, no secret, in `/etc/network-relay/install.json`; keeps the program's default destination restrictions.
- For a new account, hands over the device profile once (a link, or `--profile-out`) instead of keeping it on the server.
- Installs the systemd unit, enables it at boot, and installs the UDP buffer settings. Existing larger buffer settings are not lowered.
- Replaces the program atomically and checks HTTPS on the local machine; on failure, restores the files from before the installation and the previous running/enabled state. Backups are kept in `/etc/network-relay/backups/timestamp/`, with the original paths recorded in `manifest.json`. Package installation, certificate issuance and UFW rules are not undone by this rollback.
- Runs the networked TCP/UDP self-check over all three HTTP versions when it knows the password (a new installation, or `--profile`). If the external test targets are unreachable, the self-check fails but the started service is left running for diagnosis; passing locally does not replace checking UDP 443 from an outside network.

Without `--binary` it builds from source; if you already have an x64 build for the same Debian version, pass `--binary /path/network-relay`.

## Updating and re-running

For an installation this script created, running the same command again keeps the password and the configuration, including users or settings added by hand. You can also just run:

```bash
sudo bash deploy/install-debian13.sh
```

It reads the installation's domain, port and user name from `/etc/network-relay/install.json`, builds the currently downloaded source and updates the program. It needs neither the profile nor the password, and does not change the devices' profiles. It refuses to overwrite anything if given a different domain, port, user name or password.

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
network-relay profile --host relay.qolita.com --user ipad --match-domain google.com --publish
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
