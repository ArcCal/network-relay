# Deployment notes

For an automatic install on Debian 12/13 x64 using an uploaded prebuilt binary, including certificates and a domain-based profile, see the [automatic deployment guide](deploy-debian13.md). Source compilation is optional and requires `--build-from-source`.

The README's [one-step install](../README.md#option-1-one-step-install-on-debian-1213-recommended) and [manual install](../README.md#option-2-manual-install) are the complete deployment steps. This page covers a few alternatives mentioned there.

## Building from source

When there is no release, or you want the latest code, build on the server yourself. It needs about 1 GB of memory; a server with little memory may need swap first.

```bash
apt install -y build-essential git
```

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```bash
source "$HOME/.cargo/env"
```

The repository is private. The simplest way is to log in to GitHub in your computer's browser, download the ZIP of the `main` branch, upload it to the server and extract it (see the README's [one-step install, step 2](../README.md#step-2-download-the-source-and-upload-it)), then skip to the `cd` step below. Alternatively, log in with GitHub's official command-line tool on the server and clone:

```bash
apt install -y gh
```

```bash
gh auth login
```

Choose `GitHub.com` → `HTTPS` → `Y` → `Login with a web browser`; it shows an 8-character code. Open https://github.com/login/device in a browser **on your computer or phone**, enter the code and click Authorize. Once the server shows `Logged in as ...`:

```bash
gh repo clone ArcCal/network-relay
```

```bash
cd network-relay
```

```bash
cargo build --release
```

```bash
install -m 755 target/release/network-relay /usr/local/bin/
```

Then continue with step 6 (the decoy website) of the README's [manual install](../README.md#option-2-manual-install). The `deploy/` directory used in steps 9 and 10 is in this source directory.

To update:

```bash
cd /root/network-relay && git pull && cargo build --release && install -m 755 target/release/network-relay /usr/local/bin/ && systemctl restart network-relay
```

## Self-check from a Mac

`network-relay check` run on the server tests "the server connecting to itself". To confirm the relay is also reachable from outside (from your home network, say), run the same command on a Mac.

Build it on the Mac first (the same way as building masque-vpn):

```bash
xcode-select --install
```

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```bash
source "$HOME/.cargo/env"
```

```bash
git clone https://github.com/ArcCal/network-relay
```

The repository is private: when prompted, enter your GitHub user name as the user name and a GitHub personal access token as the password (create one under Settings → Developer settings on the GitHub website; read access to this repository is enough). If you would rather not use git, log in to GitHub in a browser, open the repository page, choose Code → Download ZIP, and extract it.

```bash
cd network-relay && cargo build --release
```

Then (**quit proxy apps such as Clash or Stash first**, or you will be testing them):

```bash
./target/release/network-relay check --server relay.example.com --user macbook
```

- The server runs only on Linux, but the `check` and `profile` commands also work on a Mac.
- To skip DNS and connect to a specific IP, add `--address server-IP`.

## Certificates

### Port 80 unavailable: use DNS validation

`certbot --standalone` needs TCP 80. When port 80 is taken or blocked, use DNS validation instead, which needs no ports:

```bash
certbot certonly --manual --preferred-challenges dns -d relay.example.com
```

As prompted, add a TXT record for `_acme-challenge.relay.example.com` in the domain's DNS, wait a minute or two, then press Enter.

- Manual DNS validation **does not renew automatically**; you have to do it again within 90 days. If the domain is on Cloudflare, you can install `python3-certbot-dns-cloudflare` and let it complete the challenge with a Cloudflare API token, which does renew automatically.
- The certificate files end up in the same place as with `--standalone`, so the configuration does not change.

### When a renewal takes effect

The relay runs as user `network-relay` and reads a copy of the certificate in `/etc/network-relay/tls`, since certbot's own files can be read by root alone. `deploy/certbot-hook.sh`, installed as certbot's deploy hook (`/etc/letsencrypt/renewal-hooks/deploy/network-relay`), makes that copy after every renewal of the certificate named in `/etc/network-relay/tls/source` and reloads the relay; see step 8 of the manual install in the README. The relay also rereads the files by itself every day at 3 a.m. (system time zone).

## Firewall on the server

Besides the cloud provider's firewall, if ufw is enabled on the server:

```bash
ufw allow 443/tcp
```

```bash
ufw allow 443/udp
```

```bash
ufw allow 80/tcp
```

If you write your own nftables or iptables rules, allow TCP 80, TCP 443 and UDP 443 in the same way.

## A port other than 443

`listen` can be changed to another port, such as `listen = "[::]:8443"`. Then:

- allow that port on both TCP and UDP in the cloud firewall;
- add `--port 8443` when generating profiles and when running the self-check.

443 is best: many networks only allow 443, and it looks like an ordinary website.

## Sharing a server with other websites

The relay needs TCP 443 and UDP 443 to itself. If nginx or similar already holds 443 on the server, the simplest fix is to give the relay its own server or IP address. The relay's built-in decoy website can serve any static pages (the `[web] root` directory), so in many cases nginx is no longer needed.

## What the systemd service does

`deploy/network-relay.service`:

- Runs as user `network-relay` (`User=`, `Group=`), with only the permission to bind port 443 added (`AmbientCapabilities=CAP_NET_BIND_SERVICE`, and nothing else in `CapabilityBoundingSet`). The configuration and the copy of the TLS key are readable by group `network-relay`; the one-step installer and step 8 of the manual install set this up.
- System directories are read-only, /home is hidden, /tmp is private, and so on.
- `systemctl reload` sends SIGHUP, which rereads the configuration.
- The open-file limit is 1048576: each relayed connection uses one.
- Logs go to the journal; with `log_dir = "/var/log/network-relay"` configured they are also saved to files (systemd creates that directory).
