# Manual deployment: build on macOS, upload to Linux, and use Cloudflare DNS validation

This guide installs Network Relay manually on a fresh Debian 12/13 or Ubuntu 22.04/24.04 **x86_64** VPS. Build the Linux executable on an Intel or Apple Silicon Mac, upload it with SCP, obtain a publicly trusted certificate with Certbot and the Cloudflare DNS plugin, and run the server with systemd. The device profile generated here uses **HTTP/2 only**.

No one-click installer is used. The service unit and certificate renewal hook come from the same source checkout as the executable. If the VPS already runs Network Relay, back up `/etc/network-relay` and review the existing service before replacing anything; these steps describe a fresh installation.

Run commands individually and check each result before continuing. A command with trailing backslashes spans multiple lines. Password prompts do not echo what you type. Replace every placeholder with your own value; do not put credentials in support messages or commit them to Git.

## 1. Prepare the domain, Cloudflare credentials, and firewall

The examples use `relay.example.com`. In Cloudflare, create an A record for the relay hostname pointing to the VPS's actual public IPv4 address. Set its proxy status to **DNS only (gray cloud)**. Add an AAAA record only if the VPS has working public IPv6 connectivity. The ordinary Cloudflare proxy is not suitable for this relay endpoint.

Create a restricted **API Token** in Cloudflare under **My Profile → API Tokens → Create Token**:

- Use the **Edit zone DNS** template.
- Include **Zone / DNS / Edit** permission.
- Restrict the zone resources to the domain's zone.
- Save the token for entry into the VPS's credentials file in step 6.

A Global API Key also works; its credentials format is shown below. API Tokens, Global API Keys, and Origin CA Keys are different credentials. Prefer a token restricted to the required zone.

Allow these inbound ports in the cloud provider's firewall:

| Port | Purpose |
| --- | --- |
| TCP 22, or your actual SSH port | SSH and SCP |
| TCP 443 | HTTPS and HTTP/2 |
| UDP 443 | Server HTTP/3 support and the complete protocol self-check |

**DNS validation does not require inbound TCP 80.** Certbot needs outbound access to Cloudflare and the ACME service. The HTTP/2-only device profile does not need UDP 443, but the server still supports HTTP/3 and its self-check tests it.

## 2. Install build tools on the Mac

Run this section in the **Mac terminal**. If Xcode Command Line Tools are not installed, run the following and finish the installation window before continuing:

```bash
xcode-select --install
```

Install [Homebrew](https://brew.sh/) if necessary, following its PATH instructions, then install GitHub CLI and Zig:

```bash
brew install gh zig
```

If Rust is not already installed through rustup, install it:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

Load the toolchain and prepare the Linux target:

```bash
source "$HOME/.cargo/env"
rustup update stable
rustup default stable
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild --locked
```

Zig supplies the target C compiler needed by `ring`. The project uses rustls rather than OpenSSL. The musl target produces a static Linux x86_64 executable, avoiding a dependency on the VPS's glibc version. Use the same target on Intel and Apple Silicon Macs; do not add `target-cpu=native` for a VPS build.

## 3. Download a fresh main checkout and compile

If GitHub CLI is not already authenticated with an account that can read the repository:

```bash
gh auth login
gh auth setup-git
```

Choose GitHub.com, HTTPS, and browser authentication. Download into a new directory so that existing checkouts and local changes are preserved:

```bash
mkdir -p "$HOME/Projects"
NR_WORK="$HOME/Projects/network-relay-manual-$(date +%Y%m%d-%H%M%S)"
gh repo clone ArcCal/network-relay "$NR_WORK"
cd "$NR_WORK"
git switch main
git pull --ff-only
git log -1 --oneline
```

Build the server:

```bash
cargo zigbuild --locked --release \
  --target x86_64-unknown-linux-musl \
  --bin network-relay
```

Inspect the result:

```bash
file target/x86_64-unknown-linux-musl/release/network-relay
```

It must identify an **ELF x86-64** executable, statically linked or static PIE. A Mach-O file is a macOS executable and is not the Linux server. Do not try to run the Linux executable on the Mac.

Prepare a conveniently named file and its checksum from the source checkout:

```bash
cp target/x86_64-unknown-linux-musl/release/network-relay \
  network-relay-linux-x86_64
shasum -a 256 network-relay-linux-x86_64 \
  > network-relay-linux-x86_64.sha256
```

## 4. Upload with SCP from the Mac

This guide assumes SSH login as root. Replace the example address:

```bash
NR_VPS_IP='YOUR_VPS_PUBLIC_IPV4'
NR_SSH="root@${NR_VPS_IP}"
```

Create the remote directory and upload the executable, checksum, and deployment assets:

```bash
ssh "$NR_SSH" 'mkdir -p /root/network-relay-upload'
```

```bash
scp \
  network-relay-linux-x86_64 \
  network-relay-linux-x86_64.sha256 \
  deploy/network-relay.service \
  deploy/certbot-hook.sh \
  deploy/99-network-relay.conf \
  "${NR_SSH}:/root/network-relay-upload/"
```

Then log in:

```bash
ssh "$NR_SSH"
```

If root SSH login is unavailable, use `ubuntu@YOUR_VPS_PUBLIC_IPV4` instead. Create and upload to `/home/ubuntu/network-relay-upload`, log in as ubuntu, and run `sudo -i`. Set `NR_UPLOAD` to that directory in the next section. Use the actual login user's home directory when it is not ubuntu.

## 5. Install prerequisites and verify the executable on the VPS

From this point, run commands on the **VPS as root**. Set the actual domain, certificate account email, and upload path:

```bash
NR_DOMAIN='relay.example.com'
NR_EMAIL='you@example.com'
NR_UPLOAD='/root/network-relay-upload'
```

These shell variables do not persist after logging out. Set them again if you reconnect.

Check the operating system and CPU architecture:

```bash
cat /etc/os-release
uname -m
```

The architecture must be `x86_64`. Install the required packages:

```bash
apt-get update
```

```bash
apt-get -o DPkg::Lock::Timeout=1800 install -y \
  ca-certificates curl openssl nano file dnsutils iproute2 python3 \
  certbot python3-certbot-dns-cloudflare
```

Verify the uploaded file before installing it:

```bash
cd "$NR_UPLOAD"
sha256sum -c network-relay-linux-x86_64.sha256
file network-relay-linux-x86_64
```

The checksum must report `OK`. Install and confirm that the Linux executable runs:

```bash
install -m 755 network-relay-linux-x86_64 \
  /usr/local/bin/network-relay
network-relay --version
```

Check the Certbot plugin:

```bash
certbot plugins
```

The output must include `dns-cloudflare`. This guide installs Certbot and its plugin together with apt; do not mix this setup with an existing snap or pip Certbot installation.

## 6. Save the Cloudflare credentials on the VPS

Create the root-only credentials file, then edit it:

```bash
install -d -m 700 /root/.secrets/certbot
touch /root/.secrets/certbot/cloudflare.ini
chmod 600 /root/.secrets/certbot/cloudflare.ini
nano /root/.secrets/certbot/cloudflare.ini
```

For an **API Token**, enter only this format:

```ini
dns_cloudflare_api_token = YOUR_CLOUDFLARE_API_TOKEN
```

For a **Global API Key**, use these two lines instead:

```ini
dns_cloudflare_email = YOUR_CLOUDFLARE_ACCOUNT_EMAIL
dns_cloudflare_api_key = YOUR_CLOUDFLARE_GLOBAL_API_KEY
```

Choose one format, replace its placeholders inside nano, and do not combine the two. In nano, save with **Ctrl+O**, Enter, then exit with **Ctrl+X**. Keep this file for automatic renewals.

## 7. Obtain the certificate through DNS challenge

Run:

```bash
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 60 \
  --cert-name "$NR_DOMAIN" \
  -d "$NR_DOMAIN" \
  --email "$NR_EMAIL" \
  --agree-tos \
  --non-interactive
```

This accepts the Let's Encrypt terms of service. The plugin creates the verification TXT record, waits for propagation, and removes it after validation. `--cert-name` makes the certificate lineage match the path used below.

After success, inspect the certificate:

```bash
certbot certificates
```

```bash
openssl x509 \
  -in "/etc/letsencrypt/live/${NR_DOMAIN}/fullchain.pem" \
  -noout -subject -issuer -dates
```

The certificate and key are in `/etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem` and `privkey.pem`. DNS validation can issue a certificate without reaching the VPS, so issuance alone does not prove that the domain's A/AAAA records or port 443 are correct.

## 8. Create the service account, website, and renewal hook

Create the service account if it does not exist:

```bash
if ! id network-relay >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home \
    --home-dir /nonexistent \
    --shell /usr/sbin/nologin \
    network-relay
fi
```

Create the configuration, certificate, and website directories:

```bash
install -d -o root -g network-relay -m 750 \
  /etc/network-relay \
  /etc/network-relay/tls
install -d -o root -g root -m 755 /var/www/relay
```

Add a simple static website:

```bash
cat > /var/www/relay/index.html <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Welcome</title>
</head>
<body>
  <h1>Welcome</h1>
  <p>This website is online.</p>
</body>
</html>
HTML
```

```bash
chmod 644 /var/www/relay/index.html
```

Install the repository's Certbot deploy hook and record the certificate lineage:

```bash
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
printf '%s\n' "/etc/letsencrypt/live/${NR_DOMAIN}" \
  > /etc/network-relay/tls/source
install -m 755 "$NR_UPLOAD/certbot-hook.sh" \
  /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

Run the hook once to copy the initial certificate and key:

```bash
/etc/letsencrypt/renewal-hooks/deploy/network-relay
ls -l /etc/network-relay/tls/
```

The copied `fullchain.pem` and `privkey.pem` must belong to `root:network-relay` with mode `640`. The service runs as `network-relay`, so it reads these copies rather than Certbot's root-only originals. On renewal, the hook copies the renewed pair and reloads the active service.

Do not move the service's configuration, website, or certificate copies into `/root` or `/home`: the supplied systemd service uses `ProtectHome=yes`.

## 9. Create credentials and write the server configuration

Generate a device account:

```bash
network-relay passwd --name iphone
```

Save the generated plaintext password in a password manager. Copy the complete `[[user]]`, `name`, and `password_hash` lines into the configuration. The plaintext password is for the client; the server stores the hash.

Open the configuration:

```bash
nano /etc/network-relay/relay.toml
```

**File contents**:

```toml
listen = "[::]:443"

[tls]
cert = "/etc/network-relay/tls/fullchain.pem"
key = "/etc/network-relay/tls/privkey.pem"

[web]
root = "/var/www/relay"

[relay]
udp_template = "/.well-known/masque/udp/{target_host}/{target_port}/"

[[user]]
name = "iphone"
password_hash = "PASTE_THE_COMPLETE_GENERATED_HASH_HERE"
```

Replace the final account stanza with the exact output of `passwd`; do not put the plaintext password in `password_hash`. Unspecified destination restrictions retain the program defaults. For other options, see [Configuration](config.md).

Set permissions and validate as the actual service user:

```bash
chown root:network-relay /etc/network-relay/relay.toml
chmod 640 /etc/network-relay/relay.toml
runuser -u network-relay -- \
  /usr/local/bin/network-relay serve \
  --config /etc/network-relay/relay.toml \
  --check
```

Expect `configuration, certificate and website are fine; users: 1`. Resolve any error before starting the service.

## 10. Open the host firewall and start the service

If UFW is already installed and active on the VPS, allow the service ports:

```bash
ufw allow 443/tcp
ufw allow 443/udp
ufw status
```

Do not enable UFW without first allowing the actual SSH port. Other host firewalls need equivalent rules, in addition to the cloud provider's firewall.

For server HTTP/3 support, apply the repository's UDP buffer settings:

```bash
install -m 644 "$NR_UPLOAD/99-network-relay.conf" \
  /etc/sysctl.d/99-network-relay.conf
sysctl -p /etc/sysctl.d/99-network-relay.conf
```

Some VPS environments prohibit these sysctl changes. They affect HTTP/3 buffer capacity, not the HTTP/2-only profile.

Install and start the supplied systemd service:

```bash
install -m 644 "$NR_UPLOAD/network-relay.service" \
  /etc/systemd/system/network-relay.service
systemctl daemon-reload
systemctl enable --now network-relay
systemctl status network-relay --no-pager -l
journalctl -u network-relay -n 50 --no-pager -l
```

Expect `active (running)`. Verify TCP and UDP listeners:

```bash
ss -lntp 'sport = :443'
ss -lnup 'sport = :443'
```

## 11. Validate HTTPS, relay credentials, and certificate renewal

On the VPS, check HTTPS locally while preserving hostname certificate verification:

```bash
curl --noproxy '*' \
  --resolve "${NR_DOMAIN}:443:127.0.0.1" \
  -I "https://${NR_DOMAIN}/"
```

Check authenticated TCP and UDP relay functionality:

```bash
network-relay check \
  --server "$NR_DOMAIN" \
  --address 127.0.0.1 \
  --user iphone
```

Enter the saved plaintext password. The check tests HTTP/3, HTTP/2, and HTTP/1.1; it has no single-protocol selector. This local check does not test the cloud firewall or the path from a device.

Enable automatic renewal and inspect the timer:

```bash
systemctl enable --now certbot.timer
systemctl list-timers --all certbot.timer
```

Test renewal and the deploy hook:

```bash
certbot renew \
  --cert-name "$NR_DOMAIN" \
  --dry-run \
  --run-deploy-hooks
```

Expect a successful simulated renewal. Retain the Cloudflare credentials file so unattended renewals can complete. The hook uses the active certificate lineage when run during a dry run.

In a separate **Mac terminal**, test external reachability with the actual domain and IP:

```bash
NR_DOMAIN='relay.example.com'
NR_VPS_IP='YOUR_VPS_PUBLIC_IPV4'
curl --noproxy '*' \
  --resolve "${NR_DOMAIN}:443:${NR_VPS_IP}" \
  -I "https://${NR_DOMAIN}/"
```

This verifies external TCP reachability and HTTPS trust. Open `https://YOUR_DOMAIN/` in a browser as well to check the ordinary DNS path. Actual relay operation still needs the device profile or a relay client.

## 12. Generate an HTTP/2-only device profile on the VPS

For all traffic through the relay, excluding the relay's own hostname:

```bash
network-relay profile \
  --host "$NR_DOMAIN" \
  --user iphone \
  --no-http3 \
  --exclude-domain "$NR_DOMAIN" \
  --ui-toggle-enabled \
  --out /root/iphone-http2.mobileconfig
```

Enter the account's plaintext password at the prompt. Alternatively, to relay only selected domains, use this command **instead**:

```bash
network-relay profile \
  --host "$NR_DOMAIN" \
  --user iphone \
  --no-http3 \
  --match-domain google.com \
  --match-domain youtube.com \
  --ui-toggle-enabled \
  --out /root/iphone-http2.mobileconfig
```

`--match-domain` includes the domain's subdomains. With no match domains or exact-host matches, the profile relays all traffic except exclusions. The Settings toggle requires iOS/iPadOS/macOS 26 or later; older supported systems ignore that option.

**Always include `--no-http3` in this manual workflow.** The one-click installers add it automatically, but the low-level `profile` command still advertises both HTTP versions by default. This option removes `HTTP3RelayURL` and retains `HTTP2RelayURL`, selecting HTTP/2 over TLS/TCP for the device-to-relay transport. It does not disable UDP application forwarding through CONNECT-UDP, nor does it disable HTTP/3 on the server.

Inspect the generated plist:

```bash
python3 - <<'PY'
import plistlib

with open("/root/iphone-http2.mobileconfig", "rb") as f:
    profile = plistlib.load(f)

relays = [
    relay
    for payload in profile["PayloadContent"]
    if payload.get("PayloadType") == "com.apple.relay.managed"
    for relay in payload["Relays"]
]

assert relays, "No relay configuration found"
for relay in relays:
    assert "HTTP2RelayURL" in relay
    assert "HTTP3RelayURL" not in relay

print("PASS: HTTP/2 only; HTTP3RelayURL is absent")
PY
```

## 13. Download the profile to the Mac and install it

In the **Mac terminal**:

```bash
NR_VPS_IP='YOUR_VPS_PUBLIC_IPV4'
NR_SSH="root@${NR_VPS_IP}"
scp "${NR_SSH}:/root/iphone-http2.mobileconfig" \
  "$HOME/Downloads/iphone-http2.mobileconfig"
```

Use AirDrop to send the file to the iPhone, then install the downloaded profile in Settings. Remove the old Network Relay profile before installing its replacement. For device installation steps, see [Installing the profile](../README.md#installing-the-profile-on-iphone-ipad-and-mac).

Once delivered, remove the temporary server copy from the Mac:

```bash
ssh "$NR_SSH" 'rm -f /root/iphone-http2.mobileconfig'
```

If you use an ubuntu SSH account, first make a private, user-owned copy on the **VPS as root**:

```bash
install -o ubuntu -g ubuntu -m 600 \
  /root/iphone-http2.mobileconfig \
  /home/ubuntu/iphone-http2.mobileconfig
```

Download it in the **Mac terminal**:

```bash
scp "ubuntu@${NR_VPS_IP}:iphone-http2.mobileconfig" \
  "$HOME/Downloads/iphone-http2.mobileconfig"
ssh "ubuntu@${NR_VPS_IP}" 'rm -f /home/ubuntu/iphone-http2.mobileconfig'
```

Then remove `/root/iphone-http2.mobileconfig` on the VPS as root as well. Use the actual account and home path when they differ. The profile contains recoverable credentials; remove temporary copies after delivery or keep any retained copy in secure storage.

## 14. Maintenance and troubleshooting

Follow live logs:

```bash
journalctl -u network-relay -f -l
```

After editing users, destination rules, the website, or certificate contents, validate and reload:

```bash
network-relay serve --config /etc/network-relay/relay.toml --check \
  && systemctl reload network-relay
```

Changing the listener, TLS path settings, or restart-required connection limits needs a restart; see [Configuration](config.md). For a binary upgrade, upload a freshly built and checksum-verified executable, then stop the service before replacing the installed executable:

```bash
systemctl stop network-relay
install -m 755 "$NR_UPLOAD/network-relay-linux-x86_64" \
  /usr/local/bin/network-relay
systemctl start network-relay
systemctl status network-relay --no-pager -l
```

| Symptom | First checks |
| --- | --- |
| Certbot cannot find the zone or Cloudflare authentication fails | Token permissions, zone scope, and credentials format |
| Port 443 is unavailable | An existing nginx, Caddy, or relay service occupying TCP or UDP 443 |
| Binding `[::]:443` fails with `Can't assign requested address` | Whether IPv6 is disabled; use `listen = "0.0.0.0:443"` for IPv4-only operation |
| HTTPS certificate validation fails | Domain, A/AAAA records, certificate hostname, and server clock |
| Client receives 404 and server logs `authentication failed` | Exact username and password; the server hides authentication failures |
| HTTP/2 works but external HTTP/3 fails | UDP 443, host/cloud firewalls, and the network path; this does not prevent using the HTTP/2-only profile |
| Service cannot read the configuration or certificate | File ownership/modes and placement outside `/home` and `/root` |

The examples have been checked against the repository's command-line interfaces and the documentation below. A macOS cross-build, production certificate issuance, and real-device installation still need to be verified on your machines; the guide does not claim those operations ran in the development environment.

## References

- [cargo-zigbuild usage and static-target guidance](https://github.com/rust-cross/cargo-zigbuild#usage)
- [Certbot Cloudflare DNS plugin: credentials and propagation options](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)
- [Certbot renewal and deploy hooks](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates)
- [Apple Relay payload schema](https://developer.apple.com/documentation/devicemanagement/relay/relay)
- [Server configuration and CLI options](config.md)
- [Additional deployment notes](deploy.md)
