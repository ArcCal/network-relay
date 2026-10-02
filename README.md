# Network Relay

A server for the **built-in "Network Relay"** feature of iPhone, iPad and Mac.

- **No app to install on the device**: install a profile (`.mobileconfig`) and the system itself forwards traffic through your server.
- Traffic can be selected or excluded by **domain and subdomains** or by **exact host name**, or **all traffic** can go through the relay. Exact matching needs iOS 18.4 / macOS 15.4 or later.
- The protocols are the standard ones Apple specifies: HTTP CONNECT for TCP and CONNECT-UDP (RFC 9298) for UDP, over HTTP/3 (QUIC), HTTP/2 and HTTP/1.1.
- User name and password authentication. Anyone visiting your domain without the password sees only an ordinary website.
- Needs iOS / iPadOS 17, macOS 14 or later.

> **Current status**: the server has been tested end to end on all three HTTP versions with curl, quic-go's masque-go client and the built-in self-check tool, and has automated tests. **It has not yet been systematically verified on real iPhones and Macs.** If you run into problems, read [Common pitfalls](#common-pitfalls-read-these) and [Troubleshooting](#troubleshooting) first.

This project and [masque-vpn](https://github.com/ArcCal/masque-vpn) are two independent projects: masque-vpn is a full-device CONNECT-IP VPN that needs its own client; this one uses a feature built into Apple's operating systems and needs no client.

## Contents

- [Before you start: read this](#before-you-start-read-this)
- [Common pitfalls (read these)](#common-pitfalls-read-these)
- [Option 1: one-step install on Debian 12/13 (recommended)](#option-1-one-step-install-on-debian-1213-recommended)
- [Option 2: manual install (other systems, or to control every step yourself)](#option-2-manual-install)
- [Installing the profile on iPhone, iPad and Mac](#installing-the-profile-on-iphone-ipad-and-mac)
- [A profile for named services plus gfwlist](#a-profile-for-named-services-plus-gfwlist)
- [Changing the password](#changing-the-password)
- [Day-to-day operations](#day-to-day-operations)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)
- [Technical notes](#technical-notes)

---

## Before you start: read this

1. **Copy one command at a time, press Enter, and read the output before the next one.**
   When you paste several lines at once and one of the commands asks for a password, the following lines are swallowed as the password; or an earlier command fails and the next one runs anyway, so it looks as if nothing happened. That is why every gray box in this document holds just one command.
   Gray boxes labeled **"File contents"** are not commands; they are to be pasted into the nano editor.
2. **Replace the examples with your own values:**

   | Example | Replace with |
   |---|---|
   | `relay.example.com` | Your relay domain |
   | `iphone` | The user name you give this device (**one per device**, so each can be disabled separately) |
   | `203.0.113.10` | Your server's public IP |
   | `~/.ssh/your-key` | The SSH private key you log in to the server with |

3. **Nothing shows on screen while you type a password.** That is normal; press Enter when done.
4. **Never send your password or profile to anyone**, including pasting them into chats, support tickets or AI conversations when asking for help. The profile contains the password in an easily decoded form. Logs are fine to share when asking for help, but check them for passwords first.
5. **Think before pressing `Ctrl+C`**: during installation, compiling or waiting for system updates, the screen may show no new output for several minutes. It has not frozen. Pressing `Ctrl+C` midway only makes you start over.

---

## Common pitfalls (read these)

All of these happened in real deployments.

### Server and network

| Pitfall | Consequence | How to avoid it |
|---|---|---|
| **Cloud firewall does not allow UDP 443** | HTTP/3 fails, devices fall back to HTTP/2, which is a bit slower; `check` fails only the two HTTP/3 lines | Add **UDP** 443 in the cloud provider's console. Many clouds open only TCP by default. On AWS Lightsail it is the instance's "Networking" tab, and both the IPv4 and IPv6 tables need the rule; on Vultr check whether the instance is attached to a "Firewall Group"; on Oracle Cloud edit the security list |
| **Cloud firewall does not allow TCP 80** | Certificate request fails (`Timeout during connect (likely firewall problem)`), and the certificate cannot be renewed automatically later | Keep TCP 80 open **permanently**, not just while requesting the certificate |
| The server's own firewall (ufw, nftables, iptables) blocks the ports | Same as above | The one-step install opens the ports automatically when ufw is active; your own nftables/iptables rules need TCP 80, TCP 443 and UDP 443 opened by hand. Some images (Oracle Cloud's Ubuntu, for example) ship iptables rules that allow only port 22 |
| **Cloudflare's orange cloud (proxy) is on** | The relay does not work at all, and opening the domain in a browser does not show your website | The DNS record must be **gray cloud (DNS only)** |
| DNS has not propagated yet, or points at the wrong IP | Certificate request fails, devices cannot connect | **On the server**, run `getent hosts relay.example.com`; the IP shown must match `curl -4 -s https://ifconfig.me` |
| Checking DNS from the iPhone/Mac | With Clash, Stash or Surge running you get fake `198.18.x.x` addresses and think DNS is wrong | Check only on the server |
| The server has no fixed public IP | After a reboot the IP changes and DNS points at the old one | Attach a "static IP / Elastic IP / Reserved IP" |
| Port 443 is already used by nginx, tuic, hysteria, xray or similar | The installer reports `Port 443 is already in use by another service` and does **not** stop it for you. QUIC-based proxies (tuic, hysteria) often hold **UDP** 443 | The relay needs TCP 443 and UDP 443 to itself. Find out who holds it with `ss -lntup \| grep ':443 '`, then use another machine or IP, or stop that service |
| Logging in to the server over Tailscale (`100.x.x.x`) | DNS gets a `100.x` address and the relay is unreachable from the internet | The A record must be the **public IP**. On the server, find the public IP with `curl -4 -s https://ifconfig.me; echo` |

### Installation

| Pitfall | Consequence | How to avoid it |
|---|---|---|
| **A freshly created VPS is running automatic updates** | Older versions of the script report `Could not get lock /var/lib/dpkg/lock-frontend ... (unattended-upgr)` | Newer versions of the script wait for it, up to 30 minutes, which looks like a hang; **do not press Ctrl+C**. **Never delete the lock file or kill that process**; it will break the system's package management |
| Using `fuser` to check the lock | A minimal Debian install has no `fuser`, so the check always says "not in use" | No need to check yourself; the script waits |
| **Not enough memory** | `Killed` or `signal: 9, SIGKILL` while compiling, or the whole machine freezes | Compiling needs about 2 GiB of memory. On a 1 GiB machine add swap first; see [adding swap](#less-than-2-gib-of-memory-add-swap-first) |
| Not enough disk | `No space left on device` | Keep at least 3 GiB free |
| **Downloaded an old version of the source** | Missing new features (such as `deploy/global-profile.py`), or old bugs still there | On the GitHub repository page, make sure the branch is `main`, then Code → Download ZIP |
| The downloaded ZIP's name contains `(1)` | `unzip network-relay-main(1).zip` gives a syntax error | Quote the file name: `unzip 'network-relay-main(1).zip'` |
| Not running from the source directory | `No such file or directory` | First `cd` into the extracted directory (you should see `Cargo.toml`, `deploy` and `src` in it) |
| Running the script with `sh` | Syntax errors | Use `bash`: `bash deploy/install-debian13.sh ...` |
| Running the one-step install on something other than Debian 12/13, or not on x86_64 | `supports only Debian 12/13 x86_64` (older versions of the script accepted only Debian 13) | Check the version with `cat /etc/os-release`; on other systems use the [manual install](#option-2-manual-install) |
| Logged in as an ordinary user such as `admin` or `ubuntu` | Permission denied | First `sudo -i` to become root; the prompt then ends in `#` |

### Password and profile

| Pitfall | Consequence | How to avoid it |
|---|---|---|
| **Copying terminal output to show someone** | It may contain the password printed by `passwd` or what you typed during `check`; the password leaks | Check before pasting; if it leaked, [change the password](#changing-the-password) |
| **Changed the password on the server but not in the profile** (or the other way round) | The device cannot connect; server log shows `authentication failed user="iphone"` | Always change both together |
| **Appending** a second `[[user]]` section with the same name to `relay.toml` | `user iphone appears twice`, the configuration does not take effect | When changing a password, **replace only** the `password_hash` line |
| Not running `systemctl reload network-relay` after editing the configuration | The new password does not take effect and the old one still works | After every configuration change: `network-relay serve --check`, then `systemctl reload network-relay` |
| Pasting `serve --check` and `systemctl reload` together | The first one fails, the second runs anyway, and you think it worked | Run them one line at a time |
| Replacing only part of the Base64 when editing a profile by hand | Authentication fails | Replace the whole string from after `Basic ` up to just before `</string>`, **including any trailing `=`** |
| Editing the profile in macOS TextEdit | It is saved as rich text and the file is ruined | First choose Format → Make Plain Text, or use an editor such as VS Code |
| The profile was saved as `.txt` | The device does not recognize it | It must end in `.mobileconfig` |
| Leaving the profile in Downloads or in the website directory | Anyone who gets it can use your relay | Delete it right after installing |
| Forgetting to delete it after `--publish` put it on the website | Anyone who guesses the link can download it | Right after installing, `rm` it and run `systemctl reload network-relay` |

### On the device

| Pitfall | Consequence | How to avoid it |
|---|---|---|
| **Clash, Stash, Shadowrocket, Surge or similar is on** | They take the traffic first, so you cannot tell whether the relay works | While testing, disconnect them in Settings → VPN first |
| **`MatchDomains` is empty** | Apple's rule: an empty match list means **all traffic** goes through the relay | To proxy only some websites, you must give `--match-domain` |
| Only `--match-fqdn` given, on a device older than iOS 18.4 | Older systems do not recognize that key, which may end up sending all traffic through the relay | Use `--match-domain` for older devices |
| `--ui-toggle-enabled false` | The relay **cannot** be turned off in Settings. If the relay is blocked while you travel abroad, every matching website stops working at once, and the only way out is to remove the profile | To keep a way out, use `true` (this switch needs iOS/macOS 26+; older systems ignore it) |
| Thinking "all traffic through the relay" equals a VPN | Some apps bring their own networking stack (some Google apps, Spotify, Instagram and others) and may bypass the relay; ICMP such as ping does not go through it either | This is a limit of the system feature, not a configuration error |
| Opening the profile link in a browser other than Safari | It cannot be installed | Use Safari on the iPhone; or download it on a Mac and AirDrop it to the iPhone |

---

## Option 1: one-step install on Debian 12/13 (recommended)

**For**: a Debian 12 or 13, x86_64, systemd VPS (the Debian images from Vultr, AWS Lightsail, Google Cloud, DigitalOcean and others all qualify). If you are not sure of the version, run `cat /etc/os-release` on the server and look at `VERSION_ID`.
**What the script does**: install dependencies → build from source as pinned by `Cargo.lock` → obtain a Let's Encrypt certificate and set up automatic renewal → generate a random password and user → write the configuration and install the systemd service → start it and run a self-check on the machine → write the device profile. On failure it automatically restores the files from before the installation.

### Step 1: Prepare the domain and firewall (on your computer, in a browser)

1. Add a DNS **A record**: `relay.example.com` → the server's public IPv4 address. In Cloudflare, choose the **gray cloud**.
2. Allow these in the cloud firewall:

   | Protocol | Port | Purpose |
   |---|---|---|
   | TCP | 22 | SSH login (usually already there; **do not remove it**) |
   | TCP | 80 | Obtaining and renewing certificates (**keep it open permanently**) |
   | TCP | 443 | HTTP/2 and HTTP/1.1 relay, and the decoy website |
   | **UDP** | **443** | HTTP/3 relay (**many clouds do not have it by default; you must add it**) |

   If the server has IPv6, add the same rules to the IPv6 firewall.

### Step 2: Download the source and upload it

1. Log in to GitHub in your browser (the repository is private and cannot be seen without logging in), open the repository page, make sure the branch at the top left is **`main`**, and click **Code → Download ZIP**.
2. Upload it from the Mac's Terminal (use the file name you actually downloaded):
   ```bash
   scp -i ~/.ssh/your-key ~/Downloads/network-relay-main.zip root@203.0.113.10:/root/
   ```
   On clouds where you log in as an ordinary user (such as `admin` on Lightsail or `ubuntu` on Ubuntu), replace `root@` with that user and the path with `/home/admin/` or similar.

### Step 3: Log in to the server

```bash
ssh -i ~/.ssh/your-key root@203.0.113.10
```

If you did not log in as root, then run:

```bash
sudo -i
```

The prompt should end in `#`. **All later commands on the server are run as root.**

### Step 4: Confirm the domain points at this server

```bash
getent hosts relay.example.com
```

```bash
curl -4 -s https://ifconfig.me; echo
```

The two IPs must be the same. If not, go back and fix DNS, wait a few minutes and try again; **do not continue**.

### Step 5: Extract the source and enter its directory

```bash
cd /root
```

```bash
apt-get -o DPkg::Lock::Timeout=1800 install -y unzip
```

If the new machine is running automatic updates, this waits for them to finish first (up to 30 minutes). It looks like a hang; do not press Ctrl+C.

```bash
unzip 'network-relay-main.zip'
```

If the file name contains `(1)` or similar, still put the whole name in single quotes.

```bash
cd network-relay-main
```

```bash
ls
```

You should see `Cargo.toml  deploy  docs  src ...`.

### Step 6: Run the installer

```bash
bash deploy/install-debian13.sh --domain relay.example.com
```

- The default user name is `iphone`; for another one, add `--user NAME`.
- To receive certificate expiry reminders by email, add `--email you@example.com`.
- On machines with 4 GiB of memory or more, add `--jobs 2` to compile a bit faster.
- The whole process takes **5 to 20 minutes**, mostly compiling. If a new machine is running automatic updates, the script waits for them first. **Do not press Ctrl+C in the meantime.**

**On success, the end of the output looks like:**

```
Installation complete. Device profile: /etc/network-relay/device.mobileconfig (contains the password, mode 600, not published on the website).
Checking the TCP/UDP relay over all three HTTP versions from this machine; access from the internet still has to be confirmed from a device.
✓ HTTP/3 TCP (CONNECT) ...
...
All checks passed.
```

- The password is 32 random characters. It is **not printed**, only written into this profile.
- The generated profile relays only Google / Gemini / YouTube / Claude / ChatGPT / X and similar services by default (the list is in `deploy/domains/google-ai-social.txt`); other websites connect directly. For a wider scope, see [A profile for named services plus gfwlist](#a-profile-for-named-services-plus-gfwlist).
- Passing the self-check on the machine **does not mean** the relay is reachable from the internet (the cloud firewall filters incoming traffic). The device is the final test.

**Running it again is safe**: running it again on the same machine (to update to newer source, for example) keeps the password, the user and any configuration you edited by hand, and only updates the program.

### Less than 2 GiB of memory: add swap first

```bash
free -h
```

If `total` on the `Mem` line is less than 2G, run these in order:

```bash
fallocate -l 2G /swapfile
```

```bash
chmod 600 /swapfile
```

```bash
mkswap /swapfile
```

```bash
swapon /swapfile
```

```bash
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

Then run the installer.

### You already have a profile someone delivered to you

Upload that `.mobileconfig` to the server and import it during installation; the server then uses the same credentials, so the device does not need a new profile:

```bash
bash deploy/install-debian13.sh --profile /root/relay.example.com-iphone.mobileconfig
```

For more details, see [docs/deploy-debian13.md](docs/deploy-debian13.md).

---

## Option 2: manual install

For Debian 12, Ubuntu 22.04 and later, or if you want to control every step yourself. You need a Linux server with a public IP and a domain. The commands use Debian as the example; Ubuntu is the same.

### Step 1: Firewall and domain

Same as [step 1 of the one-step install](#step-1-prepare-the-domain-and-firewall-on-your-computer-in-a-browser).

### Step 2: Log in to the server and become root

```bash
sudo -i
```

On Debian without sudo, use `su -`.

### Step 3: Install software and confirm the domain

```bash
apt-get -o DPkg::Lock::Timeout=1800 update
```

```bash
apt-get -o DPkg::Lock::Timeout=1800 install -y certbot curl
```

If the new machine is running automatic updates, these wait for them to finish first. It looks like a hang; do not press Ctrl+C.

```bash
getent hosts relay.example.com
```

```bash
curl -4 -s https://ifconfig.me; echo
```

**The two IPs must be the same.**

### Step 4: Obtain a certificate

```bash
certbot certonly --standalone -d relay.example.com
```

The first time, it asks for an email address (enter yours), whether you agree to the terms (`Y`), and whether to share your email (`N`).

**You should see:** `Successfully received certificate.`

- `Timeout during connect (likely firewall problem)`: TCP 80 is not open; go back to step 1.
- `Address already in use`: port 80 is held by nginx or similar. Stop it first, or use DNS validation; see [docs/deploy.md](docs/deploy.md#port-80-unavailable-use-dns-validation).

### Step 5: Install the program

Pick one of two sources:

- **Release**: on the GitHub Releases page, download `network-relay-VERSION-linux-x86_64.tar.gz` (on an ARM server, the `arm64` one; if unsure, run `uname -m` on the server: `aarch64` means arm64). After uploading it:
  ```bash
  tar -xzf network-relay-*-linux-x86_64.tar.gz
  ```
  ```bash
  cd network-relay-*-linux-x86_64
  ```
  ```bash
  install -m 755 network-relay /usr/local/bin/
  ```
- **Build it yourself**: see [docs/deploy.md](docs/deploy.md#building-from-source).

```bash
network-relay --version
```

**You should see** `network-relay 0.1.0` (or a newer version). **Stay in this directory**; the `deploy/` files in it are needed later.

### Step 6: Put up a decoy website

```bash
mkdir -p /var/www/relay
```

```bash
echo '<!doctype html><title>Welcome</title><h1>Welcome</h1>' > /var/www/relay/index.html
```

### Step 7: Create a user

```bash
network-relay passwd --name iphone
```

It prints three parts:

```
# 1. Add these lines to the end of /etc/network-relay/relay.toml, then: sudo systemctl reload network-relay
[[user]]
name = "iphone"
password_hash = "$argon2id$v=19$..."

# 2. The password (shown only now; the server keeps only the hash):
Xy3... (a 24-character password)

# 3. Make the profile for the device: ...
```

- Part 1 goes into the configuration file in the next step. **Copy the whole `password_hash` line**; it is long, so do not miss the end.
- Part 2 is the password. It is **shown only this once**; store it in a password manager. **Do not send screenshots of it to anyone.**

### Step 8: Write the configuration

```bash
mkdir -p /etc/network-relay
```

```bash
nano /etc/network-relay/relay.toml
```

**File contents** (replace `relay.example.com` with your domain, and the last three lines with part 1 printed in the previous step):

```toml
listen = "[::]:443"

[tls]
cert = "/etc/letsencrypt/live/relay.example.com/fullchain.pem"
key = "/etc/letsencrypt/live/relay.example.com/privkey.pem"

[web]
root = "/var/www/relay"

[[user]]
name = "iphone"
password_hash = "$argon2id$v=19$..."
```

Press `Ctrl+O` and Enter to save, `Ctrl+X` to exit.

```bash
chmod 600 /etc/network-relay/relay.toml
```

```bash
network-relay serve --check
```

**You should see:** `... configuration, certificate and website are fine; users: 1`

Errors point out the line and the key. The most common: the domain was not replaced, `password_hash` was not copied in full, or the quotes are curly quotes instead of straight `"`. For the other settings, see [docs/config.md](docs/config.md).

### Step 9: Raise the UDP buffer limits

```bash
cp deploy/99-network-relay.conf /etc/sysctl.d/
```

```bash
sysctl --system
```

Some VPSes do not allow changing these two parameters. Errors can be ignored; HTTP/3 may just drop packets at high speed.

### Step 10: Start it

```bash
cp deploy/network-relay.service /etc/systemd/system/
```

```bash
systemctl daemon-reload
```

```bash
systemctl enable --now network-relay
```

```bash
journalctl -u network-relay -n 20 --no-pager -o cat
```

**You should see:**

```
INFO TLS certificate: relay.example.com, valid until ...
INFO network-relay 0.1.0 ready (HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP) ...
```

- From now on it starts at boot and restarts automatically after a crash.
- Always read the logs with the `journalctl` command above; `systemctl status` truncates long lines.

To have the relay pick up a renewed certificate immediately:

```bash
printf '#!/bin/sh\nsystemctl reload network-relay\n' > /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

```bash
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

(Optional: the relay rereads the certificate by itself every day at 3 a.m.)

### Step 11: Self-check

```bash
network-relay check --server relay.example.com --user iphone
```

At the `Password:` prompt, enter the password from step 7 (**it is not shown**) and press Enter.

**You should see:** all seven lines with `✓`, ending in `All checks passed.`

- Only the two `HTTP/3` lines show `✗`: UDP 443 is not open.
- `answered like a plain website`: the user name or password is wrong, or the configuration was changed without a reload.

Then open `https://relay.example.com` in a browser; you should see the web page from step 6.

### Step 12: Generate a profile

**The first time, relay only the single website `ifconfig.me`**; the rest of your browsing is completely unaffected, which is the safest way to test:

```bash
network-relay profile --host relay.example.com --user iphone --match-domain ifconfig.me --out /root/iphone.mobileconfig
```

At the `Password:` prompt, enter the password. Then install it on the device as described in [the next section](#installing-the-profile-on-iphone-ipad-and-mac).

---

## Installing the profile on iPhone, iPad and Mac

### Step 1: Get the file from the server to the Mac

In the **Mac**'s Terminal, run (the one-step install puts the file at `/etc/network-relay/device.mobileconfig`; a manual install puts it where you pointed `--out`):

```bash
scp -i ~/.ssh/your-key root@203.0.113.10:/etc/network-relay/device.mobileconfig ~/Downloads/
```

**On servers where you log in as an ordinary user** (`admin` on Lightsail, `ubuntu` and so on), root's files cannot be downloaded directly and you get `Permission denied`. First, on the server (as root), copy it for that user:

```bash
install -m 600 -o admin -g admin /etc/network-relay/device.mobileconfig /home/admin/
```

Then on the Mac:

```bash
scp -i ~/.ssh/your-key admin@203.0.113.10:/home/admin/device.mobileconfig ~/Downloads/
```

Once downloaded, go back to the server and delete that copy: `rm /home/admin/device.mobileconfig`.

### Step 2: Turn off other proxies before testing

Disconnect **Stash, Clash, Shadowrocket, Surge** and similar on the device first (Settings → VPN shows "Not Connected").

### Step 3: Install

**iPhone / iPad:**

1. In Finder on the Mac, right-click the profile → Share → **AirDrop** it to the iPhone. (You can also put it on the website with `--publish` and open it in Safari; see [docs/config.md](docs/config.md#network-relay-profile).)
2. The iPhone says "Profile Downloaded"; tap "Close".
3. Open **Settings**; **Profile Downloaded** appears near the top → **Install** at the top right → enter the passcode → **Install**.
   If you don't see it: Settings → General → VPN & Device Management → "Downloaded Profile" below.

**Mac (macOS 14 or later):**

1. Double-click the profile.
2. Open **System Settings → General → Device Management** (called "Profiles" in older versions; you can also search for "Profiles" in the System Settings search field), double-click the profile you just added, click **Install**, and enter the Mac login password.

**Delete the downloaded file on the Mac right after installing** (and empty the Trash).

### Step 4: Verify

1. Open the live log on the server:
   ```bash
   journalctl -u network-relay -f -o cat
   ```
2. On the device, open https://ifconfig.me in Safari (if it is in your match list).

**You should see:**

- The web page shows **the server's IP**.
- The server log shows `client connected user="iphone" ... transport="HTTP/3"` (`HTTP/2` when it uses HTTP/2).
- Websites not in the match list still show your own IP.

Press `Ctrl+C` to leave the log (pressing Ctrl+C here is fine; it only stops viewing).

### Step 5: Switch to the scope you really want

**With the same user name and domain, a new profile replaces the old one**; no need to remove it first.

- Named domains through the relay, everything else direct (one `--match-domain` per domain; subdomains are included automatically):
  ```bash
  network-relay profile --host relay.example.com --user iphone --match-domain google.com --match-domain youtube.com --out /root/iphone.mobileconfig
  ```
- All traffic through the relay: give no `--match-domain` at all.
- All through the relay, but some domains direct: add `--exclude-domain DOMAIN`.
- Do not allow turning the relay off in Settings (iOS/macOS 26+): add `--ui-toggle-enabled false`. **Read the consequences of this one under [Common pitfalls](#on-the-device) first.**

For all options, see [docs/config.md](docs/config.md#network-relay-profile).

---

## A profile for named services plus gfwlist

`deploy/global-profile.py` combines the following three parts into one profile:

- `deploy/domains/google-ai-social.txt`: Google, Gemini, YouTube, Claude, ChatGPT, X and others;
- `deploy/domains/global-services.txt`: Meta AI, Instagram, Spotify, Pandora, The New York Times, Wikipedia, YouTube Music and others;
- the domains in the [gfwlist](https://github.com/gfwlist/gfwlist) (downloaded when it runs, not stored in the repository).

Run it **in the source directory on the server** (the one-step install's password exists only in `device.mobileconfig`, so read it from there into a variable first, without printing it):

```bash
P=$(python3 -c "import plistlib,base64;r=plistlib.load(open('/etc/network-relay/device.mobileconfig','rb'))['PayloadContent'][0]['Relays'][0];print(base64.b64decode(r['AdditionalHTTPHeaderFields']['Authorization'].split()[1]).decode().split(':',1)[1])")
```

```bash
python3 deploy/global-profile.py --host relay.example.com --user iphone --password "$P" --out /etc/network-relay/global.mobileconfig; unset P
```

For a manual install, just run this and enter the password when prompted:

```bash
python3 deploy/global-profile.py --host relay.example.com --user iphone --out /root/global.mobileconfig
```

When it finishes, it prints how many domains are matched and how many gfwlist rules were dropped or widened. Then install it on the device as described in [the previous section](#installing-the-profile-on-iphone-ipad-and-mac).

**Notes:**

- The default is `--ui-toggle-enabled false` (cannot be turned off in Settings). To allow turning it off, add `--ui-toggle-enabled true`.
- Regular expressions, IP addresses and exception rules in the gfwlist cannot be expressed in Apple's profile and are dropped; a rule aimed at a particular URL path sends its whole domain through the relay.
- This is a snapshot. When the gfwlist is updated, run it again and reinstall.
- The country your relay server is in decides where your traffic exits: for US-only services (Pandora and others), the server must be in the US.
- For details, see [deploy/domains/README.md](deploy/domains/README.md).

---

## Changing the password

The server and the profile **must be changed together**, or the device cannot connect.

### Step 1: On the server

```bash
network-relay passwd --name iphone
```

**Look at the printed password only in your own terminal**; do not copy it to anyone. Copy the `password_hash = "..."` line.

```bash
nano /etc/network-relay/relay.toml
```

Find the existing section:

```toml
[[user]]
name = "iphone"
password_hash = "$argon2id$..."
```

**Replace only the `password_hash` line with the new one. Do not append another `[[user]]` section**; two sections with the same name give `user iphone appears twice`. Save and exit.

```bash
network-relay serve --check
```

```bash
systemctl reload network-relay
```

**Run them one line at a time.** After the reload, the old password stops working immediately, and connections using it are dropped.

### Step 2: Confirm the new password works

```bash
network-relay check --server relay.example.com --user iphone
```

Enter the new password (not shown); everything should show `✓`.

### Step 3: The profile (pick one)

**Method A (recommended): generate it again**

```bash
network-relay profile --host relay.example.com --user iphone --match-domain your-domains... --out /root/iphone.mobileconfig
```

Or run `deploy/global-profile.py` again. Enter the new password when prompted.

**Method B: edit the file you already have**

The password in the profile is not in plain text; it is the Base64 encoding of `username:password`. In the **Mac** Terminal (macOS uses zsh by default):

```zsh
F=~/Downloads/device.mobileconfig
```

```zsh
read -s "P?New password: "; B=$(printf 'iphone:%s' "$P" | base64); sed -i '' -E "s|Basic [A-Za-z0-9+/=]+|Basic $B|" "$F"; unset P B
```

Enter the new password (not shown) and press Enter. Check that it was changed correctly (it shows `iphone:new-password`; **look at it only on your own screen**):

```zsh
grep -o 'Basic [^<]*' "$F" | cut -d' ' -f2 | base64 -d; echo
```

You can also edit it by hand in a text editor: find `<string>Basic xxxxx</string>`, and replace the **whole string** after `Basic ` and before `</string>` (including any trailing `=`) with the output of `printf 'iphone:NEW-PASSWORD' | base64`.

### Step 4: Reinstall the profile and delete the file

Same as [installing on the device](#installing-the-profile-on-iphone-ipad-and-mac). With the same user name and domain, it replaces the old one.

---

## Day-to-day operations

| Task | How |
|---|---|
| Add a device | `network-relay passwd --name NEW-NAME` → **append** the `[[user]]` section to `/etc/network-relay/relay.toml` (a different name can be appended) → `network-relay serve --check` → `systemctl reload network-relay` → generate a profile for the device |
| Disable a device | Delete its `[[user]]` section from the configuration → `serve --check` → `systemctl reload network-relay`. Its open connections are dropped immediately |
| Change which domains go through the relay | Generate a new profile with the same `--host` and `--user` and install it; it replaces the old one |
| Remove the relay from a device | iPhone: Settings → General → VPN & Device Management → tap the profile → Remove. Mac: System Settings → General → Device Management |
| Read the logs | `journalctl -u network-relay -n 50 --no-pager -o cat`; add `-f` to follow live |
| See the details of requests from devices | Add a `[debug]` section with `log_requests = true` to the configuration → reload. Each request is logged on one line (passwords hidden). Set it back to `false` when done |
| Changed the configuration | `network-relay serve --check` → `systemctl reload network-relay`. `listen`, `max_tunnels`, `log_dir` and `[tls]` need `systemctl restart network-relay` |
| Upgrade the program (one-step install) | Download the new source ZIP, extract it, enter the directory, and run `bash deploy/install-debian13.sh` again (no options needed; it keeps the original domain, user and password) |
| Upgrade the program (manual install) | Get the new `network-relay` file → `install -m 755 network-relay /usr/local/bin/` → `systemctl restart network-relay` |
| Certificates | certbot renews automatically, and the relay rereads them every day at 3 a.m.; with the renewal hook installed, it rereads them immediately |
| Check the service is running | `systemctl is-active network-relay` should print `active` |

When each device disconnects, the log has a summary line: how long it was connected, how many TCP connections and UDP flows were relayed, how many were refused, and the upload and download traffic.

---

## Troubleshooting

**The first step is always:**

```bash
network-relay check --server relay.example.com --user iphone
```

```bash
journalctl -u network-relay -n 50 --no-pager -o cat
```

### During installation

| Symptom / error | Cause and fix |
|---|---|
| `Could not get lock /var/lib/dpkg/lock-frontend ... (unattended-upgr)` | The system is running automatic updates. Newer versions of the script wait by themselves; with an older version, wait a few minutes and run it again. **Do not delete the lock or kill the process** |
| `Killed` / `signal: 9, SIGKILL` / the machine freezes | Not enough memory; [add swap](#less-than-2-gib-of-memory-add-swap-first) and run it again |
| `No space left on device` | The disk is full. At least 3 GiB must be free |
| `The relay domain does not resolve` | DNS is not set or has not propagated yet. Wait a few minutes and confirm with `getent hosts DOMAIN` on the server |
| `Port 443 is already in use by another service` / `Port 80 is already in use by another service` | Another program (usually nginx, apache or caddy) holds it. The script will not stop it for you |
| `Timeout during connect (likely firewall problem)` (certbot) | TCP 80 is not allowed; check the cloud firewall and the server's firewall |
| `too many certificates already issued` | Let's Encrypt's rate limit: at most 5 certificates per week for the same set of domains. The one-step install reuses an existing certificate; this usually comes from repeatedly deleting `/etc/letsencrypt` and reinstalling. Wait a week, or use another subdomain |
| `supports only Debian 12/13 x86_64` | Wrong OS version or CPU architecture; use the [manual install](#option-2-manual-install). If you are on Debian 12 and the message mentions only Debian 13, the source is an old version; download the `main` ZIP again |
| `Found an existing manual installation; refusing to overwrite it` | This machine had a manual install before. Follow [docs/deploy-debian13.md](docs/deploy-debian13.md#updating-and-re-running) |
| `The existing installation has a different domain, port or user name` / `The profile's password differs from the existing installation's` | The script refuses to overwrite an existing account, to prevent mistakes. Make sure the options match the first installation |
| `Local HTTPS startup check failed; restoring the previous installation` | The service did not come up and has been rolled back automatically. See `journalctl -u network-relay -n 50 --no-pager -o cat` |
| `The service is running, but the network self-check had failures` | The service runs, but the self-check could not reach the internet. Usually this machine cannot reach `example.com` or `1.1.1.1`, or outgoing UDP is blocked |

### While running

| Symptom | Cause and fix |
|---|---|
| `check` shows `✗` only on the two HTTP/3 lines | UDP 443 is not allowed (cloud firewall or server firewall). Devices switch to HTTP/2, which also works |
| `check` fails everywhere, with `QUIC handshake` / `TCP connect` timeouts | The relay is not running (`systemctl is-active network-relay`), or the ports are not open |
| `check` says `answered like a plain website` | Wrong user name or password; configuration changed without a reload; the user is not in the configuration |
| `certificate not valid for name` | The name given to `--server` differs from the one on the certificate |
| `user iphone appears twice` | The configuration has two `[[user]]` sections with the same name; delete the old one |
| Log shows `authentication failed user="iphone"` | The password in the device's profile differs from the server's. Generate a new profile and install it |
| Log shows `not reloading, configuration is invalid` | The configuration file has an error and the reload did not take effect (the old configuration is still in use). Run `network-relay serve --check` to see what is wrong |
| Web pages on the device show your own IP, and the server log shows nothing | ① Another VPN/proxy app is still on; ② the relay switch in Settings is off; ③ the profile is not the latest one; ④ the website is not in the match list; ⑤ turn on `log_requests` and try again to see whether the device connects at all |
| Log shows `client connected`, but web pages do not open | Turn on `log_requests` and look at the `refused` lines: `address blocked` means the target is on the blocklist; `DNS lookup failed` means the server cannot resolve that domain |
| Opening the relay domain in a browser does not show your website | Cloudflare's orange cloud is on, or the domain does not point at this server |
| Opening the `--publish` link in Safari shows a web page or 404 | `systemctl reload network-relay` was not run after generating it, or the file has already been deleted |
| The profile is reported as invalid when installing | The file was damaged by an editor (rich text, wrong extension); generate it again |
| Abroad, none of the matching websites open | The local network blocks the relay's domain or IP. Turn off the relay switch in Settings; if the profile was generated with `--ui-toggle-enabled false`, the only option is to remove the profile |

---

## Glossary

| Term | Meaning |
|---|---|
| Relay | The server that forwards traffic for devices; this project |
| Profile (.mobileconfig) | A configuration file for Apple devices; once installed, the system uses the relay automatically |
| VPS | A virtual server rented from a cloud provider |
| DNS / A record | The setting that points a domain at an IP address |
| Cloud firewall / security group | The setting in the cloud provider's console that controls which ports can be reached from outside |
| TCP / UDP 443 | Two protocols on the same port number; **each must be allowed separately** |
| HTTP/3, QUIC | The newer HTTP that runs over UDP, the fastest; when it fails, devices fall back to HTTP/2 automatically |
| Certificate | The file that lets devices confirm the server's identity; this project uses free Let's Encrypt certificates, renewed automatically every 90 days |
| reload / restart | reload rereads the configuration without dropping connections; restart restarts the program and all devices reconnect |
| swap | Disk space used temporarily as memory; needed for compiling on machines with little memory |
| Base64 | An encoding, not encryption; the password in the profile is encoded with it and anyone can decode it |
| PR (Pull Request) | A request on GitHub to submit code changes; once merged, the changes are in the `main` branch |
| CI | GitHub automatically building and running the tests on every push; all green checks means it passed |

---

# Technical notes

The following are implementation details you do not need for everyday use. For more, see [docs/design.md](docs/design.md).

## How it works

"Network Relay" on Apple devices is a system feature introduced in iOS 17 and macOS 14. Once a profile is installed, the system no longer connects matching connections directly to the target, but instead:

- **TCP**: sends an HTTP `CONNECT` request to the relay (`:authority` is the target's `host:port`); the relay connects to the target and answers 200, and from then on the data on the request stream is the data of that TCP connection.
- **UDP** (including QUIC, i.e. HTTP/3 websites): sends a CONNECT-UDP request (RFC 9298) following the URI template `https://relay.qolita.com/.well-known/masque/udp/{target_host}/{target_port}/`, and UDP packets travel as HTTP datagrams (QUIC DATAGRAM frames on HTTP/3).
- Domain names are resolved by the **relay**: the device sends the host name, and the server looks up DNS and connects to the target, so the DNS query does not go over the local network either.
- Every request carries the `Authorization: Basic ...` header from the profile, which the relay uses for authentication.

A device usually keeps just one HTTP/3 connection to the relay, carrying many request streams at the same time; each stream is one relayed TCP connection or UDP flow.

## What is implemented

| Feature | Description |
|---|---|
| Three HTTP versions | HTTP/3 (QUIC, UDP 443), HTTP/2 and HTTP/1.1 (TLS, TCP 443), all served on the same port at once |
| TCP relay | Classic CONNECT (RFC 9110 §9.3.6, RFC 9113 §8.5, RFC 9114 §4.4). Half-close (FIN) is passed on in both directions; when either side fails, both are reset (H3_CONNECT_ERROR on HTTP/3, TCP RST on the target side). Targets are connected with Happy Eyeballs (RFC 8305) |
| UDP relay | CONNECT-UDP (RFC 9298), with a configurable URI template. QUIC datagrams on HTTP/3, DATAGRAM capsules (RFC 9297) on HTTP/2 and HTTP/1.1. Unknown context IDs and capsules are dropped/skipped as specified. Datagrams the device sends right after the request, before receiving the response, are held rather than dropped |
| Authentication | HTTP Basic (RFC 7617), accepted in either `Authorization` or `Proxy-Authorization`. The server stores only Argon2id hashes (RFC 9106). Verification results are cached for 10 minutes (the cache key is an HMAC of the request header; passwords are not stored), so a device's stream of requests costs only one hash |
| Decoy website | Requests without the correct password (including every CONNECT) get the website's answer, the same as visiting a page that does not exist. Missing files under `/.well-known/` get 404 (Apple devices may query `/.well-known/pvd`) |
| Destination restrictions | By default the server itself, private networks, link-local, multicast and similar addresses cannot be reached; **every** address a domain resolves to is checked (against DNS rebinding). Port 25 is blocked by default (against spam). Configurable |
| Error information | When an authenticated request fails, a `Proxy-Status` header per RFC 9209 states the reason (DNS failure, connection refused, timeout, address prohibited and so on) |
| Live management | `systemctl reload` rereads users, destination rules, timeouts, the website and certificates; connections of users who were deleted or whose password changed are dropped immediately |
| Profile generation | `network-relay profile`: generates a `com.apple.relay.managed` profile, which can be put straight on the website and installed by opening it in Safari |
| Self-check | `network-relay check`: tests TCP and UDP relaying over all three HTTP versions the way a device would, and confirms that without a password the relay is indistinguishable from a website |
| Resource limits | Limit on concurrently relayed connections; UDP flows close after 5 minutes idle; under systemd only the permission to bind port 443 is kept |

## Limitations

- **Not tested on real devices** (see the top).
- According to Apple, the relay applies to connections made through the system networking frameworks (URLSession, Network.framework); programs with their own network stack or that use low-level sockets directly may bypass it. It is not a VPN: ICMP (ping) and the like do not go through the relay.
- TCP supports only classic CONNECT. The draft [draft-ietf-httpbis-connect-tcp](https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/) (`:protocol = connect-tcp`) is not implemented yet; Apple's documentation currently says the CONNECT method is used.
- Only user name and password. Authentication with a client certificate in the profile (`PayloadCertificateUUID`) is not implemented.
- The server runs only on Linux (`check` and `profile` also build and run on a Mac).

## Standards followed

| Specification | Content |
|---|---|
| RFC 9298 Proxying UDP in HTTP | CONNECT-UDP: request format on all three HTTP versions, URI templates, datagram format |
| RFC 9297 HTTP Datagrams and the Capsule Protocol | HTTP datagrams, capsules, the `Capsule-Protocol` header |
| RFC 9110 §9.3.6, RFC 9113 §8.5, RFC 9114 §4.4 | CONNECT and error handling on the three HTTP versions |
| RFC 8441, RFC 9220 | Extended CONNECT on HTTP/2 and HTTP/3 |
| RFC 9209 | `Proxy-Status` error information |
| RFC 8305 | Happy Eyeballs for connecting to targets |
| RFC 6570 | URI templates (the subset RFC 9298 allows) |
| RFC 7617, RFC 9106 | Basic authentication, Argon2 password hashing |
| RFC 8615 | `/.well-known/` paths |
| RFC 4787 | UDP flow idle timeout of at least 2 minutes |

## Documentation

| Document | Content |
|---|---|
| [docs/deploy.md](docs/deploy.md) | Deployment notes: building from source, self-check from a Mac, DNS validation for certificates, firewalls |
| [docs/config.md](docs/config.md) | Every configuration key, and the options of each `network-relay` command |
| [docs/design.md](docs/design.md) | Design: findings about Apple's network relay with sources, protocol details, security considerations, code structure |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Tests

```bash
cargo test
```

- **Unit tests**: URI templates, capsule and datagram formats, target parsing and blocklists, authentication and caching, profile format, the website, logging and more.
- **In-process integration tests** (`tests/in_process.rs`): a real relay and client in one process, over real TLS, QUIC and TCP on the loopback interface, relaying to local TCP and UDP services. They cover TCP and UDP on all three HTTP versions, bulk data and half-close, seeing the website with a wrong password, blocklists and port restrictions, Proxy-Status when the target is unreachable, dropping connections after a user is deleted, the connection limit, and early datagrams.
- **Interoperability tests** (manual): curl with CONNECT over HTTP/1.1 and HTTP/2; quic-go's [masque-go](https://github.com/quic-go/masque-go) client sending and receiving 1200- and 1300-byte datagrams with CONNECT-UDP over HTTP/3; `network-relay check` querying 1.1.1.1 over the real internet. For the steps, see [docs/design.md](docs/design.md#7-interoperability-tests).

GitHub Actions runs the format check, clippy and all tests on every push to `main`, and runs them again on arm64 (qemu); when a release is published, the x86_64 and arm64 packages are attached automatically.
