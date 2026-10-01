# Network Relay

给 iPhone、iPad、Mac **系统自带的“网络中继”（Network Relay）** 用的服务端。

- **设备上不用装任何 App**：装一个描述文件（`.mobileconfig`），系统自己把流量经你的服务器转发。
- 可以按**域名及子域名**或**精确主机名**选择和排除流量，也可以让**全部流量**走中继。精确匹配需要 iOS 18.4 / macOS 15.4 或更新。
- 协议是苹果规定的标准协议：TCP 用 HTTP CONNECT，UDP 用 CONNECT-UDP（RFC 9298），跑在 HTTP/3（QUIC）、HTTP/2、HTTP/1.1 上。
- 用户名密码认证。没有密码的人访问你的域名，看到的只是一个普通网站。
- 需要 iOS / iPadOS 17、macOS 14 或更新的系统。

> **当前状态**：服务端已经用 curl、quic-go 的 masque-go 客户端和自带的自检工具在三种 HTTP 版本上测通，并有自动化测试。**还没有在真实的 iPhone、Mac 上系统地验证过。** 遇到问题先看[常见的坑](#常见的坑一定要看)和[出了问题怎么办](#出了问题怎么办)。

这个项目和 [masque-vpn](https://github.com/ArcCal/masque-vpn) 是两个独立的项目：masque-vpn 是 CONNECT-IP 全局 VPN，需要自己的客户端；这里用的是苹果系统自带的功能，不需要客户端。

## 目录

- [开始之前：必读](#开始之前必读)
- [常见的坑（一定要看）](#常见的坑一定要看)
- [方式一：Debian 12/13 一键安装（推荐）](#方式一debian-1213-一键安装推荐)
- [方式二：手动安装（其他系统、或想自己掌控每一步）](#方式二手动安装)
- [把描述文件装到 iPhone、iPad、Mac](#把描述文件装到-iphoneipadmac)
- [生成“指定服务 + gfwlist”的描述文件](#生成指定服务--gfwlist的描述文件)
- [改密码](#改密码)
- [日常操作](#日常操作)
- [出了问题怎么办](#出了问题怎么办)
- [名词解释](#名词解释)
- [技术说明](#技术说明)

---

## 开始之前：必读

1. **一次只复制一行命令，回车，看完输出再做下一行。**
   多行一起粘贴时，遇到要输入密码的命令，后面的行会被当成密码吞掉；或者前一条失败了，后一条照样执行，看起来什么都没发生。本文每个灰框只放一条命令，就是为了这个。
   标着 **“文件内容”** 的灰框不是命令，是要粘贴进编辑器 nano 里的。
2. **把例子换成你自己的：**

   | 例子 | 换成 |
   |---|---|
   | `relay.example.com` | 你的中继域名 |
   | `iphone` | 你给这台设备起的用户名（**每台设备一个**，方便单独停用） |
   | `203.0.113.10` | 你的服务器公网 IP |
   | `~/.ssh/你的私钥` | 你登录服务器用的 SSH 私钥 |

3. **输入密码时屏幕上什么都不显示**，这是正常的，输完按回车。
4. **密码和描述文件绝对不要发给任何人**，包括贴到聊天、工单、AI 对话里求助。描述文件里有明文可解码的密码。求助时贴日志可以，贴之前先看一眼里面有没有密码。
5. **看到 `Ctrl+C` 之前先想一想**：安装、编译、等待系统更新时，屏幕可能好几分钟没有新输出，这不是卡死。中途按 `Ctrl+C` 只会让你从头再来。

---

## 常见的坑（一定要看）

这些都是真实部署时踩过的。

### 服务器和网络

| 坑 | 后果 | 怎么避免 |
|---|---|---|
| **云防火墙没放行 UDP 443** | HTTP/3 不通，设备退回 HTTP/2，慢一些；`check` 只有 HTTP/3 两行失败 | 云服务商控制台里加 **UDP** 443。很多云默认只开 TCP。AWS Lightsail 在实例的“联网/Networking”页，IPv4 和 IPv6 两张表都要加；Vultr 看实例有没有绑“Firewall Group”；Oracle Cloud 要改安全列表 |
| **云防火墙没放行 TCP 80** | 申请证书失败（`Timeout during connect (likely firewall problem)`），以后证书也无法自动续期 | TCP 80 要**长期**开着，不是申请完就关 |
| 服务器自己的防火墙（ufw、nftables、iptables）挡了端口 | 同上 | 一键安装会在 ufw 开着时自动放行；自己写的 nftables/iptables 要手动放行 TCP 80、TCP 443、UDP 443。有些镜像（例如 Oracle Cloud 的 Ubuntu）自带 iptables 规则，只放行 22 |
| **Cloudflare 开着橙色云朵（代理）** | 中继完全不能用，浏览器打开域名看到的不是你的网站 | DNS 记录必须是**灰色云朵（仅 DNS）** |
| DNS 还没生效，或填错了 IP | 证书申请失败，设备连不上 | 在**服务器上**执行 `getent hosts relay.example.com`，看到的 IP 必须和 `curl -4 -s https://ifconfig.me` 一样 |
| 在 iPhone/Mac 上查 DNS | 开着 Clash、Stash、Surge 时会查到 `198.18.x.x` 的假地址，误以为 DNS 错了 | 只在服务器上查 |
| 服务器没有固定公网 IP | 重启后 IP 变了，DNS 指向旧 IP | 绑定“静态 IP / 弹性 IP / Reserved IP” |
| 443 端口已被 nginx、tuic、hysteria、xray 等占用 | 安装脚本报 `端口 443 已被其他服务占用`，**不会**替你停掉它。QUIC 类代理（tuic、hysteria）常占 **UDP** 443 | 中继需要独占 TCP 443 和 UDP 443。先 `ss -lntup \| grep ':443 '` 看是谁，换一台机器、换一个 IP，或停掉那个服务 |
| 通过 Tailscale（`100.x.x.x`）登录服务器 | DNS 填成了 `100.x` 的地址，外网连不上 | A 记录必须填**公网 IP**。在服务器上 `curl -4 -s https://ifconfig.me; echo` 查公网 IP |

### 安装过程

| 坑 | 后果 | 怎么避免 |
|---|---|---|
| **新开的 VPS 正在自动更新** | 老版本脚本报 `Could not get lock /var/lib/dpkg/lock-frontend ... (unattended-upgr)` | 新版本脚本会自己等，最多 30 分钟，期间看起来像卡住，**别按 Ctrl+C**。**绝对不要删 lock 文件、不要 kill 那个进程**，会把系统包管理搞坏 |
| 用 `fuser` 判断锁 | Debian 最小安装没有 `fuser`，判断永远“不占用” | 不需要自己判断，脚本会等 |
| **内存不够** | 编译时报 `Killed`、`signal: 9, SIGKILL`，或者整台机器卡死 | 编译需要约 2 GiB 内存。1 GiB 的机器先加 swap，见[加 swap](#内存小于-2-gib先加-swap) |
| 磁盘不够 | `No space left on device` | 至少留 3 GiB 空闲 |
| **下载了旧版本的源码** | 缺少新功能（例如 `deploy/global-profile.py`），或者还是旧的 bug | 在 GitHub 仓库页确认分支是 `main`，再 Code → Download ZIP |
| 下载的 ZIP 文件名带 `(1)` | `unzip network-relay-main(1).zip` 报语法错误 | 文件名加引号：`unzip 'network-relay-main(1).zip'` |
| 不在源码目录里运行 | `No such file or directory` | 先 `cd` 进解压出来的目录（里面能看到 `Cargo.toml`、`deploy`、`src`） |
| 用 `sh` 运行脚本 | 语法错误 | 用 `bash`：`bash deploy/install-debian13.sh ...` |
| 一键安装在 Debian 12/13 以外、或非 x86_64 的系统上运行 | `只支持 Debian 12/13 x86_64。`（旧版本脚本只认 Debian 13） | `cat /etc/os-release` 看版本；其他系统走[手动安装](#方式二手动安装) |
| 用 `admin`、`ubuntu` 这类普通用户登录 | 权限不够 | 先 `sudo -i` 变成 root，提示符结尾变成 `#` |

### 密码和描述文件

| 坑 | 后果 | 怎么避免 |
|---|---|---|
| **把终端输出复制给别人看** | `passwd` 打印的密码、`check` 时你输入的东西都可能在里面，密码泄露 | 贴之前检查；泄露了就[改密码](#改密码) |
| **改了服务器密码，没改描述文件**（或反过来） | 设备连不上，服务器日志 `authentication failed user="iphone"` | 两边永远一起改 |
| 往 `relay.toml` 里**追加**第二段同名 `[[user]]` | `user iphone appears twice`，配置不生效 | 改密码时**只替换** `password_hash` 那一行 |
| 改完配置没 `systemctl reload network-relay` | 新密码没生效，旧密码还能用 | 改完配置一律：`network-relay serve --check`，再 `systemctl reload network-relay` |
| 把 `serve --check` 和 `systemctl reload` 两行一起粘贴 | 第一条报错了，第二条照样执行，你以为成功了 | 一行一行执行 |
| 手动改描述文件时只换了 Base64 的一部分 | 认证失败 | `Basic ` 后面一直到 `</string>` 前面整串换掉，**包括结尾的 `=`** |
| 用 macOS 的“文本编辑”改描述文件 | 存成富文本，文件损坏 | 先选“格式 → 制作纯文本”，或用 VS Code 等编辑器 |
| 描述文件存成了 `.txt` | 设备不认 | 必须以 `.mobileconfig` 结尾 |
| 描述文件留在下载文件夹、网站目录里 | 别人拿到就能用你的中继 | 装好后立刻删除 |
| 用 `--publish` 放到网站上之后忘了删 | 任何猜到链接的人都能下载 | 装完立刻 `rm` 并 `systemctl reload network-relay` |

### 设备端

| 坑 | 后果 | 怎么避免 |
|---|---|---|
| **Clash、Stash、Shadowrocket、Surge 等开着** | 流量先被它们接走，看不出中继有没有生效 | 测试时先在“设置 → VPN”里断开 |
| **`MatchDomains` 为空** | 苹果的规则是：匹配列表为空等于**全部流量**走中继 | 只想代理部分网站，就一定要写 `--match-domain` |
| 只写了 `--match-fqdn`，设备是 iOS 18.4 以前的系统 | 旧系统不认这个键，可能变成全部流量走中继 | 旧设备用 `--match-domain` |
| `--ui-toggle-enabled false` | 设置里**不能**关掉中继。出国时中继被封，所有匹配的网站一起打不开，只能删描述文件 | 想留后路就用 `true`（这个开关需要 iOS/macOS 26+，旧系统忽略它） |
| 以为“全部走中继”就等于 VPN | 有些 App 自带网络库（部分 Google、Spotify、Instagram 等），可能不经过中继；ping 等 ICMP 也不经过 | 这是系统功能的限制，不是配置错误 |
| 用 Safari 以外的浏览器打开描述文件链接 | 不能安装 | iPhone 上用 Safari；或在 Mac 上下载后 AirDrop 给 iPhone |

---

## 方式一：Debian 12/13 一键安装（推荐）

**适用**：Debian 12 或 13、x86_64、systemd 的 VPS（Vultr、AWS Lightsail、Google Cloud、DigitalOcean 等的 Debian 镜像都是）。不确定版本就在服务器上运行 `cat /etc/os-release`，看 `VERSION_ID`。
**脚本会做**：装依赖 → 按 `Cargo.lock` 从源码编译 → 申请 Let's Encrypt 证书并设置自动续期 → 生成随机密码和用户 → 写配置、装 systemd 服务 → 启动并在本机自检 → 输出设备描述文件。失败时自动恢复安装前的文件。

### 第 1 步：准备域名和防火墙（在你的电脑上，网页操作）

1. DNS 加一条 **A 记录**：`relay.example.com` → 服务器公网 IPv4。Cloudflare 选**灰色云朵**。
2. 云防火墙放行：

   | 协议 | 端口 | 用途 |
   |---|---|---|
   | TCP | 22 | SSH 登录（一般已有，**别删**） |
   | TCP | 80 | 申请和续期证书（**长期开着**） |
   | TCP | 443 | HTTP/2、HTTP/1.1 中继和伪装网站 |
   | **UDP** | **443** | HTTP/3 中继（**很多云默认没有，一定要加**） |

   服务器有 IPv6 的话，IPv6 的防火墙也加一样的规则。

### 第 2 步：下载源码并上传

1. 浏览器登录 GitHub（仓库是私有的，不登录看不到），打开仓库页，确认左上角分支是 **`main`**，点 **Code → Download ZIP**。
2. 在 Mac 的终端里上传（文件名以你实际下载到的为准）：
   ```bash
   scp -i ~/.ssh/你的私钥 ~/Downloads/network-relay-main.zip root@203.0.113.10:/root/
   ```
   用普通用户登录的云（如 Lightsail 的 `admin`、Ubuntu 的 `ubuntu`）就把 `root@` 换成那个用户，路径换成 `/home/admin/` 之类。

### 第 3 步：登录服务器

```bash
ssh -i ~/.ssh/你的私钥 root@203.0.113.10
```

不是 root 登录的，接着执行：

```bash
sudo -i
```

提示符结尾是 `#` 就对了。**后面服务器上的命令都在 root 下执行。**

### 第 4 步：确认域名指向这台服务器

```bash
getent hosts relay.example.com
```

```bash
curl -4 -s https://ifconfig.me; echo
```

两个 IP 必须一样。不一样就先回去改 DNS，等几分钟再试，**不要往下走**。

### 第 5 步：解压并进入目录

```bash
cd /root
```

```bash
apt-get -o DPkg::Lock::Timeout=1800 install -y unzip
```

新机器正在自动更新时，这条会先等它完成（最多 30 分钟），看起来像卡住，别按 Ctrl+C。

```bash
unzip 'network-relay-main.zip'
```

文件名里有 `(1)` 之类的，照样整个放在单引号里。

```bash
cd network-relay-main
```

```bash
ls
```

应该看到 `Cargo.toml  deploy  docs  src ...`。

### 第 6 步：运行安装脚本

```bash
bash deploy/install-debian13.sh --domain relay.example.com
```

- 默认用户名是 `iphone`；想用别的加 `--user 名字`。
- 想收证书到期提醒邮件加 `--email 你的邮箱`。
- 内存 4 GiB 以上的机器可以加 `--jobs 2` 编译快一些。
- 整个过程 **5 到 20 分钟**，大部分时间在编译。新开的机器如果正在自动更新，脚本会先等它。**期间不要按 Ctrl+C。**

**成功时最后会看到：**

```
安装完成。设备描述文件：/etc/network-relay/device.mobileconfig（含密码，权限 600，不会公开到网站）。
开始从本机检查三种 HTTP 版本的 TCP/UDP 中继；公网入口仍需从设备验证。
✓ HTTP/3 TCP (CONNECT) ...
...
All checks passed.
```

- 密码是随机生成的 32 个字符，**不会打印**，只写在这个描述文件里。
- 默认生成的描述文件只代理 Google / Gemini / YouTube / Claude / ChatGPT / X 等服务（列表见 `deploy/domains/google-ai-social.txt`），其他网站直连。想要更大的范围，看[生成“指定服务 + gfwlist”的描述文件](#生成指定服务--gfwlist的描述文件)。
- 本机自检通过，**不代表**外网能连上（云防火墙挡的是外面进来的流量）。最终以设备为准。

**重复运行是安全的**：同一台机器再运行一次（例如更新到新版本源码），会保留密码、用户和你手工改过的配置，只更新程序。

### 内存小于 2 GiB：先加 swap

```bash
free -h
```

`Mem` 一行的 `total` 小于 2G 时，依次执行：

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

然后再运行安装脚本。

### 已经有别人交付的描述文件

把那个 `.mobileconfig` 上传到服务器，安装时导入它，服务器就会用里面同一组凭据，不用重新给设备装：

```bash
bash deploy/install-debian13.sh --profile /root/relay.example.com-iphone.mobileconfig
```

更多说明见 [docs/deploy-debian13.md](docs/deploy-debian13.md)。

---

## 方式二：手动安装

适合 Debian 12、Ubuntu 22.04 及更新的系统，或想自己掌控每一步。需要一台有公网 IP 的 Linux 服务器和一个域名。命令以 Debian 为例，Ubuntu 一样。

### 第 1 步：防火墙和域名

同[一键安装的第 1 步](#第-1-步准备域名和防火墙在你的电脑上网页操作)。

### 第 2 步：登录服务器，变成 root

```bash
sudo -i
```

没装 sudo 的 Debian 用 `su -`。

### 第 3 步：安装软件，确认域名

```bash
apt-get -o DPkg::Lock::Timeout=1800 update
```

```bash
apt-get -o DPkg::Lock::Timeout=1800 install -y certbot curl
```

新机器正在自动更新时会先等它完成，看起来像卡住，别按 Ctrl+C。

```bash
getent hosts relay.example.com
```

```bash
curl -4 -s https://ifconfig.me; echo
```

**两个 IP 必须一样。**

### 第 4 步：申请证书

```bash
certbot certonly --standalone -d relay.example.com
```

第一次会问邮箱（填你的）、是否同意条款（`Y`）、是否分享邮箱（`N`）。

**应该看到：** `Successfully received certificate.`

- `Timeout during connect (likely firewall problem)`：TCP 80 没开，回第 1 步。
- `Address already in use`：80 端口被 nginx 之类占着。先停掉它，或用 DNS 验证，见 [docs/deploy.md](docs/deploy.md#80-端口用不了用-dns-验证)。

### 第 5 步：安装程序

两种来源选一种：

- **发布版**：在 GitHub 的 Releases 页面下载 `network-relay-版本-linux-x86_64.tar.gz`（ARM 服务器下 `arm64`；不确定就在服务器上运行 `uname -m`，`aarch64` 就是 arm64），上传后：
  ```bash
  tar -xzf network-relay-*-linux-x86_64.tar.gz
  ```
  ```bash
  cd network-relay-*-linux-x86_64
  ```
  ```bash
  install -m 755 network-relay /usr/local/bin/
  ```
- **自己编译**：见 [docs/deploy.md](docs/deploy.md#从源码编译)。

```bash
network-relay --version
```

**应该看到** `network-relay 0.1.0`（或更新的版本号）。**不要离开这个目录**，后面还要用里面的 `deploy/` 文件。

### 第 6 步：放一个伪装网站

```bash
mkdir -p /var/www/relay
```

```bash
echo '<!doctype html><title>Welcome</title><h1>Welcome</h1>' > /var/www/relay/index.html
```

### 第 7 步：建用户

```bash
network-relay passwd --name iphone
```

会打印三段：

```
# 1. Add these lines to the end of /etc/network-relay/relay.toml, then: sudo systemctl reload network-relay
[[user]]
name = "iphone"
password_hash = "$argon2id$v=19$..."

# 2. The password (shown only now; the server keeps only the hash):
Xy3...（一串 24 个字符的密码）

# 3. Make the profile for the device: ...
```

- 第 1 段要贴进下一步的配置文件。**`password_hash` 那一行要完整复制**，很长，别漏掉结尾。
- 第 2 段是密码，**只显示这一次**，记到密码管理器里。**不要截图发给别人。**

### 第 8 步：写配置

```bash
mkdir -p /etc/network-relay
```

```bash
nano /etc/network-relay/relay.toml
```

**文件内容**（`relay.example.com` 换成你的域名，最后三行换成上一步打印的第 1 段）：

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

按 `Ctrl+O`、回车保存，`Ctrl+X` 退出。

```bash
chmod 600 /etc/network-relay/relay.toml
```

```bash
network-relay serve --check
```

**应该看到：** `... configuration, certificate and website are fine; users: 1`

报错会指出哪一行哪一项。最常见：域名没换、`password_hash` 没复制全、引号是中文引号。其他可设置的项见 [docs/config.md](docs/config.md)。

### 第 9 步：加大 UDP 缓冲区

```bash
cp deploy/99-network-relay.conf /etc/sysctl.d/
```

```bash
sysctl --system
```

有些 VPS 不允许改这两个参数，报错可以忽略，只是 HTTP/3 高速时可能丢包。

### 第 10 步：启动

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

**应该看到：**

```
INFO TLS certificate: relay.example.com, valid until ...
INFO network-relay 0.1.0 ready (HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP) ...
```

- 以后开机自动启动，崩溃自动重启。
- 看日志一律用上面这条 `journalctl`；`systemctl status` 会把长的行截断。

证书续期后让中继立刻读到新证书：

```bash
printf '#!/bin/sh\nsystemctl reload network-relay\n' > /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

```bash
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

（不设也行，中继每天凌晨 3 点会自己重新读取证书。）

### 第 11 步：自检

```bash
network-relay check --server relay.example.com --user iphone
```

提示 `Password:` 时输入第 7 步的密码（**不显示**），回车。

**应该看到：** 七行都是 `✓`，最后 `All checks passed.`

- 只有 `HTTP/3` 两行 `✗`：UDP 443 没放行。
- `answered like a plain website`：用户名或密码不对，或改了配置没 reload。

再用浏览器打开 `https://relay.example.com`，应该看到第 6 步的网页。

### 第 12 步：生成描述文件

**第一次先只让 `ifconfig.me` 一个网站走中继**，其他上网完全不受影响，测试最安全：

```bash
network-relay profile --host relay.example.com --user iphone --match-domain ifconfig.me --out /root/iphone.mobileconfig
```

提示 `Password:` 时输入密码。然后按[下一节](#把描述文件装到-iphoneipadmac)装到设备上。

---

## 把描述文件装到 iPhone、iPad、Mac

### 第 1 步：把文件从服务器拿到 Mac

在 **Mac** 的终端里执行（一键安装的文件在 `/etc/network-relay/device.mobileconfig`，手动安装的在你 `--out` 指定的位置）：

```bash
scp -i ~/.ssh/你的私钥 root@203.0.113.10:/etc/network-relay/device.mobileconfig ~/Downloads/
```

**用普通用户登录的服务器**（Lightsail 的 `admin`、`ubuntu` 等）不能直接下载 root 的文件，会报 `Permission denied`。先在服务器上（root 下）复制一份给那个用户：

```bash
install -m 600 -o admin -g admin /etc/network-relay/device.mobileconfig /home/admin/
```

再在 Mac 上：

```bash
scp -i ~/.ssh/你的私钥 admin@203.0.113.10:/home/admin/device.mobileconfig ~/Downloads/
```

下载完回服务器删掉这份副本：`rm /home/admin/device.mobileconfig`。

### 第 2 步：测试前关掉别的代理

设备上的 **Stash、Clash、Shadowrocket、Surge** 之类先断开（设置 → VPN 里显示“未连接”）。

### 第 3 步：安装

**iPhone / iPad：**

1. 在 Mac 的访达里右键描述文件 → 共享 → **隔空投送**给 iPhone。（也可以用 `--publish` 放到网站上用 Safari 打开，见 [docs/config.md](docs/config.md#network-relay-profile)。）
2. iPhone 上提示“已下载描述文件”，点“关闭”。
3. 打开**设置**，最上面会出现**已下载描述文件** → 右上角**安装** → 输入锁屏密码 → **安装**。
   没看到的话：设置 → 通用 → VPN 与设备管理 → 下面的“已下载描述文件”。

**Mac（macOS 14 或更新）：**

1. 双击描述文件。
2. 打开**系统设置 → 通用 → 设备管理**（旧版本叫“描述文件”，也可以在系统设置的搜索框里搜“描述文件”），双击刚才的描述文件，点**安装**，输入 Mac 登录密码。

**装好后立刻删掉 Mac 上下载的那份文件**（废纸篓也清空）。

### 第 4 步：验证

1. 服务器上打开实时日志：
   ```bash
   journalctl -u network-relay -f -o cat
   ```
2. 设备上用 Safari 打开 https://ifconfig.me（如果它在你的匹配列表里）。

**应该看到：**

- 网页上显示的是**服务器的 IP**。
- 服务器日志出现 `client connected user="iphone" ... transport="HTTP/3"`（走 HTTP/2 时是 `HTTP/2`）。
- 不在匹配列表里的网站，显示的还是你自己的 IP。

按 `Ctrl+C` 退出日志（这里按 Ctrl+C 没关系，只是退出查看）。

### 第 5 步：改成你真正想要的范围

**用户名和域名不变时，新描述文件会替换旧的**，不用先删。

- 指定的域名走中继，其他直连（每个域名一个 `--match-domain`，子域名自动包含）：
  ```bash
  network-relay profile --host relay.example.com --user iphone --match-domain google.com --match-domain youtube.com --out /root/iphone.mobileconfig
  ```
- 全部流量走中继：不写任何 `--match-domain`。
- 全部走中继、但某些域名直连：加 `--exclude-domain 域名`。
- 不允许在设置里关掉中继（iOS/macOS 26+）：加 `--ui-toggle-enabled false`。**先看[常见的坑](#设备端)里这一条的后果。**

所有参数见 [docs/config.md](docs/config.md#network-relay-profile)。

---

## 生成“指定服务 + gfwlist”的描述文件

`deploy/global-profile.py` 会把下面三部分合起来，生成一个描述文件：

- `deploy/domains/google-ai-social.txt`：Google、Gemini、YouTube、Claude、ChatGPT、X 等；
- `deploy/domains/global-services.txt`：Meta AI、Instagram、Spotify、Pandora、纽约时报、维基百科、YouTube Music 等；
- [gfwlist](https://github.com/gfwlist/gfwlist) 里的域名（运行时下载，不存在仓库里）。

在**服务器上的源码目录里**执行（一键安装的密码只存在 `device.mobileconfig` 里，所以先从里面读出来，放进变量，不打印）：

```bash
P=$(python3 -c "import plistlib,base64;r=plistlib.load(open('/etc/network-relay/device.mobileconfig','rb'))['PayloadContent'][0]['Relays'][0];print(base64.b64decode(r['AdditionalHTTPHeaderFields']['Authorization'].split()[1]).decode().split(':',1)[1])")
```

```bash
python3 deploy/global-profile.py --host relay.example.com --user iphone --password "$P" --out /etc/network-relay/global.mobileconfig; unset P
```

手动安装的，直接运行下面这条，按提示输入密码：

```bash
python3 deploy/global-profile.py --host relay.example.com --user iphone --out /root/global.mobileconfig
```

结束时会打印匹配了多少个域名、gfwlist 里有多少条规则被丢弃或放宽。然后按[上一节](#把描述文件装到-iphoneipadmac)装到设备上。

**须知：**

- 默认 `--ui-toggle-enabled false`（设置里不能关）。想能关，加 `--ui-toggle-enabled true`。
- gfwlist 里的正则、IP 地址和例外规则苹果的描述文件表达不了，会被丢弃；只针对某个网址路径的规则会让整个域名走中继。
- 这是一份快照。gfwlist 更新后要重新运行并重新安装。
- 中继服务器所在的国家决定了出口：想用美国限定的服务（Pandora 等），服务器要在美国。
- 详细说明见 [deploy/domains/README.md](deploy/domains/README.md)。

---

## 改密码

服务器和描述文件**两边必须一起改**，否则设备连不上。

### 第 1 步：服务器端

```bash
network-relay passwd --name iphone
```

**只在自己的终端里看**打印出的密码，不要复制给任何人。复制 `password_hash = "..."` 那一行。

```bash
nano /etc/network-relay/relay.toml
```

找到已有的这一段：

```toml
[[user]]
name = "iphone"
password_hash = "$argon2id$..."
```

**只把 `password_hash` 那一行换成新的。不要再追加一段 `[[user]]`**，同名两段会报 `user iphone appears twice`。保存退出。

```bash
network-relay serve --check
```

```bash
systemctl reload network-relay
```

**一行一行执行。** reload 后旧密码立刻失效，用旧密码的连接会被断开。

### 第 2 步：确认新密码生效

```bash
network-relay check --server relay.example.com --user iphone
```

输入新密码（不显示），应该全部 `✓`。

### 第 3 步：描述文件（二选一）

**方法 A（推荐）：重新生成**

```bash
network-relay profile --host relay.example.com --user iphone --match-domain 你的域名... --out /root/iphone.mobileconfig
```

或者重新运行 `deploy/global-profile.py`。提示输入密码时输入新密码。

**方法 B：直接改你手上那份文件**

描述文件里的密码不是明文，是 `用户名:密码` 的 Base64 编码。在 **Mac** 终端里（macOS 默认 zsh）：

```zsh
F=~/Downloads/device.mobileconfig
```

```zsh
read -s "P?新密码: "; B=$(printf 'iphone:%s' "$P" | base64); sed -i '' -E "s|Basic [A-Za-z0-9+/=]+|Basic $B|" "$F"; unset P B
```

输入新密码（不显示），回车。检查改对了没有（会显示 `iphone:新密码`，**只在自己的屏幕上看**）：

```zsh
grep -o 'Basic [^<]*' "$F" | cut -d' ' -f2 | base64 -d; echo
```

想用文本编辑器手改也可以：找到 `<string>Basic xxxxx</string>`，把 `Basic ` 后面、`</string>` 前面**整串**（包括结尾的 `=`）换成 `printf 'iphone:新密码' | base64` 的输出。

### 第 4 步：重新安装描述文件，删掉文件

同[装到设备](#把描述文件装到-iphoneipadmac)。用户名和域名不变，会替换旧的。

---

## 日常操作

| 要做的事 | 怎么做 |
|---|---|
| 加一台设备 | `network-relay passwd --name 新名字` → 把 `[[user]]` 段**追加**到 `/etc/network-relay/relay.toml`（名字不同可以追加） → `network-relay serve --check` → `systemctl reload network-relay` → 给设备生成描述文件 |
| 停用一台设备 | 从配置里删掉它的 `[[user]]` 段 → `serve --check` → `systemctl reload network-relay`。它正在用的连接立刻断开 |
| 改走中继的域名 | 用同样的 `--host` 和 `--user` 重新生成描述文件并安装，会替换旧的 |
| 在设备上删除中继 | iPhone：设置 → 通用 → VPN 与设备管理 → 点描述文件 → 移除。Mac：系统设置 → 通用 → 设备管理 |
| 看日志 | `journalctl -u network-relay -n 50 --no-pager -o cat`；实时看加 `-f` |
| 看设备发来的请求细节 | 配置里加 `[debug]` 段写 `log_requests = true` → reload。每个请求记一行（密码隐去）。排查完改回 `false` |
| 改了配置 | `network-relay serve --check` → `systemctl reload network-relay`。`listen`、`max_tunnels`、`log_dir`、`[tls]` 要 `systemctl restart network-relay` |
| 升级程序（一键安装） | 下载新源码 ZIP，解压，进目录，再运行一次 `bash deploy/install-debian13.sh`（不用加参数，会沿用原来的域名、用户和密码） |
| 升级程序（手动安装） | 换新的 `network-relay` 文件 → `install -m 755 network-relay /usr/local/bin/` → `systemctl restart network-relay` |
| 证书 | certbot 自动续期，中继每天凌晨 3 点自动读取；装了续期 hook 的会立刻读取 |
| 查服务是否在运行 | `systemctl is-active network-relay`，应该显示 `active` |

每个设备断开时，日志里有一行汇总：连了多久、转发了多少 TCP 连接和 UDP 流、多少被拒绝、上下行流量。

---

## 出了问题怎么办

**第一步永远是：**

```bash
network-relay check --server relay.example.com --user iphone
```

```bash
journalctl -u network-relay -n 50 --no-pager -o cat
```

### 安装阶段

| 现象 / 报错 | 原因和处理 |
|---|---|
| `Could not get lock /var/lib/dpkg/lock-frontend ... (unattended-upgr)` | 系统正在自动更新。新版本脚本会自己等；旧版本等几分钟再运行。**不要删锁、不要 kill** |
| `Killed` / `signal: 9, SIGKILL` / 机器卡死 | 内存不够，[加 swap](#内存小于-2-gib先加-swap) 后重新运行 |
| `No space left on device` | 磁盘满了。至少要 3 GiB 空闲 |
| `中继域名无法解析` | DNS 没设或没生效。等几分钟，在服务器上 `getent hosts 域名` 确认 |
| `端口 443 已被其他服务占用` / `端口 80 已被其他服务占用` | 有别的程序（常见是 nginx、apache、caddy）占着。脚本不会替你停掉它 |
| `Timeout during connect (likely firewall problem)`（certbot） | TCP 80 没放行，检查云防火墙和服务器防火墙 |
| `too many certificates already issued` | Let's Encrypt 的频率限制：同一组域名一周最多签 5 张。一键安装会复用已有证书，通常是反复删掉 `/etc/letsencrypt` 重装触发的。等一周，或换一个子域名 |
| `只支持 Debian 12/13 x86_64。` | 系统版本或 CPU 架构不对，走[手动安装](#方式二手动安装)。如果是 Debian 12 却看到 `只支持 Debian 13`，说明源码是旧版本，重新下载 `main` 的 ZIP |
| `发现已有手工安装配置，拒绝覆盖` | 这台机器以前手动装过。按 [docs/deploy-debian13.md](docs/deploy-debian13.md#更新与重复执行) 处理 |
| `已有安装的域名、端口和用户名不同` / `密码与已有安装不同` | 脚本拒绝覆盖已有账号，防止误操作。确认参数和第一次安装一致 |
| `本机 HTTPS 启动检查失败，正在恢复原安装` | 服务没起来，已自动回滚。看 `journalctl -u network-relay -n 50 --no-pager -o cat` |
| `服务已运行，但联网自检有失败` | 服务在跑，但自检访问外网失败。通常是这台机器访问不了 `example.com` 或 `1.1.1.1`，或 UDP 出站被挡 |

### 运行阶段

| 现象 | 原因和处理 |
|---|---|
| `check` 只有 HTTP/3 两行 `✗` | UDP 443 没放行（云防火墙或服务器防火墙）。设备会改用 HTTP/2，也能用 |
| `check` 全部失败，`QUIC handshake` / `TCP connect` 超时 | 中继没在运行（`systemctl is-active network-relay`），或端口没放行 |
| `check` 提示 `answered like a plain website` | 用户名或密码不对；改了配置没 reload；用户不在配置里 |
| `certificate not valid for name` | `--server` 写的名字和证书上的不一样 |
| `user iphone appears twice` | 配置里有两段同名 `[[user]]`，删掉旧的那段 |
| 日志 `authentication failed user="iphone"` | 设备上描述文件的密码和服务器不一致。重新生成描述文件安装 |
| 日志 `not reloading, configuration is invalid` | 配置文件有错，reload 没生效（旧配置还在用）。`network-relay serve --check` 看具体哪里错 |
| 设备上网页显示自己的 IP，服务器日志什么都没有 | ① 其他 VPN/代理软件还开着；② 设置里中继开关没打开；③ 描述文件不是最新的；④ 这个网站不在匹配列表里；⑤ 打开 `log_requests` 再试，看设备有没有连过来 |
| 日志有 `client connected`，但网页打不开 | 打开 `log_requests` 看 `refused` 的行：`address blocked` 是目标在黑名单里；`DNS lookup failed` 是服务器解析不了这个域名 |
| 浏览器打开中继域名不是你的网站 | Cloudflare 橙色云朵开着，或域名没指到这台服务器 |
| Safari 打开 `--publish` 的链接显示网页或 404 | 生成后没 `systemctl reload network-relay`，或文件已经删了 |
| 装描述文件时提示无效 | 文件被编辑器改坏了（富文本、扩展名不对），重新生成 |
| 出国后所有匹配的网站都打不开 | 当地封了中继的域名或 IP。设置里关掉中继开关；如果生成时用了 `--ui-toggle-enabled false`，只能删除描述文件 |

---

## 名词解释

| 词 | 意思 |
|---|---|
| 中继（relay） | 帮设备转发流量的服务器，就是本项目 |
| 描述文件（.mobileconfig） | 苹果设备的配置文件，装上后系统自动用中继 |
| VPS | 云服务商租的虚拟服务器 |
| DNS / A 记录 | 把域名指向 IP 地址的设置 |
| 云防火墙 / 安全组 | 云服务商控制台里控制哪些端口能从外面访问的设置 |
| TCP / UDP 443 | 同一个端口号的两种协议，**需要分别放行** |
| HTTP/3、QUIC | 跑在 UDP 上的新版 HTTP，最快；不通时设备自动退回 HTTP/2 |
| 证书 | 让设备确认服务器身份的文件，本项目用 Let's Encrypt 免费证书，90 天自动续期 |
| reload / restart | reload 重新读取配置，不断开连接；restart 重启程序，所有设备重连 |
| swap | 用磁盘临时充当内存，内存小的机器编译时需要 |
| Base64 | 一种编码，不是加密；描述文件里的密码用它编码，任何人都能解开 |
| PR（Pull Request） | GitHub 上提交代码修改的请求，合并后修改进入 `main` 分支 |
| CI | 每次提交代码时 GitHub 自动编译和跑测试，全是绿勾表示通过 |

---

# 技术说明

以下是实现细节，日常使用不用看。更完整的内容见 [docs/design.md](docs/design.md)。

## 工作原理

苹果设备上的“网络中继”是 iOS 17、macOS 14 引入的系统功能。装了描述文件之后，系统对匹配的连接不再直接连目标，而是：

- **TCP**：向中继发一个 HTTP `CONNECT` 请求（`:authority` 是目标的 `主机:端口`），中继连上目标后回 200，之后请求流上的数据就是这个 TCP 连接的数据。
- **UDP**（包括 QUIC，也就是 HTTP/3 网站）：按 URI 模板 `https://relay.qolita.com/.well-known/masque/udp/{target_host}/{target_port}/` 发一个 CONNECT-UDP 请求（RFC 9298），UDP 包走 HTTP 数据报（HTTP/3 上是 QUIC DATAGRAM 帧）。
- 域名由**中继**解析：设备发来的是主机名，服务器上查 DNS、连目标，所以 DNS 查询也不经过本地网络。
- 每个请求都带着描述文件里的 `Authorization: Basic ...` 头，中继据此认证。

一个设备通常只和中继保持一条 HTTP/3 连接，上面同时跑着很多请求流，每个流是一个被转发的 TCP 连接或 UDP 流。

## 实现了什么

| 功能 | 说明 |
|---|---|
| 三种 HTTP 版本 | HTTP/3（QUIC，UDP 443）、HTTP/2 和 HTTP/1.1（TLS，TCP 443），同一个端口同时提供 |
| TCP 中继 | 经典 CONNECT（RFC 9110 §9.3.6，RFC 9113 §8.5，RFC 9114 §4.4）。半关闭（FIN）双向传递；任一方出错时双方都复位（HTTP/3 上用 H3_CONNECT_ERROR，目标一侧发 TCP RST）。连目标用 Happy Eyeballs（RFC 8305） |
| UDP 中继 | CONNECT-UDP（RFC 9298），URI 模板可配置。HTTP/3 上走 QUIC 数据报，HTTP/2 和 HTTP/1.1 上走 DATAGRAM 胶囊（RFC 9297）。未知的上下文 ID 和胶囊按规定丢弃/跳过。请求刚发出、还没收到响应时设备就发来的数据报会暂存，不丢 |
| 认证 | HTTP Basic（RFC 7617），`Authorization` 或 `Proxy-Authorization` 都接受。服务器只保存 Argon2id 哈希（RFC 9106）。验证结果缓存 10 分钟（缓存的键是请求头的 HMAC，不存密码），同一个设备的一连串请求只算一次哈希 |
| 伪装网站 | 没有正确密码的请求（包括所有 CONNECT）得到网站的回答，和访问一个不存在的页面一样。`/.well-known/` 下没有的文件回 404（苹果设备可能会查 `/.well-known/pvd`） |
| 目的地址限制 | 默认不允许访问服务器本机、私有网络、链路本地、组播等地址；域名解析出的**每个**地址都检查（防 DNS 重绑定）。默认封 25 端口（防发垃圾邮件）。可配置 |
| 错误信息 | 通过认证的请求失败时，按 RFC 9209 带 `Proxy-Status` 头说明原因（DNS 失败、连接被拒、超时、地址被禁止等） |
| 在线管理 | `systemctl reload` 重新读取用户、目的地址规则、超时、网站和证书；被删除或改了密码的用户，连接立刻断开 |
| 描述文件生成 | `network-relay profile`：生成 `com.apple.relay.managed` 描述文件，可以直接放到网站上用 Safari 打开安装 |
| 自检 | `network-relay check`：像设备一样在三种 HTTP 版本上测试 TCP 和 UDP 中继，并确认没有密码时看不出是中继 |
| 资源限制 | 同时转发的连接数上限；UDP 流空闲 5 分钟关闭；systemd 下只保留绑定 443 端口的权限 |

## 限制

- **没有在真机上测过**（见开头）。
- 按苹果的说明，中继作用于使用系统网络框架（URLSession、Network.framework）的连接；自己实现网络栈或直接用底层 socket 的程序可能不经过中继。它不是 VPN：ICMP（ping）等不经过中继。
- TCP 只支持经典 CONNECT。草案 [draft-ietf-httpbis-connect-tcp](https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/)（`:protocol = connect-tcp`）还没有实现；目前苹果的文档写的是用 CONNECT 方法。
- 只支持用户名密码。描述文件里用客户端证书（`PayloadCertificateUUID`）认证的方式没有实现。
- 服务端只能在 Linux 上运行（`check` 和 `profile` 在 Mac 上也能编译运行）。

## 遵循的标准

| 规范 | 内容 |
|---|---|
| RFC 9298 Proxying UDP in HTTP | CONNECT-UDP：三种 HTTP 版本的请求格式、URI 模板、数据报格式 |
| RFC 9297 HTTP Datagrams and the Capsule Protocol | HTTP 数据报、胶囊、`Capsule-Protocol` 头 |
| RFC 9110 §9.3.6、RFC 9113 §8.5、RFC 9114 §4.4 | 三种 HTTP 版本上的 CONNECT 和错误处理 |
| RFC 8441、RFC 9220 | HTTP/2、HTTP/3 上的扩展 CONNECT |
| RFC 9209 | `Proxy-Status` 错误信息 |
| RFC 8305 | Happy Eyeballs 连接目标 |
| RFC 6570 | URI 模板（RFC 9298 限定的子集） |
| RFC 7617、RFC 9106 | Basic 认证、Argon2 密码哈希 |
| RFC 8615 | `/.well-known/` 路径 |
| RFC 4787 | UDP 流的空闲超时不少于 2 分钟 |

## 文档

| 文档 | 内容 |
|---|---|
| [docs/deploy.md](docs/deploy.md) | 部署补充：从源码编译、在 Mac 上自检、DNS 验证申请证书、防火墙 |
| [docs/config.md](docs/config.md) | 配置文件的每一项、`network-relay` 各命令的参数 |
| [docs/design.md](docs/design.md) | 设计文档：苹果网络中继的调研结论和出处、协议细节、安全考虑、代码结构 |
| [CHANGELOG.md](CHANGELOG.md) | 版本记录 |

## 测试

```bash
cargo test
```

- **单元测试**：URI 模板、胶囊和数据报格式、目标地址解析和黑名单、认证和缓存、描述文件格式、网站、日志等。
- **进程内集成测试**（`tests/in_process.rs`）：真实的中继和客户端在一个进程里，走本机回环上真实的 TLS、QUIC 和 TCP，转发到本地的 TCP 和 UDP 服务。覆盖三种 HTTP 版本上的 TCP 和 UDP、大量数据和半关闭、密码错误时看到网站、黑名单和端口限制、目标不可达时的 Proxy-Status、删除用户后连接断开、连接数上限、提前发送的数据报。
- **互通测试**（手动）：curl 通过 HTTP/1.1 和 HTTP/2 的 CONNECT；quic-go 的 [masque-go](https://github.com/quic-go/masque-go) 客户端通过 HTTP/3 的 CONNECT-UDP 收发 1200、1300 字节的数据报；`network-relay check` 经真实互联网查询 1.1.1.1。步骤见 [docs/design.md](docs/design.md#7-互通测试)。

GitHub Actions 在每次推送到 `main` 时运行格式检查、clippy 和全部测试，并在 arm64（qemu）上再跑一遍；发布 Release 时自动附上 x86_64 和 arm64 的程序包。
