# Network Relay

给 iPhone、iPad、Mac **系统自带的“网络中继”（Network Relay）**功能用的服务端。

- **设备上不用装任何 App**：装一个描述文件（`.mobileconfig`），系统自己把流量经你的服务器转发。
- 可以只让**指定的域名**走中继、其他直连；也可以让**全部流量**走中继。
- 协议是苹果规定的标准协议：TCP 用 HTTP CONNECT，UDP 用 CONNECT-UDP（RFC 9298），跑在 HTTP/3（QUIC）、HTTP/2、HTTP/1.1 上。
- 用户名密码认证。没有密码的人访问你的域名，看到的只是一个普通网站。
- 需要 iOS / iPadOS 17、macOS 14 或更新的系统。

> **当前状态（0.1.0）**：服务端已经用 curl、quic-go 的 masque-go 客户端和自带的自检工具在 HTTP/3、HTTP/2、HTTP/1.1 上测通。**还没有在真实的 iPhone、Mac 上验证过**，按下面的步骤做完，就是第一次真机测试。遇到问题请看[出了问题怎么办](#出了问题怎么办)。

这个项目和 [masque-vpn](https://github.com/ArcCal/masque-vpn) 是两个独立的项目：masque-vpn 是 CONNECT-IP 全局 VPN，需要自己的客户端；这里用的是苹果系统自带的功能，不需要客户端。

---

## 从零开始

### 开始之前：必读三条

1. **一次只复制一行命令，回车，看完输出再做下一行。**
   多行一起粘贴时，遇到要输入密码的命令，后面的行会被吞掉，看起来什么都没发生。
   标着 **“文件内容”** 的灰框不是命令，是要粘贴进编辑器 nano 里的。
2. **把例子换成你自己的：**

   | 例子 | 换成 |
   |---|---|
   | `relay.qolita.com` | 你的中继域名 |
   | `iphone` | 你给这台设备起的用户名（**每台设备一个**，方便单独停用） |
   | `x86_64` | 服务器的 CPU 架构，第 6 步会查 |

3. **输入密码时屏幕上什么都不显示**，这是正常的，输完按回车。

### 第一部分：服务器（只做一次）

需要一台有公网 IP 的 Linux 服务器（Debian 12/13、Ubuntu 22.04 或更新），和一个域名。下面的命令以 Debian 为例，Ubuntu 完全一样。

#### 第 1 步：在云服务商的网页上开端口

在云服务商的防火墙（“安全组”“防火墙规则”之类）里放行：

| 协议 | 端口 | 用途 |
|---|---|---|
| TCP | 22 | 登录服务器（一般默认已有，**别删**） |
| TCP | 80 | 申请证书 |
| TCP | 443 | HTTP/2、HTTP/1.1 中继和伪装网站 |
| **UDP** | **443** | HTTP/3 中继（**很多云默认没有，一定要加**） |

- 服务器有 IPv6 的话，IPv6 的防火墙也加一样的规则。
- 最好给服务器绑一个固定的公网 IP（“静态 IP”“弹性 IP”），否则重启后 IP 可能变。
- UDP 443 不开也能用（设备会改用 HTTP/2），只是慢一些。

#### 第 2 步：让域名指向服务器

在域名的 DNS 里加一条 **A 记录**：`relay.qolita.com` → 服务器的公网 IPv4。

- **用 Cloudflare 的话，这条记录必须是“仅 DNS”（灰色云朵）。** 橙色云朵（代理）会让 Cloudflare 截住连接，中继无法工作。
- 服务器有 IPv6 的话，可以再加一条 AAAA 记录。

#### 第 3 步：登录服务器，变成 root

```bash
sudo -i
```

提示符的结尾变成 `#` 就对了。没装 sudo 的 Debian 用 `su -`。**后面服务器上的命令都在这个 root 窗口里执行，不用再加 sudo。**

#### 第 4 步：安装需要的软件，确认域名

```bash
apt update
```

```bash
apt install -y certbot gh curl
```

```bash
getent hosts relay.qolita.com
```

```bash
curl -4 -s https://ifconfig.me; echo
```

**应该看到：** 两条命令显示的是同一个 IP（服务器的公网 IP）。

- 不一样：A 记录填错了、还没生效（等几分钟），或者 Cloudflare 开着橙色云朵。
- **别在 iPhone 或 Mac 上查。** 开着 Clash、Stash、Surge 这类软件时，会查到 `198.18.x.x` 的假地址。

#### 第 5 步：申请证书

```bash
certbot certonly --standalone -d relay.qolita.com
```

第一次会问邮箱（填你的）、是否同意条款（`Y`）、是否分享邮箱（`N`）。

**应该看到：** `Successfully received certificate.`

- 看到 `Timeout during connect (likely firewall problem)`：TCP 80 没开，回第 1 步。
- 以后证书自动续期，中继每天凌晨 3 点自动读取新证书，不用管。

#### 第 6 步：下载程序

先登录 GitHub（仓库是私有的）：

```bash
gh auth login
```

依次选：`GitHub.com` → `HTTPS` → `Y` → `Login with a web browser`。

1. 它会显示一个 8 位代码，比如 `ABCD-1234`，然后让你按回车。按回车；服务器上没有浏览器，打开失败的提示不用管。
2. 在**电脑或手机的浏览器**里打开 https://github.com/login/device ，输入这个代码，点 Authorize。
3. 回到服务器，看到 `Logged in as ...` 就好了。

查服务器是哪种 CPU：

```bash
uname -m
```

- 显示 `x86_64`：下面照抄。
- 显示 `aarch64`：把下面命令里的 `x86_64` 全部换成 `arm64`。

```bash
cd /root
```

```bash
gh release download -R ArcCal/network-relay -p '*linux-x86_64.tar.gz'
```

```bash
tar -xzf network-relay-*-linux-x86_64.tar.gz
```

```bash
cd network-relay-*-linux-x86_64
```

```bash
install -m 755 network-relay /usr/local/bin/
```

```bash
network-relay --version
```

**应该看到：** `network-relay 0.1.0`（或更新的版本号）。

- `gh release download` 报 `no assets match`：仓库还没有发布版本，或者还在编译（发布后大约 10 分钟才有文件）。也可以自己编译，见 [docs/deploy.md](docs/deploy.md#从源码编译)。
- **不要离开这个目录**，第 10、11 步还要用这里的文件。

#### 第 7 步：放一个伪装网站

没有密码的人访问 `https://relay.qolita.com`，看到的就是这个网站。放什么都行，只要有 `index.html`。先放一个最简单的：

```bash
mkdir -p /var/www/relay
```

```bash
echo '<!doctype html><title>Welcome</title><h1>Welcome</h1>' > /var/www/relay/index.html
```

#### 第 8 步：给 iPhone 建一个用户

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

- 第 1 段（`[[user]]` 和下面两行）第 9 步要贴进配置文件。
- 第 2 段是密码，**记下来**，第二部分生成描述文件时要用。服务器只保存哈希，密码只显示这一次；丢了就重新运行这条命令，建一个新的。

#### 第 9 步：写服务器配置

```bash
mkdir -p /etc/network-relay
```

```bash
nano /etc/network-relay/relay.toml
```

**文件内容**（把 `relay.qolita.com` 换成你的域名；最后三行换成第 8 步打印的第 1 段）：

```toml
listen = "[::]:443"

[tls]
cert = "/etc/letsencrypt/live/relay.qolita.com/fullchain.pem"
key = "/etc/letsencrypt/live/relay.qolita.com/privkey.pem"

[web]
root = "/var/www/relay"

[[user]]
name = "iphone"
password_hash = "$argon2id$v=19$..."
```

按 Ctrl+O、回车保存，Ctrl+X 退出。然后让只有 root 能读这个文件：

```bash
chmod 600 /etc/network-relay/relay.toml
```

```bash
network-relay serve --check
```

**应该看到：** `... configuration, certificate and website are fine; users: 1`

- 报错会指出是哪一行、哪一项。最常见的是域名没换、`password_hash` 没复制全。
- 其他可以设置的项（只让访问某些端口、超时、调试日志等）见 [docs/config.md](docs/config.md)，完整的示例在 `deploy/relay.example.toml`。

#### 第 10 步：加大 UDP 缓冲区

让 HTTP/3 在高速时不丢包：

```bash
cp deploy/99-network-relay.conf /etc/sysctl.d/
```

```bash
sysctl --system
```

#### 第 11 步：启动

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
INFO TLS certificate: relay.qolita.com, valid until ...
INFO network-relay 0.1.0 ready (HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP) ...
```

- 以后开机自动启动，崩溃自动重启。
- 看日志一律用上面这条 `journalctl` 命令；`systemctl status` 会把长的行截断。

#### 第 12 步：自检

在服务器上，用第 8 步的用户名和密码，像设备那样把三种 HTTP 版本都试一遍：

```bash
network-relay check --server relay.qolita.com --user iphone
```

提示 `Password:` 时粘贴第 8 步的密码，回车（屏幕上不显示）。

**应该看到：** 七行都是 `✓`，最后是 `All checks passed.`

```
✓ HTTP/3 TCP (CONNECT)                 example.com:80 answered "HTTP/1.1 200 OK" (35 ms)
✓ HTTP/3 UDP (CONNECT-UDP)             DNS server 1.1.1.1:53 answered (rcode 0, 2 records) (20 ms)
✓ HTTP/2 TCP (CONNECT)                 ...
✓ HTTP/2 UDP (CONNECT-UDP)             ...
✓ HTTP/1.1 TCP (CONNECT)               ...
✓ HTTP/1.1 UDP (Upgrade: connect-udp)  ...
✓ hidden without password              a CONNECT without credentials gets 404 like any missing page
```

- 只有 `HTTP/3` 两行是 `✗`：UDP 443 没放行，回第 1 步。
- 提示 `answered like a plain website`：用户名或密码不对，或者改了配置没有 `systemctl reload network-relay`。
- 想从服务器外面再测一次，在 Mac 上也能跑这个命令，见 [docs/deploy.md](docs/deploy.md#在-mac-上自检)。

再用浏览器打开 `https://relay.qolita.com`，应该看到第 7 步的网页。

服务器部分完成。

### 第二部分：iPhone、iPad

#### 第 1 步：先关掉别的 VPN 和代理软件

测试时先把 **Stash、Clash、Shadowrocket、Surge** 之类的软件断开（设置 → VPN 里显示“未连接”）。它们开着时，流量可能先被它们接走，看不出中继有没有生效。测通以后再按需要打开。

#### 第 2 步：在服务器上生成描述文件

**第一次先只让 `ifconfig.me` 这一个网站走中继**，其他上网完全不受影响，测试最安全：

```bash
network-relay profile --host relay.qolita.com --user iphone --match-domain ifconfig.me --publish
```

提示 `Password:` 时粘贴第 8 步的密码。会打印：

```
1. Let the relay serve it:   systemctl reload network-relay
2. Open this link in Safari on the iPhone, iPad or Mac, and install the profile:
   https://relay.qolita.com/Ab3...（一串随机字符）.mobileconfig
3. Then delete it (it contains the password):
   rm /var/www/relay/Ab3....mobileconfig && systemctl reload network-relay
```

按提示先执行：

```bash
systemctl reload network-relay
```

#### 第 3 步：在 iPhone 上安装

1. 把第 2 步打印的链接发到 iPhone 上（比如用备忘录、微信发给自己），**用 Safari 打开**（别的浏览器不行）。
2. 提示“此网站正尝试下载一个配置描述文件”时，点 **允许**，然后点 **关闭**。
3. 打开 **设置**，最上面会出现 **已下载描述文件**，点进去 → 右上角 **安装** → 输入锁屏密码 → **安装**。
   - 没看到的话：设置 → 通用 → VPN 与设备管理 → 下面的“已下载描述文件”。

#### 第 4 步：删掉服务器上的描述文件

描述文件里有密码，装好后立刻删掉。在服务器上执行第 2 步打印的第 3 条命令：

```bash
rm /var/www/relay/Ab3....mobileconfig && systemctl reload network-relay
```

（`Ab3....` 换成实际的文件名；也可以用 `rm /var/www/relay/*.mobileconfig && systemctl reload network-relay` 删掉所有描述文件。）

#### 第 5 步：验证

1. 在服务器上打开实时日志：
   ```bash
   journalctl -u network-relay -f -o cat
   ```
2. 在 iPhone 的 Safari 打开 https://ifconfig.me 。

**应该看到：**
- 网页上显示的是**服务器的 IP**，不是你自己的。
- 服务器日志出现 `client connected user="iphone" ... transport="HTTP/3"`（用 HTTP/2 时是 `HTTP/2`）。
- 打开别的网站，显示的还是你自己的 IP（没走中继）。

按 Ctrl+C 退出日志。

- 显示的是自己的 IP、服务器日志里什么都没有：见[出了问题怎么办](#出了问题怎么办)。
- 设置 → 通用 → VPN 与设备管理 里能看到这个中继和它的开关（不同系统版本的位置和名字略有不同，比如“VPN 与中继”）。

#### 第 6 步：改成你真正想要的范围

测通以后，重新生成描述文件。**用户名和域名不变时，新描述文件会替换旧的**，不用先删。

- **指定的域名走中继，其他直连**：每个域名一个 `--match-domain`，子域名自动包含（写 `google.com` 就包含 `www.google.com`）：
  ```bash
  network-relay profile --host relay.qolita.com --user iphone --match-domain google.com --match-domain youtube.com --publish
  ```
- **全部流量走中继**：不写 `--match-domain`：
  ```bash
  network-relay profile --host relay.qolita.com --user iphone --publish
  ```
- 全部走中继、但某些域名直连：加 `--exclude-domain 域名`。

然后同样：`systemctl reload network-relay` → Safari 打开链接 → 安装 → 删文件。

### 第三部分：Mac

需要 macOS 14 或更新。

1. 在服务器上给 Mac 建一个自己的用户（第一部分第 8 步，名字比如 `macbook`），把 `[[user]]` 那段追加到 `/etc/network-relay/relay.toml`，然后 `systemctl reload network-relay`。
2. 生成描述文件（和 iPhone 一样，用户名换成 `macbook`）：
   ```bash
   network-relay profile --host relay.qolita.com --user macbook --match-domain ifconfig.me --publish
   ```
   ```bash
   systemctl reload network-relay
   ```
3. 在 Mac 的 **Safari** 里打开打印的链接，文件会下载下来。
4. 打开 **系统设置** → **通用** → **设备管理**（旧版本叫“描述文件”；也可以在系统设置的搜索框里搜“描述文件”），双击刚下载的描述文件，点 **安装**，输入 Mac 的登录密码。
5. 删掉服务器上的描述文件（同 iPhone 第 4 步）。
6. 验证：先退出 Mac 上的 Clash、Stash 这类软件，然后在 Safari 打开 https://ifconfig.me ，应该显示服务器的 IP；服务器日志出现 `client connected user="macbook"`。

---

## 日常操作

| 要做的事 | 怎么做 |
|---|---|
| 加一台设备 | `network-relay passwd --name 新名字` → 把 `[[user]]` 段追加到 `/etc/network-relay/relay.toml` → `systemctl reload network-relay` → 给设备生成描述文件 |
| 停用一台设备 | 从配置里删掉它的 `[[user]]` 段 → `systemctl reload network-relay`。它正在用的连接立刻断开，以后也连不上 |
| 改走中继的域名 | 用同样的 `--host` 和 `--user` 重新生成描述文件并安装，会替换旧的 |
| 在设备上删除中继 | iPhone：设置 → 通用 → VPN 与设备管理 → 点描述文件 → 移除。Mac：系统设置 → 通用 → 设备管理 |
| 看日志 | `journalctl -u network-relay -n 50 --no-pager -o cat`；实时看加 `-f` |
| 看设备发来的请求细节 | 配置里加 `[debug]` 段写 `log_requests = true`，`systemctl reload network-relay`。每个请求都会记一行（密码隐去）。排查完改回 `false` |
| 改了配置 | `network-relay serve --check` 检查 → `systemctl reload network-relay`。`listen` 和 `max_tunnels` 要 `systemctl restart network-relay` |
| 升级程序 | 按第一部分第 6 步下载新版本并 `install`，然后 `systemctl restart network-relay` |
| 证书 | certbot 自动续期，中继每天凌晨 3 点自动读取，不用管 |

每个设备连接断开时，日志里有一行汇总：连了多久、转发了多少 TCP 连接和 UDP 流、多少被拒绝、上下行流量。

## 出了问题怎么办

先在服务器上跑 `network-relay check --server relay.qolita.com --user iphone`，再看 `journalctl -u network-relay -n 50 --no-pager -o cat`。

| 现象 | 原因和处理 |
|---|---|
| `check` 只有 HTTP/3 两行失败 | UDP 443 没放行（云防火墙，或者服务器上的 ufw/nftables）。设备会改用 HTTP/2，也能用 |
| `check` 全部失败，`QUIC handshake` / `TCP connect` 超时 | 中继没在运行（看日志），或者端口没放行 |
| `check` 提示 `answered like a plain website` | 用户名或密码不对；或者改了配置没 reload；或者用户不在配置里 |
| `certificate not valid for name` | `--server` 写的名字和证书上的不一样 |
| 日志 `authentication failed user="iphone"` | 设备上的描述文件用的是旧密码或错的密码：重新生成描述文件安装 |
| iPhone 上 ifconfig.me 显示自己的 IP，服务器日志什么都没有 | ① Stash、Clash 等 VPN 还开着：断开再试。② 设置 → 通用 → VPN 与设备管理 里中继的开关是否打开。③ 描述文件是否装的是最新的。④ 打开 `log_requests` 再试，看设备到底有没有连过来，把日志发给维护者 |
| 服务器日志有 `client connected`，但网页打不开 | 看有没有 `refused` 的行（需打开 `log_requests`）：`address blocked` 是目标在黑名单里；`DNS lookup failed` 是服务器解析不了这个域名 |
| Safari 打开描述文件链接显示网页或 404 | 生成后没有 `systemctl reload network-relay`，或者文件已经删了 |
| 装描述文件时提示无效 | 把 `network-relay profile` 的完整输出和系统版本发给维护者 |
| 浏览器打开 `https://relay.qolita.com` 不是你的网站 | Cloudflare 橙色云朵开着，改成灰色；或者域名没指到这台服务器 |

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
- **互通测试**（手动）：curl 通过 HTTP/1.1 和 HTTP/2 的 CONNECT；quic-go 的 [masque-go](https://github.com/quic-go/masque-go) 客户端通过 HTTP/3 的 CONNECT-UDP 收发 1200、1300 字节的数据报；`network-relay check` 经真实互联网查询 1.1.1.1。步骤见 [docs/design.md](docs/design.md#互通测试)。

GitHub Actions 在每次推送到 `main` 时运行格式检查、clippy 和全部测试，并在 arm64（qemu）上再跑一遍；发布 Release 时自动附上 x86_64 和 arm64 的程序包。
