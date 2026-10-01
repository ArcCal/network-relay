# 部署补充

Debian 13 x64 从下载的源码自动安装、申请证书及生成分流描述文件，见[自动部署说明](deploy-debian13.md)。

README 的[一键安装](../README.md#方式一debian-13-一键安装推荐)和[手动安装](../README.md#方式二手动安装)是完整的部署步骤。这里是其中提到的几种其他做法。

## 从源码编译

没有发布版本，或者想用最新代码时，在服务器上自己编译。需要约 1 GB 内存；内存小的服务器可能要先加 swap。

```bash
apt install -y build-essential git
```

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```bash
source "$HOME/.cargo/env"
```

仓库是私有的。最简单的是在电脑浏览器登录 GitHub，下载 `main` 分支的 ZIP 上传到服务器解压（见 README [一键安装第 2 步](../README.md#第-2-步下载源码并上传)），然后跳到下面的 `cd` 那一步。也可以在服务器上用 GitHub 官方命令行登录后克隆：

```bash
apt install -y gh
```

```bash
gh auth login
```

依次选 `GitHub.com` → `HTTPS` → `Y` → `Login with a web browser`，它显示一个 8 位代码；在**电脑或手机的浏览器**里打开 https://github.com/login/device 输入代码，点 Authorize。服务器上看到 `Logged in as ...` 后：

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

之后照 README [手动安装](../README.md#方式二手动安装)的第 6 步（伪装网站）继续。第 9、10 步用到的 `deploy/` 目录就在这个源码目录里。

更新：

```bash
cd /root/network-relay && git pull && cargo build --release && install -m 755 target/release/network-relay /usr/local/bin/ && systemctl restart network-relay
```

## 在 Mac 上自检

`network-relay check` 在服务器上跑，测的是“服务器自己连自己”。想确认从外面（比如家里的网络）也能连通，可以在 Mac 上跑同一个命令。

Mac 上要先编译（和编译 masque-vpn 的方法一样）：

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

仓库是私有的：提示输入时，用户名填 GitHub 用户名，密码填一个 GitHub personal access token（GitHub 网页的 Settings → Developer settings 里创建，能读这个仓库即可）。不想用 git 的话，在浏览器里登录 GitHub，打开仓库页面，Code → Download ZIP，解压。

```bash
cd network-relay && cargo build --release
```

然后（**先退出 Clash、Stash 之类的代理软件**，否则测的是它们）：

```bash
./target/release/network-relay check --server relay.qolita.com --user macbook
```

- 服务器只能在 Linux 上运行，但 `check` 和 `profile` 两个命令在 Mac 上也能用。
- 想绕过 DNS、直接连某个 IP：加 `--address 服务器IP`。

## 证书

### 80 端口用不了：用 DNS 验证

`certbot --standalone` 需要 TCP 80。80 端口被占用或被封时，改用 DNS 验证，不需要任何端口：

```bash
certbot certonly --manual --preferred-challenges dns -d relay.qolita.com
```

按提示在域名的 DNS 里加一条 `_acme-challenge.relay.qolita.com` 的 TXT 记录，等一两分钟再按回车。

- 手动 DNS 验证**不能自动续期**，90 天内要再做一次。域名在 Cloudflare 上的话，可以装 `python3-certbot-dns-cloudflare`，用 Cloudflare 的 API Token 自动完成，能自动续期。
- 证书文件的位置和 `--standalone` 一样，配置不用改。

### 续期后多久生效

中继默认每天凌晨 3 点（系统时区）重新读取证书文件；想立刻生效就 `systemctl reload network-relay`。也可以让 certbot 每次续期后自动通知中继：

```bash
printf '#!/bin/sh\nsystemctl reload network-relay\n' > /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

```bash
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/network-relay
```

## 服务器上的防火墙

云服务商的防火墙之外，服务器上如果开着 ufw：

```bash
ufw allow 443/tcp
```

```bash
ufw allow 443/udp
```

```bash
ufw allow 80/tcp
```

用 nftables 或 iptables 自己写规则的，同样放行 TCP 80、TCP 443、UDP 443。

## 端口不是 443

`listen` 可以改成别的端口，比如 `listen = "[::]:8443"`，然后：

- 云防火墙放行 TCP 和 UDP 的这个端口；
- 生成描述文件时加 `--port 8443`，自检时也加 `--port 8443`。

用 443 最好：很多网络只放行 443，而且看起来就是一个普通网站。

## 和别的网站共用一台服务器

中继要独占 TCP 443 和 UDP 443。服务器上已经有 nginx 之类占着 443 时，最简单的是给中继另开一台服务器或另一个 IP。中继自带的伪装网站可以放任意静态网页（`[web] root` 目录），很多情况下不再需要 nginx。

## systemd 服务做了什么

`deploy/network-relay.service`：

- 以 root 启动，只是为了能读 certbot 的私钥（只有 root 能读）；root 的其他权限都去掉了，只保留绑定 443 端口的权限（`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`）。
- 系统目录只读、看不到 /home、独立的 /tmp，等等。
- `systemctl reload` 发送 SIGHUP，重新读取配置。
- 打开文件数上限设为 1048576：每个被转发的连接占一个。
- 日志进 journal；配置了 `log_dir = "/var/log/network-relay"` 时另存文件（这个目录由 systemd 创建）。
