# Debian 12/13 x64：下载源码后自动安装

适用于 Debian 12 或 13、x86_64、systemd VPS（脚本文件名仍是 `install-debian13.sh`）。源码可以从 GitHub 下载 ZIP 后上传、解压；VPS 无需登录 GitHub。编译时仍需访问 Debian 软件源、Rust 官方下载站、crates.io 和公开依赖仓库。

## 已有本次交付的 mobileconfig

1. 将 `relay.qolita.com` 的 A 记录指向 VPS 公网 IPv4。仅在 IPv6 可用时设置 AAAA；Cloudflare 选择“仅 DNS”。
2. 云服务商安全组放行 TCP 80、TCP 443、UDP 443，保留 SSH 端口。
3. 将源码 ZIP 解压，并将单独交付的 `relay.qolita.com-iphone.mobileconfig` 上传到 VPS 的 `/root/`。该文件包含随机账号密码，不在 Git 仓库中。
4. 在解压的源码目录中执行：

```bash
sudo bash deploy/install-debian13.sh --profile /root/relay.qolita.com-iphone.mobileconfig
```

可以附加 `--email 你的邮箱` 接收证书账户相关邮件；不提供时创建无邮箱 ACME 账户。执行自动证书申请流程会调用 certbot 的 `--agree-tos`，即接受 Let's Encrypt 服务条款。若已有公共 CA 的证书，可以改用 `--cert /路径/fullchain.pem --key /路径/privkey.pem`。

安装完成后，把**同一份** mobileconfig 安装到 iPhone/iPad/Mac。不要另生成不同密码的文件替换它；设备和服务器必须使用同一组凭据。安装副本也保存在 `/etc/network-relay/device.mobileconfig`，权限 600，不会发布到网站。

## 没有预先生成的 mobileconfig

```bash
sudo bash deploy/install-debian13.sh --domain relay.qolita.com
```

脚本会生成新随机密码，创建 `iphone` 账号，并在 `/etc/network-relay/device.mobileconfig` 输出与其一致的分流文件。下载这份新文件到设备安装。此模式的随机密码与其他独立生成的 profile 不同。

默认分流 Google/Gemini（含 Gmail、Drive、YouTube）、Claude、X/Grok、ChatGPT 等服务，使用非空 `MatchDomains`；规则和边界见 [域名表说明](../deploy/domains/README.md)。新生成文件可用 `--domains 自己的列表.txt` 调整；导入文件时直接保留其规则。

## 脚本完成的步骤

- 检查系统、并发安装锁、域名及端口占用；不会停止占用端口的其他服务。
- 安装软件依赖和 Rust 工具链，按 `Cargo.lock` 编译源码。默认单进程编译并关闭构建 LTO，以降低小 VPS 的峰值内存需求；建议至少 2 GiB 内存及 3 GiB 可用磁盘。可用 `--jobs 2` 提高并发。
- 自动申请/复用 Let's Encrypt 证书，启用 `certbot.timer`，安装续期后重载中继的 hook。TCP 80 须长期可用以续期。
- 若 UFW 已启用，添加 TCP 80 和中继 TCP/UDP 端口规则；不会清空防火墙规则。自行配置的 nftables/iptables 和云安全组仍需你放行相应端口。
- 创建默认网站、仅保存 Argon2id 哈希的服务器配置，以及权限 600 的设备描述文件；保留程序默认的目标地址限制。
- 安装 systemd 单元、开机启动和 UDP 缓冲区配置。现有较大的缓冲区设置不会被调小。
- 原子替换程序并验证本机 HTTPS；失败时恢复安装前文件及原来的运行/启用状态。文件备份在 `/etc/network-relay/backups/时间戳/`，对应路径记录在 `manifest.json` 中。软件包安装、证书签发和 UFW 放行不会随此回退而撤销。
- 运行三种 HTTP 版本的 TCP/UDP 联网自检。若外部测试目标不可达，自检返回失败并保留已启动服务，便于诊断；本机通过不能代替外部网络的 UDP 443 检查。

不传 `--binary` 时从源码编译；已有同一 Debian 版本的 x64 编译产物时，可传 `--binary /路径/network-relay`。

## 更新与重复执行

由本脚本创建的安装，再次运行同一命令会保留密码及配置，包括手工添加的用户或设置。也可以只运行：

```bash
sudo bash deploy/install-debian13.sh
```

它会从 `/etc/network-relay/device.mobileconfig` 恢复安装身份，编译当前下载的源码并更新程序。提供不同域名、端口、用户名或密码时会拒绝覆盖。

脚本不会接管没有该 profile 的旧手工安装。旧安装可以保留现有配置并单独更新二进制；修改前先备份：

```bash
cargo build --locked --release
sudo target/release/network-relay serve --config /etc/network-relay/relay.toml --check
sudo install -m 755 target/release/network-relay /usr/local/bin/network-relay.new
sudo mv /usr/local/bin/network-relay.new /usr/local/bin/network-relay
sudo systemctl restart network-relay
```

## 检查运行状态

```bash
systemctl status network-relay --no-pager
journalctl -u network-relay -n 80 --no-pager
systemctl list-timers certbot.timer
```

脚本、真实 profile/config 生成和解析、重复执行、端口冲突与启动失败回退均有自动化测试；其中包管理、ACME 和 systemd 操作使用模拟命令，避免在测试机上更改系统。实际证书签发和云防火墙连通性须在你的 VPS 上验证。
