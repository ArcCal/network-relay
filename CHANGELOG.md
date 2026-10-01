# 版本记录

## 未发布

- 网站加载时检查实际打开的文件，父目录在检查和打开之间被换成符号链接时，不会读到站点外的文件。
- HTTP/1.1 请求缺少 `Host` 或有多个 `Host` 时返回 400（RFC 9112 §3.2，RFC 9298 §3.2）。
- 按 `relay.udp_template` 展开的请求解析不回原目标时，配置和描述文件生成直接报错，不再静默把 UDP 请求当网站请求。
- `serve --check` 遇到过期或尚未生效的证书时报错。
- 安装脚本：`--cert`/`--key` 按原样保存（不展开 Let's Encrypt 的 `live/` 符号链接）；升级沿用已有安装的证书方式，不会突然改用 certbot；与现有配置不同的 `--cert`/`--key` 被拒绝而不是静默忽略；启动检查接受任何 HTTP 响应（没有 `[web]` 时首页是 404）；安装 `procps`。
- 一键安装脚本也支持 Debian 12（bookworm）x86_64。
- 安装脚本的 `apt-get` 等待 dpkg 锁（最多 30 分钟），新开机的 VPS 正在自动更新时不再直接失败。
- CI：arm64 测试中由测试启动的子进程也能通过 qemu 找到动态链接器。
- `passwd --stdin`、`profile` 和 `check` 在终端里提示输入密码时不再回显。
- UDP 流提前结束时的错误码按原因区分：畸形消息、目标套接字失效、取消或撤销分别用 `H3_MESSAGE_ERROR`/`PROTOCOL_ERROR`、`H3_CONNECT_ERROR`/`CONNECT_ERROR`、`H3_REQUEST_CANCELLED`/`CANCEL`；此前一律按畸形消息处理。
- HTTP/3 TCP 隧道在设备已发 FIN 后收到的数据报静默丢弃（RFC 9297 §2.1），不再复位流。
- HTTP/1.1 的 `Connection` 和 `Upgrade` 按令牌列表解析；HTTP/2 拒绝响应带 `Date`。
- 增加 `deploy/global-profile.py`：用服务域名表（`deploy/domains/global-services.txt`）和 gfwlist 生成 `.mobileconfig`，只用标准库和 `network-relay profile`；有对应的自动化测试。
- 监听或证书重载任务意外退出时，进程现在报错退出（由 systemd 重启），而不是缺一个监听器继续运行；信号处理在监听器启动前注册。
- reload 不再让正在做首次验证、且用户没有变化的请求得到伪装网站的 404；失败的验证结果不再能挤掉缓存中已验证的条目。
- 网站目录里悬空或循环的软链接不再导致整个网站加载失败。
- HTTP/1.1 请求头缓冲限制为 64 KiB（原为 hyper 默认的约 400 KiB），与 HTTP/2、HTTP/3 的 32 KiB 头部上限接近。
- 没有 IPv6 回环的环境里，禁止分片的测试跳过 IPv6 部分；增加 HTTP/1.1 成功响应不带帧头的回归测试。
- 增加 Debian 13 x64 源码安装脚本：自动证书、续期、systemd、配置导入、自检与启动失败回退；提供 Google/AI/X 域名分流预设，私密设备描述文件单独生成，不加入仓库。
- 修复 HTTP/2 半关闭后的取消、HTTP/3 空闲 STOP_SENDING、连接丢失和响应受流控阻塞时的用户撤销，及时释放目标连接及转发名额。
- 按协议拒绝 CONNECT 上的尾部 HEADERS；修复 HTTP/3 空 DATA 被误判为结束、截断 DATA 被误判为正常关闭的问题。依赖的局部修补及来源记录在 `vendor/*/PATCH.md`。
- UDP 未知 Context 的大 Capsule 流式丢弃；写端关闭不再当作普通丢包，阻塞写任务有界退出，持续收包不再阻碍取消和超时。
- 修复 URI 模板分隔符出现在主机名中的匹配错误；加强配置、Argon2 哈希及描述文件 XML/域名校验。
- 网站不再通过文件软链接暴露目录外或隐藏文件，读取大小有界；自定义响应头不能覆盖协议帧控制字段，合法覆盖不产生重复头。
- 自检补全 DNS、HTTP/3 建连和写入超时，TLS 握手失败可尝试下一个地址；DNS 查询校验标签和总长度。
- 描述文件新增 `--match-fqdn`、`--exclude-fqdn`、`--ui-toggle-enabled`、`--allow-dns-failover` 和 `--relay-uuid`，并校验域名、端口和 UUID。
- 修复用户删除或改密期间的认证、建连竞态；限制等待认证的不同凭据数量，取消请求后清理等待项，哈希真正结束前保留计算名额。
- HTTP/2 直接管理流控和流复位，将目标 TCP 错误映射为 `CONNECT_ERROR`，保留正常半关闭。
- HTTP/3 只有在 HTTP 和 QUIC 两层均协商数据报后才使用 QUIC DATAGRAM，否则使用 Capsule；非 UDP 请求收到数据报时发送 `H3_DATAGRAM_ERROR`。
- 修复超大 UDP Payload、未知大 Capsule、禁止的 Capsule 请求头以及混合字面量/变量查询模板的处理。Linux 目标 UDP 套接字显式禁止 IP 分片。
- 普通保存、发布及覆盖描述文件均以权限 600 原子写入，并拒绝符号链接目标。
- 增加协议错误码、Capsule 回退、空 UDP 包和文件权限等回归测试；苹果真机验证仍待完成。

## 0.1.0

第一个版本。

- **中继服务端**：HTTP/3（UDP 443）、HTTP/2 和 HTTP/1.1（TCP 443）上的 TCP 中继（经典 CONNECT）和 UDP 中继（CONNECT-UDP，RFC 9298），按苹果网络中继的用法实现。
- **认证**：用户名密码（HTTP Basic，`Authorization` 或 `Proxy-Authorization`），服务器只存 Argon2id 哈希；验证结果缓存；reload 后被删除的用户立刻断开。
- **伪装网站**：没有密码的请求看到普通网站；`/.well-known/` 下不存在的文件回 404。
- **目的地址限制**：默认禁止内网、本机、元数据服务等地址，检查域名解析出的每个地址；默认封 25 端口。
- **错误信息**：认证通过的请求失败时带 `Proxy-Status`（RFC 9209）。
- **`network-relay profile`**：生成 iPhone、iPad、Mac 用的描述文件，可以直接放到伪装网站上用 Safari 打开安装（`--publish`）。
- **`network-relay check`**：在三种 HTTP 版本上测试 TCP 和 UDP 中继。
- **`network-relay passwd`**：生成用户和密码。
- systemd 服务文件（只保留绑定 443 端口的权限）、UDP 缓冲区的 sysctl 设置、GitHub Actions 编译 x86_64 和 arm64。
- 已用 curl 和 quic-go 的 masque-go 做过互通测试；**还没有在真实的苹果设备上测试过**。
