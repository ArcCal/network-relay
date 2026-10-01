# 设计文档

## 1. 苹果的网络中继

iOS 17、iPadOS 17、macOS 14 起，苹果系统内置了“网络中继”（Network Relay）：系统把匹配的连接交给一个 HTTP 代理服务器转发，不需要 VPN App。iCloud 专用代理（Private Relay）用的也是同一类协议。

配置它有三种方式：

| 方式 | 适用 | 本项目 |
|---|---|---|
| 描述文件负载 `com.apple.relay.managed` | iOS 17+、macOS 14+，**可以手动安装**，不需要监管（supervision）。iOS、macOS、visionOS 27 起标记为“已弃用” | **用这个**。`network-relay profile` 生成 |
| 声明式管理（DDM）的 `com.apple.configuration.network.relay` | 通过 MDM 下发；使用 `VisibleName` 等声明式配置字段 | 不涉及；需要 MDM |
| App 用 `NERelayManager` 配置 | App 自己的中继配置 | 不涉及 |

“已弃用”表示苹果推荐改用 DDM；schema 并未将传统负载标为已移除。安装成功或设置显示已开启都不能代替实际流量的真机验证，本项目尚未完成该验证。

### 1.1 描述文件里的键

来自苹果的 [Relay 负载文档](https://developer.apple.com/documentation/devicemanagement/relay) 和 [apple/device-management](https://github.com/apple/device-management) 仓库里的 `mdm/profiles/com.apple.relay.managed.yaml`：

| 键 | 含义 | `network-relay profile` 的做法 |
|---|---|---|
| `Relays` | 中继服务器列表，可以串联多个 | 一个 |
| `Relays[].HTTP3RelayURL` | “一个 URL 或 RFC 9298 定义的 URI 模板，指向经 HTTP/3 访问、**用 CONNECT 方法代理 TCP 和 UDP** 的中继” | URI 模板 `https://域名/.well-known/masque/udp/{target_host}/{target_port}/` |
| `Relays[].HTTP2RelayURL` | 同上，HTTP/2 | 同一个模板 |
| `Relays[].AdditionalHTTPHeaderFields` | 每个请求都附带的 HTTP 头 | `Authorization: Basic ...` |
| `Relays[].PayloadCertificateUUID` | 用描述文件里的身份证书做客户端认证 | 不用（只支持密码） |
| `Relays[].RawPublicKeys` | 用固定的公钥验证服务器，不走 CA | 不用（用公共 CA 证书） |
| `MatchDomains` | 只有这些域名及其子域名走中继；和 `MatchFQDNs` 都为空时全部走中继 | `--match-domain` |
| `ExcludedDomains` | 这些域名及其子域名不走中继 | `--exclude-domain` |
| `MatchFQDNs`、`ExcludedFQDNs` | 精确匹配的域名（iOS 18.4、macOS 15.4 起） | `--match-fqdn`、`--exclude-fqdn` |
| `UIToggleEnabled` | 允许用户停用中继，默认 true（iOS/macOS 26 起，传统负载也支持） | `--ui-toggle-enabled true/false` |
| `AllowDNSFailover` | 允许回退到设备默认系统 DNS，默认 false（iOS/macOS 26 起） | `--allow-dns-failover true/false` |
| `RelayUUID` | 托管 App 路由标识，user enrollment 必填；macOS 不支持 | `--relay-uuid`；App 关联仍由 MDM 配置 |

### 1.2 设备怎样使用中继

综合苹果的文档、[WWDC23 “Ready, set, relay: Protect app traffic with network relays”](https://developer.apple.com/videos/play/wwdc2023/10002/)、[NERelay](https://developer.apple.com/documentation/networkextension/nerelay) API 文档，以及 jedda 的实测文章 [Beneath the MASQUE: Network Relay on Apple Platforms](https://jedda.me/beneath-the-masque-network-relay-on-apple-platforms/) 和配套的 [Envoy 配置](https://gist.github.com/jedda/62643893faffd9143f9587a12ca1db38)：

- **TCP 用经典 CONNECT**：`:method = CONNECT`，`:authority = 目标主机:端口`，没有 `:protocol`。
- **UDP 用 CONNECT-UDP**（RFC 9298）：扩展 CONNECT，`:protocol = connect-udp`，路径由 URI 模板展开。HTTP/3 上 UDP 包走 QUIC DATAGRAM。
- Envoy 的配置示例分别启用经典 CONNECT 和 CONNECT-UDP，可作为实现对照；支持相同协议并不等于通过苹果真机验证。
- 中继 URL 可以只写 `https://主机:端口/`，这时 UDP 用 RFC 9298 的默认模板 `/.well-known/masque/udp/{target_host}/{target_port}/`。本项目默认就用这个模板，并且在描述文件里写出完整模板，两种理解都对得上。
- **请求携带的主机名由中继解析**：例如 `CONNECT www.example.com:443`。设备是否还会使用本地 DNS 取决于系统和匹配/回退策略，不能据此断言所有 DNS 都经过中继。
- 认证头是描述文件里写的，每个请求都主动带上，不等 401/407 质询。所以中继可以对没带凭据的请求装作普通网站。
- 设备可能按 [draft-ietf-intarea-proxy-config](https://datatracker.ietf.org/doc/draft-ietf-intarea-proxy-config/)（苹果参与编写）查询 `https://中继域名/.well-known/pvd`，看有没有额外的代理配置。本项目对 `/.well-known/` 下不存在的文件回 404，设备就只用描述文件里的配置。
- `NERelayManagerClientError` 列出了设备端可能报告的错误：证书过期/无效/缺失、DNS 失败、服务器证书过期/无效、服务器断开、服务器不可达等。服务器这边能控制的是：证书有效且名字对、端口通、认证正确。

### 1.3 其他实现

调研时看过：Envoy（上面的配置）、quic-go 的 [masque-go](https://github.com/quic-go/masque-go)（CONNECT-UDP 客户端和服务端，只支持 HTTP/3）、sing-box 的 MASQUE 客户端、Vincent-bin/masque-server（面向苹果中继和 Surge 的 CONNECT/CONNECT-UDP 服务端）、erlang_masque、connect-ip-go（CONNECT-IP）。mihomo/usque 用的是 Cloudflare WARP 的私有变体，和标准不兼容。

## 2. 协议实现

### 2.1 请求分类

| HTTP 版本 | TCP 隧道 | UDP 隧道 |
|---|---|---|
| HTTP/3 | `CONNECT`，无 `:protocol`，`:authority = 主机:端口`（RFC 9114 §4.4） | `CONNECT`，`:protocol = connect-udp`，`:path` 匹配模板（RFC 9298 §3.4） |
| HTTP/2 | 同上（RFC 9113 §8.5） | 同上（RFC 8441 扩展 CONNECT） |
| HTTP/1.1 | `CONNECT 主机:端口 HTTP/1.1`（RFC 9110 §9.3.6） | `GET 路径` + `Connection: Upgrade` + `Upgrade: connect-udp`（RFC 9298 §3.2），回 101 |

其他所有请求都交给伪装网站。

### 2.2 处理一个请求

1. **分类**：不是上表中的请求 → 网站。UDP 请求的路径不匹配模板 → 网站。
2. **认证**：先看 `Proxy-Authorization`，没有再看 `Authorization`，都按 Basic 解析。失败 → 网站（CONNECT 得到 404）。认证失败会记日志（用户名转义后记录，防止伪造日志行）。
3. **名额**：同时转发数达到 `max_tunnels` → 503。
4. **目标**：TCP 从 `:authority` 解析 `主机:端口`（端口必填，IPv6 带方括号）；UDP 从模板变量取 `target_host`（IPv6 不带方括号、冒号已编码）和 `target_port`。格式不对 → 400。
5. **策略**：端口在 `blocked_ports` → 403；解析域名（5 秒超时）；解析出的每个地址都检查 `blocked_destinations`，IPv4 映射地址按 IPv4 检查；一个都不剩 → 403。
6. **连接**：TCP 按 Happy Eyeballs（RFC 8305）：按解析顺序、两种地址族交替，每 250 毫秒多试一个，失败的立刻试下一个，整体 `connect_timeout_secs` 超时。UDP 建一个 connect 过的 UDP 套接字（只收目标发回的包），选第一个有路由的地址。
7. **回应**：成功回 200（HTTP/1.1 的 CONNECT-UDP 回 101），CONNECT-UDP 带 `Capsule-Protocol: ?1`。失败时回上面的状态码，并带 RFC 9209 的 `Proxy-Status: network-relay; error=...`（`dns_error`、`dns_timeout`、`destination_not_found`、`destination_ip_prohibited`、`http_request_denied`、`connection_refused`、`connection_timeout`、`destination_unavailable`、`connection_limit_reached`、`http_request_error`）。

### 2.3 TCP 转发

- **HTTP/3**：请求流的 DATA 帧就是 TCP 数据。一方发 FIN（流结束 / TCP FIN），就把另一方的发送方向关掉，另一个方向继续，两个方向都结束才算完（半关闭）。任一方出错：请求流用 `H3_CONNECT_ERROR` 复位，目标一侧发 TCP RST（`SO_LINGER=0`），按 RFC 9114 §4.4 的要求。用户被删除时用 `H3_REQUEST_CANCELLED`。
- **HTTP/2**：通过 h2 直接管理 DATA、流控和 RST_STREAM，双向复制并传递半关闭；目标 TCP 错误（含 RST）显式发送 `CONNECT_ERROR`，客户端复位或用户撤销时目标一侧发 RST。
- **HTTP/1.1**：hyper 把 CONNECT 后的流交出来，双向复制并传递半关闭；出错时目标一侧发 RST。
- HTTP/2 半关闭后仍监听 RST_STREAM；HTTP/3 空闲时也监听 STOP_SENDING 和连接断开。响应头因流控阻塞时，用户撤销仍可取消建好的连接。
- CONNECT 上的尾部 HEADERS：HTTP/2 使用 `PROTOCOL_ERROR` 流错误，HTTP/3 使用 `H3_FRAME_UNEXPECTED` 连接错误。空 DATA 不代表 FIN，截断 DATA 不能当作正常结束。
- 读目标的缓冲区 64 KiB。字节数边转发边计数，连接怎么结束都统计得准。
- 目标连接关闭 Nagle（设备的 TCP 已经攒过包），开 keepalive（2 分钟起），避免对端消失后连接一直挂着。

### 2.4 UDP 转发

- 数据报格式（RFC 9298 §5）：上下文 ID（变长整数）+ UDP 负载。只处理上下文 ID 0，其他丢弃；空负载合法，超过 65527 字节则中止流。
- HTTP/3 只有在 HTTP 的 `SETTINGS_H3_DATAGRAM` 和 QUIC 的 DATAGRAM 能力均已协商时才发送 QUIC DATAGRAM（RFC 9297）；否则和 HTTP/2、HTTP/1.1 一样，使用请求流里的 DATAGRAM 胶囊。
- 未知类型或未知 Context 的胶囊流式跳过，不受 UDP 大小限制；Context 0 根据声明长度尽早检查 UDP 上限。截断等格式错误中止请求流；Capsule 请求禁止 `Content-Length`、`Content-Type`、`Transfer-Encoding`（RFC 9297 §3.2–3.3）。
- Linux 目标 UDP 套接字显式设置 IPv4/IPv6 的不分片策略；超过路径 MTU 的包丢弃，避免引入 IP 分片（RFC 9298 §3.1）。
- 目标发回的 UDP 包太大、装不进一个 QUIC DATAGRAM 时丢弃，不改用可靠传输（否则 QUIC 套 QUIC 会互相干扰拥塞控制）。
- 队列满、目标回单个数据报的 ICMP/PMTU 错误时丢包；套接字失效或请求写端关闭则结束流。转发循环限制每轮收包量，等待发送时仍响应撤销和超时。
- 流结束后最多留一秒排空 Capsule 写队列；阻塞不退的写端随后复位，避免遗留后台任务。
- 双向都 `udp_idle_timeout_secs` 没有包时关闭（RFC 4787 要求 NAT 映射至少 2 分钟，默认 5 分钟）。设备关闭请求流时立刻关闭。

### 2.5 HTTP/3 细节

- 每个 QUIC 连接只有一个数据报读取者，按数据报里的 quarter stream ID 分给对应的 UDP 流。
- 已知非 UDP 请求收到 HTTP Datagram 时，以 `H3_DATAGRAM_ERROR` 复位请求；已关闭流的数据报丢弃。
- **提前到达的数据报**：RFC 9298 §5 允许设备发出请求后、收到回应前就开始发 UDP 包（比如 QUIC 的第一个包）。这时中继可能还在认证，数据报找不到对应的流。每个连接暂存最多 64 个这样的数据报，流建立时交给它，其余的按先进先出丢掉。
- 每个请求在自己的任务里解析和处理，慢请求不会挡住同一连接上的其他请求。
- 传输参数：最多 1024 个并发双向流（一个设备的每个 TCP 连接都是一个流）；单流接收窗口 4 MiB、连接 32 MiB；数据报收发缓冲各 4 MiB；空闲超时 300 秒（实际取双方较小值）。
- **初始 MTU 1350**：被转发的 QUIC 包至少 1200 字节（RFC 9000 §14.1），加上外层的 QUIC 头、DATAGRAM 帧和上下文 ID，需要约 1250 字节的 UDP 负载；QUIC 默认的初始值 1200 装不下。1350 在常见的 1500、1492 字节路径上都没问题，之后路径 MTU 探测会继续往上调。
- UDP 套接字申请 8 MiB 的收发缓冲；内核上限太小时日志提示，`deploy/99-network-relay.conf` 调大上限。

### 2.6 HTTP/2 细节

- `SETTINGS_ENABLE_CONNECT_PROTOCOL`（RFC 8441），否则设备不能发 CONNECT-UDP。
- 最多 1024 个并发流；单流接收窗口 4 MiB、连接窗口 32 MiB；每 30 秒一次 PING，20 秒没回应就断开。HTTP/2 和 HTTP/3 的请求头上限均为 32 KiB。
- TLS 同时提供 HTTP/2 和 HTTP/1.1（ALPN），并允许 TLS 1.2，和普通网站一样。HTTP/3 只用 TLS 1.3。

## 3. 认证

- 服务器只保存 Argon2id 哈希（默认参数：19 MiB、2 轮，OWASP 的建议）。`network-relay passwd` 生成 144 位随机密码，在线猜不中，所以不需要封锁 IP 或账号。
- **缓存**：设备几乎每建一个连接就发一个请求，每个都带同样的凭据，而一次 Argon2id 验证要几十毫秒。所以验证结果按请求头缓存：成功的 10 分钟、失败的 1 分钟（防止密码错的设备反复消耗 CPU）。缓存的键是请求头的 HMAC-SHA256（每次启动随机密钥），内存里不存密码。同一个请求头同时来多个请求时，只算一次哈希，其余等结果。缓存最多 4096 条。
- 用户列表变化（reload）时清空缓存，并通知所有正在转发的连接检查自己的用户是否还有效，无效的立刻断开。正在验证的旧结果不能重新写入缓存或通过认证；在解析目标、建连前订阅变更，建连后和转发开始时再次检查用户，防止错过撤销。
- 同时进行的哈希计算数有上限（CPU 核数的 2 倍），取消 HTTP 请求不会提前释放仍在计算的名额。等待认证的不同凭据最多 4096 项，取消后清理；这不等于服务器总连接数限制。
- 用户名不存在时也算一次哈希（对一个随机哈希），响应时间不暴露哪些用户名存在。

## 4. 伪装

- 没有有效凭据的请求（包括所有 CONNECT 和 Upgrade）得到网站的回答。CONNECT 的 2xx 表示“隧道已建立”，所以 CONNECT 得到 404 加首页。
- 不存在的路径返回首页（单页应用的常见做法），所以探测不到“这里有个特殊路径”。`/.well-known/` 例外，回空的 404。
- TCP 上的回应带 `Alt-Svc: h3=":443"`，和提供 HTTP/3 的网站一样。
- 状态码 403、502、503 等和 `Proxy-Status` 只有通过认证的请求才会看到。

## 5. 安全考虑

- **SSRF / 访问内网**：默认禁止访问本机、私有网络、云服务商元数据等（`blocked_destinations`），域名解析出的每个地址都查，防 DNS 重绑定。IPv4 映射的 IPv6 地址按 IPv4 查，NAT64 本地前缀也在默认列表里。
- **滥用**：默认封 25 端口；`max_tunnels` 限制总转发数；UDP 流空闲关闭。
- **中继循环**：设备可以让中继连中继自己（公网地址），但每一层都要认证，不会被未认证的人利用。
- **权限**：systemd 下以 root 启动只为读私钥，能力只保留 `CAP_NET_BIND_SERVICE`，文件系统只读等。
- **日志**：不记录密码；`log_requests` 只显示 Basic 凭据里的用户名；客户端提供的用户名转义后记录。
- **描述文件**：里面有明文的 Basic 凭据（这是苹果的格式决定的）。`--publish` 用 144 位随机文件名；保存、发布和覆盖都通过权限 600 的文件原子替换，拒绝符号链接目标。安装后删除发布文件并 reload，清除网站内存中的副本。

## 6. 代码结构

单个 crate，一个程序 `network-relay`，四个子命令（`serve`、`passwd`、`profile`、`check`）。

| 模块 | 内容 |
|---|---|
| `proto/` | 变长整数、胶囊、数据报格式、URI 模板。不做 I/O，全部单元测试。从 masque-vpn 复制后改成 CONNECT-UDP 的语义 |
| `config` | 配置文件和校验 |
| `auth` | Basic 认证、Argon2id、验证缓存、用户变化通知 |
| `policy` | 目标的解析和检查、拒绝原因和 Proxy-Status |
| `connect` | Happy Eyeballs 的 TCP 连接、UDP 套接字 |
| `tunnel` | 与 HTTP 版本无关的 CONNECT-UDP 请求流（数据报和胶囊） |
| `server/` | `mod.rs`：请求分类、认证、打开目标、连接统计、reload、`run`；`over_h3.rs`：QUIC 和 HTTP/3，数据报分发；`over_tcp.rs`：HTTP/2 和 HTTP/1.1；`h2_stream.rs`：HTTP/2 字节流、流控和显式复位；`pump.rs`：TCP 和 UDP 的数据搬运 |
| `web` | 伪装网站 |
| `certs`、`tls` | 证书读取、定时重新读取、rustls 配置 |
| `profile`、`private_file` | 生成 `.mobileconfig`，以私密权限原子保存 |
| `check` | 自检客户端（HTTP/3、HTTP/2、HTTP/1.1），集成测试也用它 |
| `logging` | 日志（可选按小时分文件） |
| `sys` | 打开文件数、套接字选项 |

`auth`、`certs`、`tls`、`web`、`logging` 和 `proto` 最初从 [masque-vpn](https://github.com/ArcCal/masque-vpn) 复制过来再修改。两个项目不共享代码，各自独立发布。

依赖：tokio、quinn（QUIC）、h3 / h3-quinn / h3-datagram（HTTP/3，固定在一个带 CONNECT-UDP 支持的提交上）、h2（HTTP/2 服务端）、hyper（HTTP/1.1 服务端及 HTTP 客户端）、rustls（ring）、argon2。

`h3`、`h3-quinn` 在 `vendor/` 保留同一上游提交的源码和许可证，并只修补帧校验及空闲取消通知。具体差异与移除条件见各目录的 `PATCH.md`。它们没有替换为不同的协议实现。

## 7. 互通测试

自动化集成测试通过真实 TLS/QUIC 连接检查 TCP/UDP 往返、半关闭、撤销和并发，还检查 HTTP/2 `CONNECT_ERROR` / `PROTOCOL_ERROR`、HTTP/3 `H3_DATAGRAM_ERROR`、未协商数据报时的 Capsule 回退、大型未知 Capsule 和空 UDP 负载。禁止分片的自动化检查读取 IPv4/IPv6 套接字选项，尚未覆盖低 MTU 链路抓包。

最近一次完整复查的方法、规范来源和可复现结果见 [复查记录](review-2026-10-01.md)。下面保留初版的历史互通记录，不将历史结果等同于本轮重新验证。

除了 `cargo test`，发布前手动做了下面的测试（中继在本机 `relay.test:8443`，私有 CA）：

**curl（HTTP/1.1 和 HTTP/2 的 CONNECT，凭据在 `Proxy-Authorization`）：**

```bash
curl --noproxy '' -p -x https://relay.test:8443 --proxy-cacert ca.pem \
  --resolve relay.test:8443:127.0.0.1 --proxy-user alice:密码 http://127.0.0.1:18080/
curl ... --proxy-http2 ...
```

结果：两种版本都拿到网页；错误密码得到 `CONNECT tunnel failed, response 404`；25 端口和 `10.0.0.0/8` 得到 403。

**quic-go masque-go v0.6.0（HTTP/3 的 CONNECT-UDP，凭据在 `Authorization`）：** 一个小的 Go 程序用 `masque.Transport` 连中继，经 UDP 回显服务收发数据报。

结果：60、1200、1300 字节的数据报各几百个全部原样返回；回应带 `Capsule-Protocol: ?1`；错误密码或没有凭据得到 404；`10.0.0.1:53` 得到 403 和 `Proxy-Status: network-relay; error=destination_ip_prohibited`。

**`network-relay check`**：本地目标和真实互联网（经中继访问 `example.com:80`、向 `1.1.1.1:53` 查询 DNS）在三种 HTTP 版本上全部通过。

**权限**：用 `setpriv` 只保留 `CAP_NET_BIND_SERVICE`，中继能读 600 权限的私钥并在 443 端口正常工作。

**还没做的**：真实 iPhone、Mac 的测试。

## 8. 以后可能做的

- 在真机上验证后，按设备的实际行为调整（`log_requests` 就是为此准备的）。
- `connect-tcp`（[draft-ietf-httpbis-connect-tcp](https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/)）：设备开始使用时再加。目前用的 h3 库不认识这个 `:protocol`，需要先改库。
- 客户端证书认证（描述文件的 `PayloadCertificateUUID`）。
- 每个用户的连接数上限、流量统计。
- 成功回应里带 `Proxy-Status` 的 `next-hop`（实际连接的地址）。

## 参考

- Apple：[Relay 负载](https://developer.apple.com/documentation/devicemanagement/relay)、[apple/device-management](https://github.com/apple/device-management)、[Use network relays](https://support.apple.com/guide/deployment/use-network-relays-dep91a6e427d/web)、[Relay payload settings](https://support.apple.com/guide/deployment/relay-payload-settings-dep131693e6b/web)、[NERelay](https://developer.apple.com/documentation/networkextension/nerelay)、[Relays](https://developer.apple.com/documentation/networkextension/relays)、[WWDC23 10002](https://developer.apple.com/videos/play/wwdc2023/10002/)
- jedda：[Beneath the MASQUE](https://jedda.me/beneath-the-masque-network-relay-on-apple-platforms/)、[Envoy 配置](https://gist.github.com/jedda/62643893faffd9143f9587a12ca1db38)
- IETF：RFC 9298、9297、9110、9113、9114、8441、9220、9209、8305、6570、7617、9106、8615、4787；[draft-ietf-intarea-proxy-config](https://datatracker.ietf.org/doc/draft-ietf-intarea-proxy-config/)；[draft-ietf-httpbis-connect-tcp](https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/)
