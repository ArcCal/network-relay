# 配置参考

## 配置文件

默认位置 `/etc/network-relay/relay.toml`（`network-relay serve --config 路径` 可以换）。格式是 TOML。完整示例见 [`deploy/relay.example.toml`](../deploy/relay.example.toml)。

- 写错的项名会直接报错，不会被悄悄忽略。
- 改完先 `network-relay serve --check` 检查，再 `systemctl reload network-relay` 生效。
- 文件里有密码哈希，权限设成 `600`。

### 顶层

| 项 | 默认 | 说明 |
|---|---|---|
| `listen` | `"[::]:443"` | 监听的地址和端口。UDP 上是 HTTP/3，TCP 上是 HTTP/2 和 HTTP/1.1，同一个端口。`[::]` 同时接受 IPv4 和 IPv6。改了要 restart |
| `log_dir` | 不设 | 另外把日志存成文件的目录，必须是完整路径，比如 `"/var/log/network-relay"`。每小时一个文件，保留 24 小时。不设时日志只进 journal |

### `[tls]`（必填）

| 项 | 默认 | 说明 |
|---|---|---|
| `cert` | — | 证书链文件，certbot 的 `fullchain.pem` |
| `key` | — | 私钥文件，certbot 的 `privkey.pem` |
| `reload_interval_days` | 不设 | 每隔几天（1 到 7）重新读取证书文件。不设时每天凌晨 3 点（系统时区）读取。`systemctl reload` 也会立刻读取 |

证书上的名字必须是设备连接用的域名。读取新证书失败时（比如文件损坏）继续用旧的，并在日志里警告。证书 14 天内过期时，日志里也有警告。

### `[web]`（可选）

| 项 | 默认 | 说明 |
|---|---|---|
| `root` | — | 伪装网站的目录，里面必须有 `index.html` |
| `headers` | 无 | 额外的响应头，比如 `[web.headers]` 下写 `Content-Security-Policy = "default-src 'self'"` |

- 没有密码的请求都得到这个网站的回答：有的文件返回文件；不存在的路径返回 `index.html`（像单页应用那样）；CONNECT 请求返回 404 加 `index.html`。
- 例外：`/.well-known/` 下不存在的文件返回空的 404，因为这些路径有固定含义（RFC 8615）。
- 以 `.` 开头的文件和目录不对外提供，`.well-known` 目录除外。
- 文件软链接只允许指向网站内的公开文件；目录软链接不遍历。指向目录外或隐藏文件的链接不会发布。
- `headers` 中同名字段覆盖默认值；禁止设置 `Content-Length`、`Transfer-Encoding`、`Connection`、`Upgrade`、`Keep-Alive`、`Proxy-Connection`、`TE`、`Trailer`，这些字段由协议实现管理。
- 目录在启动和 reload 时整个读进内存（最多 1000 个文件、64 MiB），之后改了文件要 reload 才生效。
- 不设 `[web]` 时，所有这类请求一律 404。
- `.mobileconfig` 文件按描述文件的类型（`application/x-apple-aspen-config`）提供，Safari 打开时会提示安装。`network-relay profile --publish` 就是把描述文件放在这里。

### `[relay]`（可选）

| 项 | 默认 | 说明 |
|---|---|---|
| `udp_template` | `"/.well-known/masque/udp/{target_host}/{target_port}/"` | CONNECT-UDP 的 URI 模板里的路径部分（RFC 9298 §2）。必须包含 `{target_host}` 和 `{target_port}`，而且按它展开的请求必须能解析回原来的目标（例如查询里不带名字的 `?{target_host}` 解析不回来，会被拒绝）。描述文件必须用同一个模板（`network-relay profile --udp-template`）。一般不用改 |
| `blocked_destinations` | 见下 | 设备不能访问的地址段。域名解析出的每个地址都检查；IPv4 映射的 IPv6 地址（`::ffff:a.b.c.d`）按 IPv4 地址检查 |
| `blocked_ports` | `[25]` | 设备不能访问的端口，TCP 和 UDP 都算。25 是发邮件的端口，封掉防止服务器被用来发垃圾邮件 |
| `connect_timeout_secs` | `10` | 连接目标 TCP 服务的超时（1 到 120） |
| `udp_idle_timeout_secs` | `300` | UDP 流双向都没有数据多久后关闭（120 到 3600；RFC 4787 要求至少 2 分钟） |
| `max_tunnels` | `20000` | 所有用户加起来，同时转发的 TCP 连接和 UDP 流的上限。超过时新请求得到 503。改了要 restart |

`blocked_destinations` 的默认值：本机（`127.0.0.0/8`、`::1`）、未指定地址、私有网络（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`）、运营商级 NAT（`100.64.0.0/10`）、链路本地（`169.254.0.0/16`，包括云服务商的元数据服务 `169.254.169.254`；`fe80::/10`）、组播、保留地址、文档和测试用地址、IPv4 映射地址、本地用的 NAT64 前缀。完整列表见示例配置。

- 想让设备访问服务器所在的内网（比如家里的 NAS），把对应的段从列表里删掉。**不要整个清空**：那样设备能访问服务器本机上只监听 127.0.0.1 的服务。
- 被拒绝的请求返回 403，`Proxy-Status` 头里写明原因（`destination_ip_prohibited` 或 `http_request_denied`）。

### `[debug]`（可选）

| 项 | 默认 | 说明 |
|---|---|---|
| `log_requests` | `false` | 每个代理请求（CONNECT 或 Upgrade）记一行日志：HTTP 版本、方法、`:protocol`、目标、路径和所有请求头（`Authorization` 只显示用户名）。被拒绝的请求也记下原因。用来弄清楚设备实际发了什么；很吵，用完关掉 |

### `[[user]]`（可以有多个）

| 项 | 说明 |
|---|---|
| `name` | 用户名：1 到 64 个字母、数字、`-`、`_`、`.`，不能以 `.` 开头 |
| `password_hash` | `network-relay passwd` 打印的 Argon2id 哈希 |

- 每台设备一个用户，停用某台设备只删它的那段。
- reload 后，被删除或改了密码的用户，正在进行的连接立刻断开。
- 没有任何用户时，中继只是一个网站，启动时日志里有警告。

## reload 和 restart

| 改了什么 | 怎么生效 |
|---|---|
| `[[user]]`、`[relay]`（`max_tunnels` 除外）、`[debug]`、`[web]`、证书文件 | `systemctl reload network-relay`，已有连接不受影响（被删除的用户除外） |
| `listen`、`max_tunnels`、`log_dir`、`[tls]` 的文件路径和 `reload_interval_days` | `systemctl restart network-relay`，所有设备会断开并自动重连 |

配置解析或校验失败时，reload 不会生效，日志里写明原因。网站读取失败时保留旧网站，其他合法配置变更仍生效；证书更新失败时保留旧证书。

## 命令

所有命令都有 `--help`。

### `network-relay serve`

运行中继。systemd 用的就是它。

| 参数 | 说明 |
|---|---|
| `-c`、`--config 路径` | 配置文件，默认 `/etc/network-relay/relay.toml` |
| `--check` | 只检查配置、证书和网站能不能读，然后退出。证书已过期或尚未生效时报错（正常启动时只警告，好让之后的续期自动修复） |

环境变量 `RUST_LOG=debug` 可以看到更详细的日志（每个转发连接的开始和结束）。

### `network-relay passwd`

生成一个用户：随机密码（144 位随机数）和它的哈希。

| 参数 | 说明 |
|---|---|
| `--name 名字` | 用户名 |
| `--stdin` | 不生成随机密码，从标准输入读取你自己的密码（至少 12 个字符） |

### `network-relay profile`

生成给 iPhone、iPad、Mac 用的描述文件（`.mobileconfig`）。

| 参数 | 说明 |
|---|---|
| `--host 域名` | 中继的域名（证书上的名字） |
| `--user 名字` | 用户名 |
| `--password 密码` | 密码；不写时运行后提示输入（推荐，不会留在 shell 历史里） |
| `--port 端口` | 不是 443 时写 |
| `--match-domain 域名` | 这个域名和它的子域名走中继。可以写多个；它和 `--match-fqdn` 都不写时，全部流量走中继（排除项除外） |
| `--exclude-domain 域名` | 这个域名和它的子域名不走中继。可以写多个 |
| `--match-fqdn 主机名` | 只有精确匹配的主机名走中继，不包含其子域名。可以写多个；iOS 18.4、macOS 15.4 起支持 |
| `--exclude-fqdn 主机名` | 精确排除这个主机名，不包含其子域名。可以写多个；iOS 18.4、macOS 15.4 起支持 |
| `--ui-toggle-enabled [true/false]` | 是否允许用户在设置里停用中继；iOS/macOS 26 起支持。不写时使用系统默认值 `true`，只写开关相当于 `true` |
| `--allow-dns-failover [true/false]` | 是否允许设备回退到默认系统 DNS 解析器；iOS/macOS 26 起支持。不写时使用系统默认值 `false`，只写开关相当于 `true` |
| `--relay-uuid UUID` | 指定托管 App 路由所用的 Relay UUID；用户注册（user enrollment）需要此字段。须与 MDM 的 App 关联配置一致；Apple 未在 macOS 上提供此字段 |
| `--name 名称` | 在设置里显示的名字，默认是域名 |
| `--udp-template 路径` | 改过 `relay.udp_template` 时写同样的值 |
| `--no-http3` | 只用 HTTP/2（TCP）。UDP 被封的网络里可以试 |
| `--no-http2` | 只用 HTTP/3 |
| `-o`、`--out 文件` | 保存到这个文件，默认 `域名-用户名.mobileconfig`（权限 600） |
| `--publish` | 放进 `[web] root` 目录，文件名随机、权限 600，并打印下载链接。要 `systemctl reload` 后才能下载；装好后删掉并再次 reload |
| `--config 路径` | `--publish` 读哪个配置文件，默认 `/etc/network-relay/relay.toml` |

描述文件的内容：

- 一个 `com.apple.relay.managed` 负载（iOS 17、macOS 14 起，可以手动安装，不需要监管）。
- `HTTP3RelayURL` 和 `HTTP2RelayURL` 都是 URI 模板，比如 `https://relay.qolita.com/.well-known/masque/udp/{target_host}/{target_port}/`。
- `AdditionalHTTPHeaderFields` 里是 `Authorization: Basic ...`，设备每个请求都会带上。**所以描述文件里有密码**，不要随便传给别人。
- 标识符由域名和用户名用点拼接而成：同一域名、同一用户重新生成的描述文件，安装时会替换旧的。所以用户名里的点可能和域名“接上”：域名 `relay.example` 加用户 `com.alice`，与域名 `relay.example.com` 加用户 `alice` 得到同一个标识，后装的会替换先装的。给同一台设备装多个中继时，用户名不要用这种以点分段的形式。（为了让已装的描述文件仍能被替换，标识的拼法保持不变。）
- 新选项只有在显式指定时才写入描述文件。请按设备版本选择：例如仅使用 `--match-fqdn` 的配置不适用于不支持该字段的旧系统。域名统一转成小写并去掉末尾的点。
- DNS 回退允许设备使用本地网络的系统 DNS；希望 DNS 始终经过中继时，保留默认值。
- 保存和覆盖均采用权限 600 的临时文件原子替换，拒绝覆盖符号链接。以运行中继服务的用户生成发布文件，保证服务能读取它。

例如，只中继 `api.example.com`，同时允许用户手动停用（设备需要 iOS/macOS 26 或更新）：

```bash
network-relay profile --host relay.example.com --user iphone --match-fqdn api.example.com --ui-toggle-enabled true
```

### `network-relay check`

像设备一样测试一个正在运行的中继：HTTP/3、HTTP/2、HTTP/1.1 上各测一次 TCP（经 CONNECT 请求一个网页）和 UDP（经 CONNECT-UDP 查一次 DNS），再确认没有密码时 CONNECT 得到 404。全部通过时退出码是 0。

| 参数 | 默认 | 说明 |
|---|---|---|
| `--server 域名` | — | 中继的域名 |
| `--address IP` | 解析域名 | 直接连这个 IP（可以写多个） |
| `--port 端口` | `443` | |
| `--user 名字` | — | |
| `--password 密码` | 提示输入 | |
| `--tcp-target 主机:端口` | `example.com:80` | 经 TCP 中继访问的网站（发一个 HTTP 请求，显示第一行回答） |
| `--udp-target 主机:端口` | `1.1.1.1:53` | 经 UDP 中继查询的 DNS 服务器 |
| `--dns-name 域名` | `example.com` | 查询的域名 |
| `--udp-template 路径` | 默认模板 | 改过 `relay.udp_template` 时写同样的值 |
| `--ca 文件` | 系统根证书 | 只信任这个 CA（测试用） |
| `--timeout 秒` | `10` | 每一步的超时 |
