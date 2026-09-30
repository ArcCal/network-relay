# 版本记录

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
