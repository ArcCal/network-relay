# Google、AI 和 X 分流预设

`google-ai-social.txt` 用于生成 Apple `MatchDomains`：每行匹配域名及其子域名，未匹配的连接不由这份中继配置代理。保留非空匹配表；不要用空表表示“全部直连”，因为 Apple 对空匹配表的含义恰好相反。

覆盖 Google/Gemini 登录及常用资源、Gmail、Drive、Photos、Maps、YouTube，Claude 及 artifacts/MCP 内容，X/Twitter/Grok，OpenAI/ChatGPT/Sora 及常用语音端点。列入 ChatGPT 是这份通用 AI 分流预设的选择；不需要的服务可以整组删除。

2026-10-01 对照 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/2d71342eea1720da57261b55663c9d55619e9b1c/data) 的 `google`、`youtube`、`anthropic`、`twitter`、`xai`、`openai` 数据，筛选服务端点。来源是社区维护的域名数据，**不是各厂商保证完整的官方白名单**；尝试读取 Google/Claude 官方帮助页面时，当前环境返回 403。源数据的 MIT 许可证保留在 `LICENSE.domain-list-community`。

没有导入整个 Google 企业资产表、广告表，也没有让整个 `cloudflare.com`、`amazonaws.com`、`azure.com`、`appspot.com` 或 `livekit.cloud` 走代理。仅加入明确的服务域名和若干具体 CDN/语音主机。Apple MatchDomains 不支持社区规则中的正则表达式，因此没有将 ChatGPT 动态 Azure WebPubSub 的正则粗暴扩大成整个 Azure 域名。

域名会变更，这不是逐版本抓包得到的 App 全量清单。Google 的区域域名只列出常用项；其他地区的跳转、付费流程或动态第三方端点可能还需补充。若某项功能没有走中继，可临时启用服务器 `debug.log_requests`，结合设备实际连接检查域名，再增加最小范围的规则。

这是**域名分流**，不是 App 身份分流：其他 App 使用相同 Google API、共享验证码或 CDN 时也会匹配。只指定某个 App 而不影响其他 App，需要另外的设备管理配置。本预设也不会覆盖设备上其他 VPN/代理已有的路由规则。

修改后重新生成 profile 并安装；已有 profile 不会因文本文件变化自动更新。安装时可用 `--domains 自己的列表.txt`；如果通过 `--profile` 导入现成文件，则以该文件内的规则为准。

## 全球服务 + gfwlist 描述文件

`global-services.txt`（Meta AI/Instagram、Spotify、Pandora、NYT、Wikipedia、YouTube Music 等）加上 `google-ai-social.txt` 和 [gfwlist](https://github.com/gfwlist/gfwlist)，可以用 `deploy/global-profile.py` 生成一份描述文件：

```bash
cargo build --release
python3 deploy/global-profile.py --host relay.example.com --user iphone
```

- 密码不写 `--password` 时提示输入，并通过标准输入交给 `network-relay profile`，不出现在进程列表里。
- gfwlist 在运行时下载（`--gfwlist-url` 可换，`--gfwlist-file` 用本地文件，`--no-gfwlist` 不用）；列表本身不在仓库里。官方的 base64 版本和纯文本版本都能读。
- 苹果的 `MatchDomains` 只能写域名：gfwlist 里的正则、IP 和 `@@` 例外规则被丢弃，只限某个 URL 路径的规则会让整个域名走中继；脚本结束时打印各类的数量。父域名已在列表里的子域名会合并。
- 中继域名自己放进 `ExcludedDomains`。`--ui-toggle-enabled` 默认 `false`（设备上不能在设置里关闭，iOS/macOS 26+）；描述文件本身仍可删除。
- 更新服务列表或 gfwlist 后重新运行，并重新安装；同一域名和用户的新描述文件会替换旧的。
- 描述文件含明文密码，已被 `.gitignore` 忽略，不要提交或随意传递。
