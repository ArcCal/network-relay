# Google、AI 和 X 分流预设

`google-ai-social.txt` 用于生成 Apple `MatchDomains`：每行匹配域名及其子域名，未匹配的连接不由这份中继配置代理。保留非空匹配表；不要用空表表示“全部直连”，因为 Apple 对空匹配表的含义恰好相反。

覆盖 Google/Gemini 登录及常用资源、Gmail、Drive、Photos、Maps、YouTube，Claude 及 artifacts/MCP 内容，X/Twitter/Grok，OpenAI/ChatGPT/Sora 及常用语音端点。列入 ChatGPT 是这份通用 AI 分流预设的选择；不需要的服务可以整组删除。

2026-10-01 对照 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/2d71342eea1720da57261b55663c9d55619e9b1c/data) 的 `google`、`youtube`、`anthropic`、`twitter`、`xai`、`openai` 数据，筛选服务端点。来源是社区维护的域名数据，**不是各厂商保证完整的官方白名单**；尝试读取 Google/Claude 官方帮助页面时，当前环境返回 403。源数据的 MIT 许可证保留在 `LICENSE.domain-list-community`。

没有导入整个 Google 企业资产表、广告表，也没有让整个 `cloudflare.com`、`amazonaws.com`、`azure.com`、`appspot.com` 或 `livekit.cloud` 走代理。仅加入明确的服务域名和若干具体 CDN/语音主机。Apple MatchDomains 不支持社区规则中的正则表达式，因此没有将 ChatGPT 动态 Azure WebPubSub 的正则粗暴扩大成整个 Azure 域名。

域名会变更，这不是逐版本抓包得到的 App 全量清单。Google 的区域域名只列出常用项；其他地区的跳转、付费流程或动态第三方端点可能还需补充。若某项功能没有走中继，可临时启用服务器 `debug.log_requests`，结合设备实际连接检查域名，再增加最小范围的规则。

这是**域名分流**，不是 App 身份分流：其他 App 使用相同 Google API、共享验证码或 CDN 时也会匹配。只指定某个 App 而不影响其他 App，需要另外的设备管理配置。本预设也不会覆盖设备上其他 VPN/代理已有的路由规则。

修改后重新生成 profile 并安装；已有 profile 不会因文本文件变化自动更新。安装时可用 `--domains 自己的列表.txt`；如果通过 `--profile` 导入现成文件，则以该文件内的规则为准。
