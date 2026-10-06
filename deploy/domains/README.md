# Google, AI and X domain preset

`google-ai-social.txt` is a base list for Apple's `MatchDomains`. The automatic installer combines it with gfwlist, widens all names to registered roots using `public-suffix-icann.dat`, then deduplicates. Each resulting root and its subdomains matches. Private hosting suffixes are ignored, so the final scope deliberately includes entire shared hosting/CDN domains. The `adult` suffix and its domains are removed. Each profile stays below 524288 bytes; oversized lists are refused, never split. The relay's own hostname is excluded. Keep the match list non-empty; Apple treats an empty list as matching all traffic.

It covers Google/Gemini sign-in and common resources, Gmail, Drive, Photos, Maps and YouTube; Claude, including artifacts/MCP content; X/Twitter/Grok; and OpenAI/ChatGPT/Sora with the common voice endpoints. Including ChatGPT is a choice made for this general AI preset; services you do not need can be removed as a group.

On 2026-10-01 the service endpoints were selected by comparison with the `google`, `youtube`, `anthropic`, `twitter`, `xai` and `openai` data in [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/2d71342eea1720da57261b55663c9d55619e9b1c/data). The source is community-maintained domain data, **not an official allowlist that the vendors guarantee to be complete**; attempts to read Google's and Claude's official help pages returned 403 from the environment used. The MIT license of the source data is kept in `LICENSE.domain-list-community`.

The raw Google/AI/X preset selects specific service and resource hosts, rather than all corporate assets or ads. The root-domain installer intentionally widens these names: for example specific Azure storage hosts become `windows.net`, and `challenges.cloudflare.com` becomes `cloudflare.com`. That wider scope is a routing choice; it can include services unrelated to the named apps.

Domains change, and this is not a complete per-app list obtained by capturing each release's traffic. Only the common Google regional domains are listed; redirects for other regions, payment flows or dynamic third-party endpoints may still need to be added. If a feature does not go through the relay, temporarily enable `debug.log_requests` on the server, check the domains against what the device actually connects to, and add the narrowest rule that works.

This is **domain-based routing**, not app-based routing: other apps that use the same Google APIs, shared verification codes or CDNs also match. Targeting only one app without affecting others needs a separate device-management configuration. This preset also does not override routing rules that other VPNs or proxies on the device already have.

After editing, regenerate the profile and install it; an existing device profile is not updated automatically. During installation `--domains your-list.txt` changes the base list; downloaded gfwlist is still merged unless explicitly disabled. The standalone script refreshes routing profiles on rerun while preserving credentials. See [the deployment guide](../../docs/deploy-debian13.md).

## Global services + gfwlist profile

`global-services.txt` (Meta AI/Instagram, Spotify, Pandora, NYT, Wikipedia, YouTube Music and others), together with `google-ai-social.txt` and the [gfwlist](https://github.com/gfwlist/gfwlist), can be turned into one profile with `deploy/global-profile.py`:

```bash
python3 deploy/global-profile.py --host relay.example.com --user iphone --binary /usr/local/bin/network-relay
```

- Without `--password` the password is prompted for and passed to `network-relay profile` on standard input, so it does not appear in the process list.
- The gfwlist is downloaded when the script runs (`--gfwlist-url` changes the source, `--gfwlist-file` uses a local file, `--no-gfwlist` skips it); the list itself is not in the repository. Both the official base64 version and the plain-text version can be read.
- Apple's `MatchDomains` can only hold domain names: regular expressions, IP addresses and `@@` exception rules in the gfwlist are dropped, and a rule limited to a URL path relays its whole domain; the script prints how many of each kind there were when it finishes. Subdomains whose parent domain is already listed are merged.
- The relay's own domain goes into `ExcludedDomains`. `--ui-toggle-enabled` defaults to `true` (iOS/macOS 26+).
- After updating the service lists or the gfwlist, run the script again and reinstall; a new profile for the same domain and user replaces the old one.
- The profile contains the password in recoverable form. It is ignored by `.gitignore`; do not commit it or pass it around.

This separate tool uses the listed service domains and gfwlist. The automatic installer applies root-domain normalization and excludes `.adult`; it does not include Loyalsoldier proxy.txt. `public-suffix-icann.dat` is the ICANN section of the official Public Suffix List, fetched 2026-10-06, version `2026-10-01_23-02-52_UTC`, commit `6cd82aff889e3d64e5e03bc5c1f43da1934a960a`; its MPL-2.0 notice is retained. It is bundled to avoid another deployment-time download.
