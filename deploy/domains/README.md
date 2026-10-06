# Google, AI, X and selected GreatFire domains

`google-ai-social.txt` is a base list for Apple's `MatchDomains`. The automatic installer combines it with gfwlist and eighteen blackmatrix7 service lists, widens all names to registered roots using `public-suffix-icann.dat`, then deduplicates. Each resulting root and its subdomains matches. Private hosting suffixes are ignored, so the final scope deliberately includes entire shared hosting/CDN domains. The `adult` suffix and its domains are removed. Each profile stays below 524288 bytes; oversized lists are refused, never split. The relay's own hostname is excluded. Keep the match list non-empty; Apple treats an empty list as matching all traffic.

It covers Google/Gemini sign-in and common resources, Gmail, Drive, Photos, Maps and YouTube; Claude, including artifacts/MCP content; X/Twitter/Grok; and OpenAI/ChatGPT/Sora with the common voice endpoints. Including ChatGPT is a choice made for this general AI preset; services you do not need can be removed as a group.

On 2026-10-01 the service endpoints were selected by comparison with the `google`, `youtube`, `anthropic`, `twitter`, `xai` and `openai` data in [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/2d71342eea1720da57261b55663c9d55619e9b1c/data). The source is community-maintained domain data, **not an official allowlist that the vendors guarantee to be complete**; attempts to read Google's and Claude's official help pages returned 403 from the environment used. The MIT license of the source data is kept in `LICENSE.domain-list-community`.

The Google/AI/X preset selects service and resource hosts, and includes the user-selected GreatFire roots. The root-domain installer intentionally widens these names: for example specific Azure storage hosts become `windows.net`, and `challenges.cloudflare.com` becomes `cloudflare.com`. That wider scope is a routing choice; it can include services unrelated to the named apps.

Domains change, and this is not a complete per-app list obtained by capturing each release's traffic. The Google rule source supplies its listed regional domains; redirects for other regions, payment flows or dynamic third-party endpoints may still need to be added. If a feature does not go through the relay, temporarily enable `debug.log_requests` on the server, check the domains against what the device actually connects to, and add the narrowest rule that works.

This is **domain-based routing**, not app-based routing: other apps that use the same Google APIs, shared verification codes or CDNs also match. Targeting only one app without affecting others needs a separate device-management configuration. This preset also does not override routing rules that other VPNs or proxies on the device already have.

After editing, regenerate the profile and install it; an existing device profile is not updated automatically. During installation `--domains your-list.txt` changes the base list; downloaded gfwlist and all eighteen service lists are still merged unless explicitly disabled. The standalone script refreshes routing profiles on rerun while preserving credentials. See [the deployment guide](../../docs/deploy-debian13.md).

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

Both generators use their base lists, gfwlist and the eighteen service lists. Both apply root-domain normalization, exclude `.adult`, and enforce the single-file 524288-byte limit. Neither includes Loyalsoldier proxy.txt. `public-suffix-icann.dat` is the ICANN section of the official Public Suffix List, fetched 2026-10-06, version `2026-10-01_23-02-52_UTC`, commit `6cd82aff889e3d64e5e03bc5c1f43da1934a960a`; its MPL-2.0 notice is retained. It is bundled to avoid another deployment-time download.

On 2026-10-06, the 40 domains supplied by the user from GreatFire’s “Most blocked sites (all time)” list were merged into this preset. The counts describe GreatFire tests, not subdomains that need separate rules. The installer normalizes and deduplicates these names with gfwlist; shared hosting roots intentionally include every tenant.

## blackmatrix7 service rule sources

Both the installer and global-profile.py request the following URLs anew on each profile generation, without reusing local download caches. Both standalone installation modes automatically generate a profile on every normal run. Only explicit DOMAIN and DOMAIN-SUFFIX entries are extracted. IP/CIDR, ASN, keyword, regex and process rules are discarded and counted; they never enter MatchDomains. Domain entries are widened to registered roots and deduplicated with all other sources. `--rules-dir` selects local copies of all eighteen YAML files, while `--no-service-rules` explicitly skips them. A missing, malformed or empty list aborts rather than silently generating a partial profile.

- [Cloudflare](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Cloudflare/Cloudflare.yaml)
- [Gemini](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Gemini/Gemini.yaml)
- [OpenAI](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml)
- [Anthropic](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Anthropic/Anthropic.yaml)
- [Google](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Google/Google.yaml)
- [GitHub](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/GitHub/GitHub.yaml)
- [Twitter](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Twitter/Twitter.yaml)
- [Jsdelivr](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Jsdelivr/Jsdelivr.yaml)
- [Pandora](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Pandora/Pandora.yaml)
- [Spotify](https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml) (raw YAML corresponding to the supplied GitHub page)
- [Reddit](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Reddit/Reddit.yaml)
- [Discord](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Discord/Discord.yaml)
- [iCloudPrivateRelay](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/iCloudPrivateRelay/iCloudPrivateRelay.yaml)
- [Claude](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Claude/Claude.yaml)
- [AppleNews](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AppleNews/AppleNews.yaml)
- [AppleProxy](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AppleProxy/AppleProxy.yaml)
- [TikTok](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TikTok/TikTok.yaml)
- [TigerFintech](https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TigerFintech/TigerFintech.yaml)
