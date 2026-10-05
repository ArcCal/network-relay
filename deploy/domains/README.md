# Google, AI and X domain preset

`google-ai-social.txt` is used to generate Apple's `MatchDomains`: each line matches a domain and its subdomains, and connections that do not match are not relayed by this configuration. Keep the match list non-empty; do not use an empty list to mean "everything direct", because Apple reads an empty match list as exactly the opposite.

It covers Google/Gemini sign-in and common resources, Gmail, Drive, Photos, Maps and YouTube; Claude, including artifacts/MCP content; X/Twitter/Grok; and OpenAI/ChatGPT/Sora with the common voice endpoints. Including ChatGPT is a choice made for this general AI preset; services you do not need can be removed as a group.

On 2026-10-01 the service endpoints were selected by comparison with the `google`, `youtube`, `anthropic`, `twitter`, `xai` and `openai` data in [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/2d71342eea1720da57261b55663c9d55619e9b1c/data). The source is community-maintained domain data, **not an official allowlist that the vendors guarantee to be complete**; attempts to read Google's and Claude's official help pages returned 403 from the environment used. The MIT license of the source data is kept in `LICENSE.domain-list-community`.

The whole Google corporate asset list and the ad lists were not imported, and none of `cloudflare.com`, `amazonaws.com`, `azure.com`, `appspot.com` or `livekit.cloud` is relayed as a whole. Only clear service domains and a few specific CDN/voice hosts were added. Apple's MatchDomains does not support the regular expressions in the community rules, so the regular expression for ChatGPT's dynamic Azure WebPubSub hosts was not crudely widened to the whole Azure domain.

Domains change, and this is not a complete per-app list obtained by capturing each release's traffic. Only the common Google regional domains are listed; redirects for other regions, payment flows or dynamic third-party endpoints may still need to be added. If a feature does not go through the relay, temporarily enable `debug.log_requests` on the server, check the domains against what the device actually connects to, and add the narrowest rule that works.

This is **domain-based routing**, not app-based routing: other apps that use the same Google APIs, shared verification codes or CDNs also match. Targeting only one app without affecting others needs a separate device-management configuration. This preset also does not override routing rules that other VPNs or proxies on the device already have.

After editing, regenerate the profile and install it; an existing profile is not updated automatically when the text file changes. During installation you can pass `--domains your-list.txt`; when importing a ready-made file with `--profile`, the rules in that file apply.

## Global services + gfwlist profile

`global-services.txt` (Meta AI/Instagram, Spotify, Pandora, NYT, Wikipedia, YouTube Music and others), together with `google-ai-social.txt` and the [gfwlist](https://github.com/gfwlist/gfwlist), can be turned into one profile with `deploy/global-profile.py`:

```bash
cargo build --release
python3 deploy/global-profile.py --host relay.example.com --user iphone
```

- Without `--password` the password is prompted for and passed to `network-relay profile` on standard input, so it does not appear in the process list.
- The gfwlist is downloaded when the script runs (`--gfwlist-url` changes the source, `--gfwlist-file` uses a local file, `--no-gfwlist` skips it); the list itself is not in the repository. Both the official base64 version and the plain-text version can be read.
- Apple's `MatchDomains` can only hold domain names: regular expressions, IP addresses and `@@` exception rules in the gfwlist are dropped, and a rule limited to a URL path relays its whole domain; the script prints how many of each kind there were when it finishes. Subdomains whose parent domain is already listed are merged.
- The relay's own domain goes into `ExcludedDomains`. `--ui-toggle-enabled` defaults to `false` (the relay cannot be turned off in Settings on the device, iOS/macOS 26+); the profile itself can still be removed.
- After updating the service lists or the gfwlist, run the script again and reinstall; a new profile for the same domain and user replaces the old one.
- The profile contains the password in recoverable form. It is ignored by `.gitignore`; do not commit it or pass it around.
