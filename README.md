# IP Pools

Curated IP CIDR and domain lists of popular services, maintained for firewall
policies, network allowlists and routing rules.

One folder per service. Network lists use an `ipset hash:net`-compatible format.

## Lists

| Service | Networks (CIDR IPv4) | Domains |
| --- | --- | --- |
| WhatsApp | [WhatsApp/whatsapp_cidr_ipv4.txt](WhatsApp/whatsapp_cidr_ipv4.txt) | — |
| Cursor | [Cursor/cursor_cidr_ipv4.txt](Cursor/cursor_cidr_ipv4.txt) | [Cursor/cursor_domains.txt](Cursor/cursor_domains.txt) |
| Cursor — git egress proxy¹ | [Cursor/cursor_git_egress_proxy_ipv4.txt](Cursor/cursor_git_egress_proxy_ipv4.txt) | — |
| Cursor — Origin¹ | [Cursor/cursor_origin_ipv4.txt](Cursor/cursor_origin_ipv4.txt) | — |
| OpenAI / ChatGPT | [OpenAI/openai_cidr_ipv4.txt](OpenAI/openai_cidr_ipv4.txt) | [OpenAI/openai_domains.txt](OpenAI/openai_domains.txt) |
| OpenAI — 3rd party² | [OpenAI/openai_3rd_party_cidr_ipv4.txt](OpenAI/openai_3rd_party_cidr_ipv4.txt) | [OpenAI/openai_3rd_party_domains.txt](OpenAI/openai_3rd_party_domains.txt) |

¹ These are **outbound** addresses of Cursor Cloud Agents (traffic *from* Cursor
*to* your infrastructure), not service endpoints. Allowlist them if Cursor agents
must reach your git hosts; they are not required for firewall rules covering
traffic to Cursor services.

² Third-party dependencies used by ChatGPT (SendGrid, Intercom, WorkOS,
Cloudflare, Apple, Stripe, Sentry, Datadog). Not owned by OpenAI — kept as a
separate group so it can be disabled independently.

Raw URLs for automation:

```
https://raw.githubusercontent.com/<user>/<repo>/main/WhatsApp/whatsapp_cidr_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_cidr_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_domains.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_git_egress_proxy_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_origin_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_cidr_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_domains.txt
https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_3rd_party_cidr_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_3rd_party_domains.txt
```

## Sources

- **WhatsApp** — synced from [HybridNetworks/whatsapp-cidr](https://github.com/HybridNetworks/whatsapp-cidr) (official Meta networks).
- **Cursor** — official domains from the [Cursor documentation](https://cursor.com/docs/cloud-agent/security-network), resolved via public DoH resolvers (Google + Cloudflare). Domains without A records at the last check (`api5.cursor.sh`, `authentication.cursor.sh`, `cursorapi.com`) are kept in the domain list in case they appear. The `*.api5.cursor.sh` and `*.authentication.cursor.sh` entries are subdomain masks for domain-based rules (Cursor does not publish a DNS wildcard, so they do not resolve directly).
- **Cursor — git egress proxy** — merged from the [documentation](https://cursor.com/docs/cloud-agent/security-network) and the official API [cursor.com/docs/ips.json](https://cursor.com/docs/ips.json). Active addresses are verified against the API; the remaining ones are marked in the file header as allocated but not yet serving traffic.
- **Cursor — Origin** — static list from the [documentation](https://cursor.com/docs/cloud-agent/security-network), applied on top of the git egress proxy addresses.
- **OpenAI / ChatGPT** — domains from the official [network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps) (verified 2026-11-12), resolved via public DoH resolvers. Includes the WebSocket endpoints required by ChatGPT and Codex (`ws.chatgpt.com`, `chatgpt.com` over TCP 443). Outbound OpenAI IP ranges (ChatGPT agent / connectors JSON feeds) are intentionally **not** included — they cover traffic from OpenAI to your services, not user access.
- **OpenAI — 3rd party** — third-party dependency domains from the same OpenAI document, resolved via DoH. Kept as an independent group.

> Note: some Cursor domains are behind Cloudflare, so the network list contains
> shared CDN addresses. If your firewall supports domain-based rules, prefer
> the domain list and use the CIDR list as a supplement.

## Automation

GitHub Actions ([.github/workflows/update.yml](.github/workflows/update.yml)) runs
`scripts/update_lists.py` daily at 04:17 UTC and commits any changes.
Manual run: **Actions → Update IP lists → Run workflow**.

Locally:

```bash
python scripts/update_lists.py
```
