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

¹ These are **outbound** addresses of Cursor Cloud Agents (traffic *from* Cursor
*to* your infrastructure), not service endpoints. Allowlist them if Cursor agents
must reach your git hosts; they are not required for firewall rules covering
traffic to Cursor services.

Raw URLs for automation:

```
https://raw.githubusercontent.com/<user>/<repo>/main/WhatsApp/whatsapp_cidr_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_cidr_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_domains.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_git_egress_proxy_ipv4.txt
https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_origin_ipv4.txt
```

## Sources

- **WhatsApp** — synced from [HybridNetworks/whatsapp-cidr](https://github.com/HybridNetworks/whatsapp-cidr) (official Meta networks).
- **Cursor** — official domains from the [Cursor documentation](https://cursor.com/docs/cloud-agent/security-network), resolved via public DoH resolvers (Google + Cloudflare). Domains without A records at the last check (`api5.cursor.sh`, `authentication.cursor.sh`, `cursorapi.com`) are kept in the domain list in case they appear. The `*.api5.cursor.sh` and `*.authentication.cursor.sh` entries are subdomain masks for domain-based rules (Cursor does not publish a DNS wildcard, so they do not resolve directly).
- **Cursor — git egress proxy** — merged from the [documentation](https://cursor.com/docs/cloud-agent/security-network) and the official API [cursor.com/docs/ips.json](https://cursor.com/docs/ips.json). Active addresses are verified against the API; the remaining ones are marked in the file header as allocated but not yet serving traffic.
- **Cursor — Origin** — static list from the [documentation](https://cursor.com/docs/cloud-agent/security-network), applied on top of the git egress proxy addresses.

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
