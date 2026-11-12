<div align="center">
  <h3> 🌐 Service CIDR Lists ♻️ </h3>
  <hr>
  <p>Automatically updated IP ranges and domain lists of popular services — ready for firewall policies and network allowlists.</p>
  <hr>
</div>

## 📋 Attributes

1. IPv4-only, CIDR-only network lists in an `ipset hash:net`-compatible format. Domain lists (including wildcard masks) where the service publishes domains.
2. Updates daily at 04:17 UTC via GitHub Actions; manual run: **Actions → Update IP lists → Run workflow**.
3. One folder per service; third-party dependencies are kept in separate groups that can be toggled independently.
4. Sources are official vendor documents and APIs only — no scraping, no third-party aggregators.
5. No excess or trailing whitespace. Lines are terminated with `\n`.

## 📜 FILES

The links below will direct you to the processed versions of the files in this repository. (Files are updated daily)

| File Name | Format | Protocol | Official |
| --- | --- | --- | --- |
| whatsapp_cidr_ipv4.txt | txt | IPv4 | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/WhatsApp/whatsapp_cidr_ipv4.txt) |
| cursor_cidr_ipv4.txt | txt | IPv4 | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_cidr_ipv4.txt) |
| cursor_domains.txt | txt | Domain | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_domains.txt) |
| cursor_git_egress_proxy_ipv4.txt ¹ | txt | IPv4 | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_git_egress_proxy_ipv4.txt) |
| cursor_origin_ipv4.txt ¹ | txt | IPv4 | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/Cursor/cursor_origin_ipv4.txt) |
| openai_cidr_ipv4.txt | txt | IPv4 | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_cidr_ipv4.txt) |
| openai_domains.txt | txt | Domain | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_domains.txt) |
| openai_3rd_party_cidr_ipv4.txt ² | txt | IPv4 | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_3rd_party_cidr_ipv4.txt) |
| openai_3rd_party_domains.txt ² | txt | Domain | [Download](https://raw.githubusercontent.com/<user>/<repo>/main/OpenAI/openai_3rd_party_domains.txt) |

¹ **Outbound** addresses of Cursor Cloud Agents (traffic *from* Cursor *to* your infrastructure), not service endpoints. Allowlist them if Cursor agents must reach your git hosts.

² Third-party dependencies used by ChatGPT (SendGrid, Intercom, WorkOS, Cloudflare, Apple, Stripe, Sentry, Datadog). Not owned by OpenAI — separate group, can be disabled independently.

## 🔎 Sources

- **WhatsApp** — synced from [HybridNetworks/whatsapp-cidr](https://github.com/HybridNetworks/whatsapp-cidr) (official Meta networks).
- **Cursor** — official domains from the [Cursor documentation](https://cursor.com/docs/cloud-agent/security-network), resolved via public DoH resolvers (Google + Cloudflare); egress addresses merged with the official API [cursor.com/docs/ips.json](https://cursor.com/docs/ips.json).
- **OpenAI / ChatGPT** — domains from the official [network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps), resolved via public DoH resolvers.

> Note: some domains are behind Cloudflare and other CDNs, so the CIDR lists
> contain shared addresses that rotate over time. If your firewall supports
> domain-based rules, prefer the domain lists and use the CIDR lists as
> a supplement.

---

## 📝 License

```
MIT License

Copyright (c) 2026 Service CIDR Lists contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
