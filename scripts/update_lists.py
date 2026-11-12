#!/usr/bin/env python3
"""Обновление списков IP/доменов для podkop.

- WhatsApp: синхронизация с upstream HybridNetworks/whatsapp-cidr.
- Cursor: резолв официальных доменов через DoH (Google + Cloudflare)
  с fallback на системный DNS.

Зависимостей нет, только стандартная библиотека Python 3.9+.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

WHATSAPP_URL = (
    "https://raw.githubusercontent.com/HybridNetworks/whatsapp-cidr/"
    "main/WhatsApp/whatsapp_cidr_ipv4.txt"
)
WHATSAPP_FILE = ROOT / "WhatsApp" / "whatsapp_cidr_ipv4.txt"

CURSOR_DIR = ROOT / "Cursor"
CURSOR_CIDR_FILE = CURSOR_DIR / "cursor_cidr_ipv4.txt"
CURSOR_DOMAINS_FILE = CURSOR_DIR / "cursor_domains.txt"

CURSOR_IPS_JSON_URL = "https://cursor.com/docs/ips.json"

# Egress-адреса Cursor Cloud Agents (Cursor -> ваша инфраструктура).
# Источник: https://cursor.com/docs/cloud-agent/security-network
# Активные адреса дополнительно сверяются с CURSOR_IPS_JSON_URL.
CURSOR_GIT_EGRESS_PROXY_IPS = [
    "184.73.225.134",
    "3.209.66.12",
    "52.44.113.131",
    # Выделены, но ещё не обслуживают трафик (опубликованы заранее,
    # в ips.json не возвращаются):
    "100.63.97.141",
    "100.63.144.57",
    "18.210.232.136",
    "3.208.51.163",
    "3.224.130.48",
    "3.234.118.132",
    "34.197.19.148",
    "34.198.251.120",
    "34.199.187.247",
    "35.170.160.152",
    "44.215.226.85",
    "52.202.172.69",
    "54.81.109.217",
    "54.204.61.44",
    "54.236.99.119",
    "67.202.63.191",
    "184.193.125.229",
    "184.193.223.40",
    "184.194.140.210",
    "184.194.175.144",
    "184.194.208.56",
]

# Дополнительные egress-адреса для связки Cloud Agents + Origin.
# Источник: https://cursor.com/docs/cloud-agent/security-network
CURSOR_ORIGIN_IPS = [
    "34.192.39.182",
    "50.16.106.255",
    "44.217.29.124",
    "3.223.245.201",
    "54.164.185.10",
    "34.194.133.23",
    "35.170.116.221",
]

# https://cursor.com/docs/cloud-agent/security-network
# Записи вида "*.domain" — маски поддоменов для маршрутизации по доменам
# (podkop/dnsmasq); напрямую не резолвятся, DNS-wildcard не опубликован.
CURSOR_DOMAINS = [
    "cursor.com",
    "cursor.sh",
    "cursorapi.com",
    "cursor-cdn.com",
    "api2.cursor.sh",
    "api3.cursor.sh",
    "api4.cursor.sh",
    "api5.cursor.sh",
    "*.api5.cursor.sh",
    "repo42.cursor.sh",
    "authentication.cursor.sh",
    "*.authentication.cursor.sh",
    "prod.authentication.cursor.sh",
    "authenticator.cursor.sh",
    "marketplace.cursorapi.com",
    "downloads.cursor.com",
]

# https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps
# Записи вида "*.domain" — маски поддоменов для доменных правил FW,
# напрямую не резолвятся.
OPENAI_DOMAINS = [
    "*.auth.openai.com",
    "*.chatgpt.com",
    "*.oaistatic.com",
    "*.oaiusercontent.com",
    "*.openai.com",
    "*.oaistatsig.com",
    "android.chat.openai.com",
    "auth0.openai.com",
    "cdn.openaimerge.com",
    "cdn.platform.openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "desktop.chat.openai.com",
    "ios.chat.openai.com",
    "setup.auth.openai.com",
    "tcr9i.chat.openai.com",
    "ws.chatgpt.com",
]

# Зависимости третьих сторон (не принадлежат OpenAI) — отдельная группа,
# чтобы её можно было отключать независимо.
OPENAI_3RD_PARTY_DOMAINS = [
    "*.ct.sendgrid.net",
    "*.intercom.io",
    "*.intercomcdn.com",
    "cdn.workos.com",
    "challenges.cloudflare.com",
    "forwarder.workos.com",
    "frontend-apps-multi-region.workos.com",
    "humb.apple.com",
    "images.workoscdn.com",
    "js.intercomcdn.com",
    "js.stripe.com",
    "o207216.ingest.sentry.io",
    "o33249.ingest.sentry.io",
    "rum.browser-intake-datadoghq.com",
    "setup.workos.com",
    "workos.imgix.net",
]

OPENAI_DIR = ROOT / "OpenAI"
OPENAI_DOMAINS_FILE = OPENAI_DIR / "openai_domains.txt"
OPENAI_CIDR_FILE = OPENAI_DIR / "openai_cidr_ipv4.txt"

OPENAI_SOURCE_URL = (
    "https://help.openai.com/en/articles/9247338-"
    "network-recommendations-for-chatgpt-errors-on-web-and-apps"
)

DOH_SERVERS = [
    "https://dns.google/resolve?name={name}&type=A",
    "https://1.1.1.1/dns-query?name={name}&type=A",
]

HEADERS = {
    "User-Agent": "ip-pools-updater/1.0",
    "Accept": "application/dns-json",
}

# fake-ip диапазон локальных VPN/прокси (RFC 2544) — не должен попадать в списки
FAKE_IP_RANGE = ipaddress.ip_network("198.18.0.0/15")


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ip-pools-updater/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def resolve_doh(domain: str) -> set[str]:
    ips: set[str] = set()
    for tpl in DOH_SERVERS:
        try:
            req = urllib.request.Request(tpl.format(name=domain), headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.load(resp)
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:
                    ips.add(ans["data"])
        except Exception as exc:  # noqa: BLE001
            print(f"  ! DoH error for {domain}: {exc}", file=sys.stderr)
    return ips


def resolve_system(domain: str) -> set[str]:
    try:
        return {i[4][0] for i in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except socket.gaierror:
        return set()


def is_usable(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    return addr.is_global and addr not in FAKE_IP_RANGE


def resolve(domain: str) -> set[str]:
    ips = resolve_doh(domain)
    if not ips:
        ips = resolve_system(domain)
    return {ip for ip in ips if is_usable(ip)}


def write_if_changed(path: Path, text: str) -> bool:
    """Пишет файл, если содержимое изменилось (игнорируя строку Updated)."""
    def normalize(t: str) -> str:
        return "\n".join(
            line for line in t.splitlines() if not line.startswith("# Updated (UTC)")
        )

    if path.exists() and normalize(path.read_text(encoding="utf-8")) == normalize(text):
        print(f"= {path.relative_to(ROOT)}: без изменений")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"+ {path.relative_to(ROOT)}: обновлён")
    return True


def update_whatsapp() -> None:
    text = fetch_text(WHATSAPP_URL)
    if not text.strip():
        raise RuntimeError("Пустой ответ от upstream WhatsApp")
    write_if_changed(WHATSAPP_FILE, text)


def section(title: str, lines: list[str] | set[str], note: str | None = None,
            sort_ips: bool = False) -> str:
    """Блок комментария-раздела внутри списка + строки данных."""
    out = (
        "\n# ------------------------------------------------------------\n"
        f"# {title}\n"
    )
    if note:
        out += f"# {note}\n"
    out += "# ------------------------------------------------------------\n"
    items = sorted(lines, key=lambda i: int(ipaddress.IPv4Address(i))) if sort_ips else list(lines)
    if items:
        out += "".join(f"{item}\n" for item in items)
    else:
        out += "# (no entries resolved at last check)\n"
    return out


def update_cursor() -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- Сервисные домены -> IP (трафик К Cursor) ---
    svc_ips, inactive, wildcards = resolve_group(CURSOR_DOMAINS)
    if not svc_ips:
        raise RuntimeError("Не удалось резолвить ни один домен Cursor — списки не тронуты")

    # --- Git egress proxy (исходящие ИЗ Cursor Cloud Agents) ---
    api_proxy: set[str] | None = None
    try:
        data = json.loads(fetch_text(CURSOR_IPS_JSON_URL))
        api_proxy = {
            entry.split("/")[0]
            for entry in data.get("gitEgressProxy", [])
            if is_usable(entry.split("/")[0])
        }
        print(f"  ips.json gitEgressProxy: {', '.join(sorted(api_proxy))}")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! не удалось получить ips.json, активные адреса берём из документации: {exc}",
              file=sys.stderr)

    proxy_ips = set(CURSOR_GIT_EGRESS_PROXY_IPS) | (api_proxy or set())
    if not proxy_ips:
        raise RuntimeError("Пустой список git egress proxy — файл не тронут")
    # Если API недоступен, активными считаем первые три адреса из документации
    # (именно они возвращаются ips.json).
    active = api_proxy if api_proxy is not None else set(CURSOR_GIT_EGRESS_PROXY_IPS[:3])
    reserved = sorted(proxy_ips - active, key=lambda i: int(ipaddress.IPv4Address(i)))

    header = f"""# ============================================================
#
# cursor_cidr_ipv4
#
# ipv4 hash:net ipset
#
# All Cursor IP ranges in one file, grouped by comment blocks:
#   1. Service endpoints (traffic TO Cursor)
#   2. Git egress proxy (OUTBOUND from Cursor Cloud Agents)
#   3. Origin (OUTBOUND from Cursor Cloud Agents)
#
# Maintainer      : DNS resolve + Cursor docs, see scripts/update_lists.py
# List source URL : https://cursor.com/docs/cloud-agent/security-network
# Domains         : Cursor/cursor_domains.txt
#
# Category        : servers
# Updated (UTC)   : {now}
#
# ============================================================
"""
    text = header
    text += section(
        "Cursor service endpoints (traffic TO Cursor, resolved from domains)",
        [f"{ip}/32" for ip in sorted(svc_ips, key=lambda i: int(ipaddress.IPv4Address(i)))],
    )
    proxy_note = None
    if reserved:
        proxy_note = "Allocated, not yet serving traffic: " + ", ".join(reserved)
    text += section(
        "Cursor git egress proxy (OUTBOUND from Cursor Cloud Agents, "
        "allowlist on your side if agents must reach your git hosts)",
        [f"{ip}/32" for ip in sorted(proxy_ips, key=lambda i: int(ipaddress.IPv4Address(i)))],
        proxy_note,
    )
    text += section(
        "Cursor Origin (OUTBOUND, Cloud Agents used alongside Origin)",
        [f"{ip}/32" for ip in sorted(CURSOR_ORIGIN_IPS, key=lambda i: int(ipaddress.IPv4Address(i)))],
    )
    write_if_changed(CURSOR_CIDR_FILE, text)

    # --- Файл доменов ---
    domains_header = f"""# ============================================================
#
# cursor_domains
#
# List of official Cursor domains.
# Source: https://cursor.com/docs/cloud-agent/security-network
# Updated (UTC)   : {now}
#
"""
    if wildcards:
        domains_header += (
            "# Wildcard entries (subdomain masks for domain-based routing, "
            "not resolvable directly): " + ", ".join(wildcards) + "\n"
        )
    if inactive:
        domains_header += "# No A records at last check: " + ", ".join(inactive) + "\n"
    domains_header += "# ============================================================\n"
    domains_text = domains_header + "".join(f"{d}\n" for d in CURSOR_DOMAINS)
    write_if_changed(CURSOR_DOMAINS_FILE, domains_text)


def resolve_group(domains: list[str]) -> tuple[set[str], list[str], list[str]]:
    """Резолвит конкретные домены группы. Возвращает (IP, inactive, wildcards)."""
    all_ips: set[str] = set()
    inactive: list[str] = []
    wildcards = [d for d in domains if d.startswith("*.")]
    for domain in domains:
        if domain.startswith("*."):
            continue
        ips = resolve(domain)
        if ips:
            print(f"  {domain}: {', '.join(sorted(ips, key=lambda i: int(ipaddress.IPv4Address(i))))}")
            all_ips |= ips
        else:
            print(f"  {domain}: нет A-записей")
            inactive.append(domain)
    return all_ips, inactive, wildcards


def update_openai() -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print("-- OpenAI --")
    oai_ips, oai_inactive, oai_wildcards = resolve_group(OPENAI_DOMAINS)
    print("-- OpenAI 3rd party --")
    tp_ips, tp_inactive, tp_wildcards = resolve_group(OPENAI_3RD_PARTY_DOMAINS)

    if not oai_ips and not tp_ips:
        raise RuntimeError("Не удалось резолвить ни один домен OpenAI — списки не тронуты")

    cidr_header = f"""# ============================================================
#
# openai_cidr_ipv4
#
# ipv4 hash:net ipset
#
# All OpenAI/ChatGPT IP addresses in one file, grouped by comment blocks:
#   1. OpenAI service endpoints (traffic TO OpenAI)
#   2. Third-party dependencies (NOT owned by OpenAI)
#
# Maintainer      : DNS resolve, see scripts/update_lists.py
# List source URL : {OPENAI_SOURCE_URL}
# Domains         : OpenAI/openai_domains.txt
#
# Category        : servers
# Updated (UTC)   : {now}
#
# ============================================================
"""
    cidr_text = cidr_header
    cidr_text += section(
        "OpenAI/ChatGPT service endpoints (traffic TO OpenAI, resolved from domains)",
        [f"{ip}/32" for ip in sorted(oai_ips, key=lambda i: int(ipaddress.IPv4Address(i)))],
    )
    cidr_text += section(
        "Third-party dependencies used by OpenAI — NOT owned by OpenAI "
        "(SendGrid, Intercom, WorkOS, Cloudflare, Apple, Stripe, Sentry, Datadog)",
        [f"{ip}/32" for ip in sorted(tp_ips, key=lambda i: int(ipaddress.IPv4Address(i)))],
    )
    write_if_changed(OPENAI_CIDR_FILE, cidr_text)

    domains_header = f"""# ============================================================
#
# openai_domains
#
# All OpenAI/ChatGPT domains in one file, grouped by comment blocks:
#   1. OpenAI domains
#   2. Third-party dependencies (NOT owned by OpenAI)
#
# Source: {OPENAI_SOURCE_URL}
# Updated (UTC)   : {now}
#
"""
    all_wildcards = oai_wildcards + tp_wildcards
    if all_wildcards:
        domains_header += (
            "# Wildcard entries (subdomain masks for domain-based rules, "
            "not resolvable directly): " + ", ".join(all_wildcards) + "\n"
        )
    all_inactive = oai_inactive + tp_inactive
    if all_inactive:
        domains_header += "# No A records at last check: " + ", ".join(all_inactive) + "\n"
    domains_header += "# ============================================================\n"

    domains_text = domains_header
    domains_text += section("OpenAI domains", OPENAI_DOMAINS)
    domains_text += section(
        "Third-party dependencies used by OpenAI — NOT owned by OpenAI "
        "(separate group, can be disabled independently)",
        OPENAI_3RD_PARTY_DOMAINS,
    )
    write_if_changed(OPENAI_DOMAINS_FILE, domains_text)


def main() -> None:
    print("== WhatsApp ==")
    update_whatsapp()
    print("== Cursor ==")
    update_cursor()
    print("== OpenAI / ChatGPT ==")
    update_openai()
    print("Готово.")


if __name__ == "__main__":
    main()
