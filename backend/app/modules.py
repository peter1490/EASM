from __future__ import annotations

import asyncio
import socket
import ssl
import ipaddress
from datetime import datetime
import os
import uuid
import shutil
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urlparse
import httpx
import json
import logging

from .config import get_settings
from .utils import retry, CircuitBreaker
from .exceptions import ExternalServiceException

logger = logging.getLogger(__name__)
settings = get_settings()

# Circuit breakers for external services
crtsh_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
bufferover_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
hackertarget_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
certspotter_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
virustotal_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
shodan_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
bgpview_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
wayback_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
urlscan_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
otx_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
doh_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
wikidata_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)
opencorporates_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300.0)

@retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(httpx.HTTPError, httpx.ConnectError))
async def _get_with_retries(client: httpx.AsyncClient, url: str, *, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Optional[httpx.Response]:
    """HTTP GET with automatic retries."""
    resp = await client.get(url, params=params, headers=headers)
    if resp.status_code == 200:
        return resp
    elif resp.status_code >= 500:
        # Server errors are retryable
        raise httpx.HTTPError(f"Server error: {resp.status_code}")
    return None



def extract_organization_names_from_subject(subject: Optional[str]) -> Set[str]:
    """Extract organization names from an OpenSSL subject string.

    Accepts keys like O= and organizationName= in a comma-separated string.
    Returns a set of non-empty organization names.
    """
    orgs: Set[str] = set()
    if not subject:
        return orgs
    try:
        # Subject formatted like "countryName=US, organizationName=Example Inc, commonName=www.example.com"
        parts = [p.strip() for p in str(subject).split(",")]
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key_l = key.strip().lower()
            val = value.strip()
            if not val:
                continue
            if key_l in {"o", "organizationname"}:
                orgs.add(val)
    except Exception:
        return orgs
    return orgs

async def enumerate_subdomains_by_organization_crtsh(
    organization_name: str, timeout_seconds: Optional[float] = None
) -> Set[str]:
    """Enumerate DNS names by organization using crt.sh O parameter.

    Uses JSON output and parses name_value fields similarly to domain-based enumeration.
    Returns a set of normalized hostnames (lowercased, wildcard removed).
    """
    # Avoid sending empty queries
    org = (organization_name or "").strip()
    if not org:
        return set()
    
    org = quote(org)
    url = f"https://crt.sh/?O={org}&match=ILIKE&output=json"
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    
    try:
        async def _fetch():
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                resp = await _get_with_retries(client, url)
                if not resp:
                    return set()
                return resp.json()
        
        data = await crtsh_breaker.call(_fetch)
        if not data:
            return set()
        names: Set[str] = set()
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                # Parse common_name lines (historical), plus name_value and dns_names if present
                common_name = entry.get("common_name")
                if common_name:
                    for raw in str(common_name).split("\n"):
                        n = str(raw or "").strip().lower()
                        if not n:
                            continue
                        if n.startswith("*."):
                            n = n[2:]
                        names.add(n)
                """ name_value = entry.get("name_value")
                if name_value:
                    for raw in str(name_value).split("\n"):
                        n = str(raw or "").strip().lower()
                        if not n:
                            continue
                        if n.startswith("*."):
                            n = n[2:]
                        names.add(n) """
                dns_names = entry.get("dns_names")
                if isinstance(dns_names, list):
                    for raw in dns_names:
                        n = str(raw or "").strip().lower()
                        if not n:
                            continue
                        if n.startswith("*."):
                            n = n[2:]
                        names.add(n)
        return names
    except Exception:
        return set()

async def enumerate_subdomains_crtsh(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Enumerate subdomains using crt.sh JSON output.

    This is best-effort and may return an empty set on error.
    """
    #url = f"https://crt.sh/?q=%25.{domain}&match=ILIKE&output=json"
    url = f"https://crt.sh/?Identity={domain}&match=ILIKE&output=json"
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return set()
            data = resp.json()
            names: Set[str] = set()
            for entry in data:
                name_value = entry.get("name_value")
                if not name_value:
                    continue
                # name_value can contain multiple lines with wildcards
                for raw in str(name_value).split("\n"):
                    n = raw.strip().lower()
                    if not n:
                        continue
                    if "*" in n:
                        n = n.replace("*.", "")
                    names.add(n)
            return names
    except Exception:
        return set()


async def enumerate_subdomains_bufferover(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Enumerate subdomains using BufferOver public endpoints (best-effort).

    Docs are unofficial; responses can vary. We defensively parse common shapes.
    Returns an empty set on any error.
    """
    # Two endpoints observed in the wild
    endpoints = [
        f"https://tls.bufferover.run/dns?q=%25.{domain}",
        f"https://dns.bufferover.run/dns?q=%25.{domain}",
    ]
    names: Set[str] = set()
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            for url in endpoints:
                try:
                    resp = await client.get(url, headers={"User-Agent": "EASM/0.2"})
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                except Exception:
                    continue

                # Common schemas: keys like FDNS_A, RDNS, CNAME; or sometimes a flat list in "Results"
                values: List[str] = []
                if isinstance(data, dict):
                    for key, val in data.items():
                        if isinstance(val, list):
                            values.extend([str(x) for x in val])
                elif isinstance(data, list):
                    values.extend([str(x) for x in data])

                for raw in values:
                    # Frequently lines look like "1.2.3.4,sub.example.com" or just "sub.example.com"
                    for token in str(raw).split(","):
                        host = token.strip().lower()
                        if not host:
                            continue
                        if "*" in host:
                            host = host.replace("*.", "")
                        if host == domain.lower() or host.endswith("." + domain.lower()):
                            names.add(host)
    except Exception:
        return set()
    return names


async def enumerate_subdomains_hackertarget(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Enumerate subdomains via HackerTarget hostsearch (rate-limited, best-effort).

    Returns an empty set on error. Response is CSV lines: subdomain,ip
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.get(url, headers={"User-Agent": "EASM/0.2"})
            if resp.status_code != 200:
                return set()
            text = resp.text or ""
            names: Set[str] = set()
            for line in text.splitlines():
                line = line.strip()
                if not line or line.lower().startswith("error"):
                    continue
                host = line.split(",")[0].strip().lower()
                if "*" in host:
                    host = host.replace("*.", "")
                if host and (host == domain.lower() or host.endswith("." + domain.lower())):
                    names.add(host)
            return names
    except Exception:
        return set()


async def enumerate_subdomains_certspotter(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Enumerate subdomains via CertSpotter API if token available; anonymous is best-effort.

    Set CERTSPOTTER_API_TOKEN to increase reliability and rate limits.
    """
    base = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
        # Be permissive about matches; API may ignore unknown params
        "match_wildcards": "true",
    }
    headers = {"User-Agent": "EASM/0.2"}
    token = os.getenv("CERTSPOTTER_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.get(base, params=params, headers=headers)
            if resp.status_code != 200:
                return set()
            data = resp.json()
            names: Set[str] = set()
            if isinstance(data, list):
                for entry in data:
                    dns_names = entry.get("dns_names") if isinstance(entry, dict) else None
                    if not isinstance(dns_names, list):
                        continue
                    for n in dns_names:
                        host = str(n or "").strip().lower()
                        if not host:
                            continue
                        if "*" in host:
                            host = host.replace("*.", "")
                        if host == domain.lower() or host.endswith("." + domain.lower()):
                            names.add(host)
            return names
    except Exception:
        return set()


async def enumerate_subdomains_subfinder(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Enumerate subdomains using the Subfinder CLI if available.

    Uses SUBFINDER_PATH env var or falls back to resolving "subfinder" on PATH.
    Returns an empty set on error or if the binary is not present.
    """
    # This is a local process; keep its timeout but allow override
    if timeout_seconds is None:
        timeout_seconds = 10.0  # Default timeout for subprocess
    try:
        binary_path = os.getenv("SUBFINDER_PATH") or shutil.which("subfinder")
        if not binary_path:
            return set()
        # Build command: subfinder -silent -d <domain>
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            "-silent",
            "-d",
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return set()
        if proc.returncode not in (0, None):
            # Best-effort: treat non-zero as empty
            return set()
        text = (stdout or b"").decode(errors="ignore")
        names: Set[str] = set()
        dom_l = domain.strip().lower()
        for line in text.splitlines():
            n = line.strip().lower()
            if not n:
                continue
            if n.startswith("*."):
                n = n[2:]
            if n == dom_l or n.endswith("." + dom_l):
                names.add(n)
        return names
    except Exception:
        return set()


async def enumerate_subdomains_virustotal(domain: str, timeout_seconds: Optional[float] = None, max_pages: int = 2) -> Set[str]:
    """Enumerate subdomains using VirusTotal v3 API if VIRUSTOTAL_API_KEY is set.

    Paginates a couple of pages to keep latency bounded. Returns empty set on error.
    """
    token = os.getenv("VIRUSTOTAL_API_KEY")
    if not token:
        return set()
    base = f"https://www.virustotal.com/api/v3/domains/{domain.strip().lower()}/subdomains"
    headers = {"x-apikey": token, "User-Agent": "EASM/0.2"}
    params: Dict[str, str] = {"limit": "40"}
    names: Set[str] = set()
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
            cursor = None
            pages_fetched = 0
            while pages_fetched < max_pages:
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(base, params=params)
                if resp.status_code != 200:
                    break
                data = resp.json()
                arr = data.get("data") if isinstance(data, dict) else None
                if isinstance(arr, list):
                    for item in arr:
                        # items are objects with id field as subdomain
                        sid = None
                        if isinstance(item, dict):
                            sid = item.get("id") or item.get("type")  # prefer id
                        if not sid:
                            continue
                        host = str(sid).strip().lower()
                        if host.startswith("*."):
                            host = host[2:]
                        dom_l = domain.strip().lower()
                        if host and (host == dom_l or host.endswith("." + dom_l)):
                            names.add(host)
                cursor = None
                meta = data.get("meta") if isinstance(data, dict) else None
                if isinstance(meta, dict):
                    next_cursor = meta.get("cursor")
                    cursor = str(next_cursor) if next_cursor else None
                pages_fetched += 1
                if not cursor:
                    break
        return names
    except Exception:
        return set()


async def enumerate_subdomains_shodan(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Enumerate subdomains using Shodan DNS domain API if SHODAN_API_KEY is set.

    Endpoint: /dns/domain/{domain}
    Response includes "subdomains" as labels. Compose with domain.
    """
    token = os.getenv("SHODAN_API_KEY")
    if not token:
        return set()
    url = f"https://api.shodan.io/dns/domain/{domain.strip().lower()}"
    params = {"key": token}
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return set()
            data = resp.json()
            names: Set[str] = set()
            dom_l = domain.strip().lower()
            # "subdomains" is a list of labels
            subs = data.get("subdomains") if isinstance(data, dict) else None
            if isinstance(subs, list):
                for label in subs:
                    try:
                        n = str(label or "").strip().lower()
                        if not n:
                            continue
                        host = f"{n}.{dom_l}"
                        if host.startswith("*."):
                            host = host[2:]
                        if host == dom_l or host.endswith("." + dom_l):
                            names.add(host)
                    except Exception:
                        continue
            # Some responses have detailed records under "data"
            records = data.get("data") if isinstance(data, dict) else None
            if isinstance(records, list):
                for rec in records:
                    try:
                        sub = rec.get("subdomain") if isinstance(rec, dict) else None
                        if not sub:
                            continue
                        n2 = str(sub).strip().lower()
                        if not n2:
                            continue
                        host2 = f"{n2}.{dom_l}"
                        if host2.startswith("*."):
                            host2 = host2[2:]
                        if host2 == dom_l or host2.endswith("." + dom_l):
                            names.add(host2)
                    except Exception:
                        continue
            return names
    except Exception:
        return set()


async def enumerate_hosts_wayback(domain: str, timeout_seconds: Optional[float] = None, max_rows: int = 2000) -> Set[str]:
    """Enumerate hostnames seen in the Internet Archive (Wayback Machine) for a domain.

    Uses the CDX API to list archived URLs for *.domain/* and extracts hostnames.
    Best-effort; returns a set possibly empty.
    """
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 12.0)
    names: Set[str] = set()
    try:
        base = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(max_rows),
        }
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            resp = await wayback_breaker.call(_get_with_retries, client, base, params=params)
            if not resp:
                return set()
            data = resp.json()
            # First row may be headers, skip if needed
            rows = data[1:] if isinstance(data, list) and data and isinstance(data[0], list) else data
            if not isinstance(rows, list):
                return set()
            dom_l = domain.strip().lower()
            for row in rows:
                try:
                    url = row[0] if isinstance(row, list) and row else row
                    h = urlparse(str(url)).hostname or ""
                    h = h.strip().lower()
                    if not h:
                        continue
                    if h.startswith("*."):
                        h = h[2:]
                    if h == dom_l or h.endswith("." + dom_l):
                        names.add(h)
                except Exception:
                    continue
        return names
    except Exception:
        return set()


async def enumerate_hosts_urlscan(domain: str, timeout_seconds: Optional[float] = None, max_pages: int = 2) -> Set[str]:
    """Enumerate hostnames via urlscan.io search API.

    Queries for domain:example.com and extracts page/task domains and URLs.
    """
    token = os.getenv("URLSCAN_API_KEY")
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 12.0)
    headers = {"User-Agent": "EASM/0.2"}
    if token:
        headers["API-Key"] = token
    names: Set[str] = set()
    try:
        base = "https://urlscan.io/api/v1/search/"
        query = f"domain:{domain.strip().lower()}"
        async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
            page = 1
            while page <= max_pages:
                params = {"q": query, "size": "100", "page": str(page)}
                resp = await urlscan_breaker.call(_get_with_retries, client, base, params=params)
                if not resp:
                    break
                data = resp.json()
                results = data.get("results") if isinstance(data, dict) else None
                if not isinstance(results, list) or not results:
                    break
                dom_l = domain.strip().lower()
                for item in results:
                    try:
                        page_info = item.get("page") if isinstance(item, dict) else None
                        task_info = item.get("task") if isinstance(item, dict) else None
                        for host in [
                            (page_info or {}).get("domain"),
                            (task_info or {}).get("domain"),
                            urlparse(str((page_info or {}).get("url") or "")).hostname,
                        ]:
                            h = (str(host or "")).strip().lower()
                            if not h:
                                continue
                            if h.startswith("*."):
                                h = h[2:]
                            if h == dom_l or h.endswith("." + dom_l):
                                names.add(h)
                    except Exception:
                        continue
                page += 1
        return names
    except Exception:
        return set()


async def enumerate_hosts_otx(domain: str, timeout_seconds: Optional[float] = None, max_pages: int = 3) -> Set[str]:
    """Enumerate hostnames via AlienVault OTX passive DNS for the domain.

    Requires or benefits from OTX_API_KEY, but some endpoints may work anonymously.
    """
    token = os.getenv("OTX_API_KEY")
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 12.0)
    headers = {"User-Agent": "EASM/0.2"}
    if token:
        headers["X-OTX-API-KEY"] = token
    names: Set[str] = set()
    try:
        base = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain.strip().lower()}/passive_dns"
        async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
            page = 1
            url = base
            while page <= max_pages and url:
                resp = await otx_breaker.call(_get_with_retries, client, url)
                if not resp:
                    break
                data = resp.json()
                dom_l = domain.strip().lower()
                # Two shapes: {passive_dns: [...], next: url} or {results: [...]} etc.
                entries = None
                if isinstance(data, dict):
                    entries = data.get("passive_dns") or data.get("results")
                if isinstance(entries, list):
                    for e in entries:
                        try:
                            host = None
                            if isinstance(e, dict):
                                host = e.get("hostname") or e.get("host") or e.get("indicator")
                            h = (str(host or "")).strip().lower()
                            if not h:
                                continue
                            if h.startswith("*."):
                                h = h[2:]
                            if h == dom_l or h.endswith("." + dom_l):
                                names.add(h)
                        except Exception:
                            continue
                # Pagination
                url = None
                if isinstance(data, dict):
                    nxt = data.get("next")
                    if nxt:
                        url = str(nxt)
                page += 1
        return names
    except Exception:
        return set()

async def fetch_asn_prefixes_bgpview(asn: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Fetch IPv4/IPv6 prefixes announced by an ASN using BGPView.

    Accepts inputs like "AS15169" or "15169" and returns a set of CIDR strings.
    Returns an empty set on error.
    """
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        val = str(asn or "").strip().upper()
        if not val:
            return set()
        if val.startswith("AS"):
            val = val[2:]
        if not val.isdigit():
            return set()
        url = f"https://api.bgpview.io/asn/{val}/prefixes"
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return set()
            data = resp.json()
            prefixes: Set[str] = set()
            d = data.get("data") if isinstance(data, dict) else None
            if isinstance(d, dict):
                v4 = d.get("ipv4_prefixes")
                if isinstance(v4, list):
                    for item in v4:
                        p = item.get("prefix") if isinstance(item, dict) else None
                        if p:
                            prefixes.add(str(p).strip())
                v6 = d.get("ipv6_prefixes")
                if isinstance(v6, list):
                    for item in v6:
                        p = item.get("prefix") if isinstance(item, dict) else None
                        if p:
                            prefixes.add(str(p).strip())
            return prefixes
    except Exception:
        return set()


async def enumerate_hostnames_shodan_by_org(organization_name: str, timeout_seconds: Optional[float] = None, max_pages: int = 1) -> Set[str]:
    """Enumerate hostnames observed by Shodan for a given organization.

    Requires SHODAN_API_KEY. Returns a set of hostnames/domains from matches.
    """
    token = os.getenv("SHODAN_API_KEY")
    if not token:
        return set()
    org = (organization_name or "").strip()
    if not org:
        return set()
    names: Set[str] = set()
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        base = "https://api.shodan.io/shodan/host/search"
        headers = {"User-Agent": "EASM/0.2"}
        async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
            page = 1
            while page <= max_pages:
                params = {"key": token, "query": f"org:\"{org}\"", "page": str(page)}
                resp = await client.get(base, params=params)
                if resp.status_code != 200:
                    break
                data = resp.json()
                matches = data.get("matches") if isinstance(data, dict) else None
                if isinstance(matches, list):
                    for m in matches:
                        if not isinstance(m, dict):
                            continue
                        hh = m.get("hostnames")
                        if isinstance(hh, list):
                            for h in hh:
                                n = str(h or "").strip().lower()
                                if n:
                                    names.add(n)
                        dd = m.get("domains")
                        if isinstance(dd, list):
                            for d in dd:
                                n2 = str(d or "").strip().lower()
                                if n2:
                                    names.add(n2)
                # Stop if no more pages or fewer results than a typical page
                total = data.get("total") if isinstance(data, dict) else None
                if not matches or (isinstance(total, int) and page * 100 >= total):
                    break
                page += 1
    except Exception:
        return set()
    return names


async def enumerate_hostnames_shodan_by_asn(asn: str, timeout_seconds: Optional[float] = None, max_pages: int = 1) -> Set[str]:
    """Enumerate hostnames observed by Shodan for a given ASN.

    Requires SHODAN_API_KEY. Accepts "AS123" or "123".
    """
    token = os.getenv("SHODAN_API_KEY")
    if not token:
        return set()
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        val = str(asn or "").strip().upper()
        if not val:
            return set()
        if not val.startswith("AS"):
            if val.isdigit():
                val = f"AS{val}"
            else:
                return set()
        names: Set[str] = set()
        base = "https://api.shodan.io/shodan/host/search"
        headers = {"User-Agent": "EASM/0.2"}
        async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
            page = 1
            while page <= max_pages:
                params = {"key": token, "query": f"asn:{val}", "page": str(page)}
                resp = await client.get(base, params=params)
                if resp.status_code != 200:
                    break
                data = resp.json()
                matches = data.get("matches") if isinstance(data, dict) else None
                if isinstance(matches, list):
                    for m in matches:
                        if not isinstance(m, dict):
                            continue
                        hh = m.get("hostnames")
                        if isinstance(hh, list):
                            for h in hh:
                                n = str(h or "").strip().lower()
                                if n:
                                    names.add(n)
                        dd = m.get("domains")
                        if isinstance(dd, list):
                            for d in dd:
                                n2 = str(d or "").strip().lower()
                                if n2:
                                    names.add(n2)
                total = data.get("total") if isinstance(data, dict) else None
                if not matches or (isinstance(total, int) and page * 100 >= total):
                    break
                page += 1
        return names
    except Exception:
        return set()

async def enumerate_subdomains_bruteforce(domain: str, candidates: Optional[Sequence[str]] = None) -> Set[str]:
    """Very small best-effort brute force using DNS resolution as a last resort.

    Uses a tiny built-in list to avoid heavy traffic. Returns only names that resolve.
    """
    wordlist = list(dict.fromkeys(candidates or [
        "www", "mail", "mx", "smtp", "imap", "pop", "vpn", "dev", "staging", "api",
        "app", "portal", "intranet", "test", "beta", "cdn", "assets", "static", "gw",
        "gateway", "sso", "auth", "admin", "docs", "blog", "status", "shop", "store",
        "pay", "files", "download", "downloads", "jira", "confluence", "git", "gitlab",
        "grafana", "kibana", "log", "logs", "monitor", "monitoring", "ns1", "ns2",
        "ns", "devops", "prod", "production", "stage", "ci", "cd"
    ]))

    hostnames = [f"{w.strip().lower()}.{domain}" for w in wordlist if w]
    try:
        resolutions = await resolve_hostnames(hostnames)
    except Exception:
        return set()
    names: Set[str] = set()
    resolved_items = {h: list(ips or []) for h, ips in resolutions.items() if ips}
    for host, ips in resolved_items.items():
        if ips:
            names.add(host.lower())

    # Wildcard DNS detection: if most or all candidates resolve, verify with random labels
    try:
        total = len(hostnames)
        resolved_count = len(resolved_items)
        # Heuristic: high resolution ratio OR very few distinct IP sets across many hits
        distinct_ip_signatures: Set[str] = set(
            ",".join(sorted(ips)) for ips in resolved_items.values() if ips
        )
        suspicious = False
        if total > 0 and resolved_count / float(total) >= 0.8:
            suspicious = True
        if resolved_count >= max(5, total // 2) and len(distinct_ip_signatures) <= 2:
            suspicious = True

        if suspicious:
            # Probe a few random non-existent labels to confirm wildcard
            random_labels = [uuid.uuid4().hex[:12], uuid.uuid4().hex[:12], uuid.uuid4().hex[:12]]
            probe_hosts = [f"{r}.{domain}" for r in random_labels]
            probe_map = await resolve_hostnames(probe_hosts)
            probe_resolved = {h: v for h, v in probe_map.items() if v}
            # Consider wildcard confirmed if at least 2 random labels resolve
            if len(probe_resolved) >= 2:
                wildcard_ips: Set[str] = set()
                for ips in probe_resolved.values():
                    for ip in ips:
                        wildcard_ips.add(ip)
                # Filter out hosts that only resolve to the wildcard IPs
                filtered: Set[str] = set()
                for host, ips in resolved_items.items():
                    ips_set = set(ips)
                    if not ips_set.issubset(wildcard_ips):
                        filtered.add(host.lower())
                names = filtered
    except Exception:
        # Best-effort; if detection fails, keep original names
        pass

    return names


async def enumerate_subdomains(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Aggregate subdomain enumeration across multiple passive sources with graceful fallbacks.

    Sources: crt.sh, BufferOver (dns/tls), HackerTarget, CertSpotter (optional token), and a tiny brute-force fallback.
    Always returns a set (possibly empty). Never raises.
    """
    domain_l = domain.strip().lower()
    try:
        tasks = [
            enumerate_subdomains_crtsh(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_bufferover(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_hackertarget(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_certspotter(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_subfinder(domain_l, timeout_seconds=min(timeout_seconds, 10.0)),
            enumerate_subdomains_virustotal(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_shodan(domain_l, timeout_seconds=timeout_seconds),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        names: Set[str] = set()
        for res in results:
            if isinstance(res, Exception) or res is None:
                continue
            for n in res:
                nn = str(n or "").strip().lower()
                if not nn:
                    continue
                if "*" in nn:
                    nn = nn.replace("*.", "")
                if nn == domain_l or nn.endswith("." + domain_l):
                    names.add(nn)

        # Last-resort tiny brute-force if nothing was found
        if not names:
            brute = await enumerate_subdomains_bruteforce(domain_l)
            for n in brute:
                if n == domain_l or n.endswith("." + domain_l):
                    names.add(n)

        return names
    except Exception:
        return set()


async def enumerate_subdomains_with_sources(domain: str, timeout_seconds: Optional[float] = None) -> Dict[str, Set[str]]:
    """Enumerate subdomains and return a mapping of hostname -> set of discovery sources.

    Includes multiple passive sources and optional OSINT pivots (Wayback, URLScan,
    OTX) if enabled in settings and keys are provided.
    Always returns a dict (possibly empty). Never raises.
    """
    domain_l = domain.strip().lower()
    origins: Dict[str, Set[str]] = {}
    try:
        tasks = [
            enumerate_subdomains_crtsh(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_bufferover(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_hackertarget(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_certspotter(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_subfinder(domain_l, timeout_seconds=min(timeout_seconds, 15.0)),
            enumerate_subdomains_virustotal(domain_l, timeout_seconds=timeout_seconds),
            enumerate_subdomains_shodan(domain_l, timeout_seconds=timeout_seconds),
        ]
        labels = ["crtsh", "bufferover", "hackertarget", "certspotter", "subfinder", "virustotal", "shodan"]

        # Optional OSINT sources
        if settings.enable_wayback:
            tasks.append(enumerate_hosts_wayback(domain_l, timeout_seconds=min(timeout_seconds or settings.http_timeout_seconds, 12.0)))
            labels.append("wayback")
        if settings.enable_urlscan and os.getenv("URLSCAN_API_KEY"):
            tasks.append(enumerate_hosts_urlscan(domain_l, timeout_seconds=min(timeout_seconds or settings.http_timeout_seconds, 12.0)))
            labels.append("urlscan")
        if settings.enable_otx and os.getenv("OTX_API_KEY"):
            tasks.append(enumerate_hosts_otx(domain_l, timeout_seconds=min(timeout_seconds or settings.http_timeout_seconds, 12.0)))
            labels.append("otx")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for label, res in zip(labels, results):
            if isinstance(res, Exception) or res is None:
                continue
            for n in res:
                nn = str(n or "").strip().lower()
                if not nn:
                    continue
                if "*" in nn:
                    nn = nn.replace("*.", "")
                if nn == domain_l or nn.endswith("." + domain_l):
                    if nn not in origins:
                        origins[nn] = set()
                    origins[nn].add(label)

        # Last-resort tiny brute-force if nothing was found at all
        if not origins:
            brute = await enumerate_subdomains_bruteforce(domain_l)
            for n in brute:
                if n == domain_l or n.endswith("." + domain_l):
                    if n not in origins:
                        origins[n] = set()
                    origins[n].add("bruteforce")
        return origins
    except Exception:
        return {}


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except Exception:
        return False


def expand_cidr(cidr: str, max_hosts: int = 4096) -> List[str]:
    """Expand a CIDR into a list of IP addresses (as strings), capped by max_hosts."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if len(hosts) > max_hosts:
            return hosts[:max_hosts]
        return hosts
    except Exception:
        return []


async def resolve_hostnames(hostnames: Iterable[str], family: int = socket.AF_UNSPEC, limit: Optional[int] = None) -> Dict[str, List[str]]:
    """Resolve a set of hostnames to IPs using asyncio.getaddrinfo.

    Returns a mapping hostname -> list of IP addresses (strings).
    """
    results: Dict[str, List[str]] = {}
    if limit is None:
        limit = settings.dns_concurrency

    semaphore = asyncio.Semaphore(limit)

    async def resolve_one(hostname: str) -> None:
        try:
            async with semaphore:
                infos = await asyncio.get_event_loop().getaddrinfo(
                    hostname, None, family=family, type=socket.SOCK_STREAM
                )
            ips: List[str] = []
            for info in infos:
                sockaddr = info[4]
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
            results[hostname] = ips
        except Exception:
            results[hostname] = []

    tasks = [asyncio.create_task(resolve_one(h)) for h in set(hostnames)]
    if tasks:
        await asyncio.gather(*tasks)
    return results


async def reverse_dns_ips(ips: Iterable[str], limit: Optional[int] = None) -> Dict[str, Optional[str]]:
    """Reverse DNS for a list of IPs. Returns ip -> PTR hostname or None."""
    results: Dict[str, Optional[str]] = {}
    if limit is None:
        limit = settings.rdns_concurrency

    semaphore = asyncio.Semaphore(limit)

    async def lookup(ip: str) -> None:
        try:
            async with semaphore:
                name, _, _ = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip)
            results[ip] = name
        except Exception:
            results[ip] = None

    tasks = [asyncio.create_task(lookup(ip)) for ip in set(ips)]
    if tasks:
        await asyncio.gather(*tasks)
    return results


async def tcp_scan_ports(
    host: str,
    ports: Sequence[int],
    connect_timeout_seconds: float = 0.35,
    limit_concurrency: int = 64,
) -> List[int]:
    """Return a list of open TCP ports on host.

    Uses asyncio.open_connection with a small timeout to stay fast.
    """
    # To avoid noisy "Future exception was never retrieved" logs that can occur
    # when DNS resolution inside asyncio.open_connection is cancelled by a short
    # timeout, pre-resolve hostnames to an IP and connect directly to the IP.
    target_for_connect: str = host
    if not is_ip(host):
        try:
            resolved = await resolve_hostnames([host])
            ips_for_host = resolved.get(host, [])
            if not ips_for_host:
                return []
            # Use the first resolved IP similar to default getaddrinfo ordering
            target_for_connect = ips_for_host[0]
        except Exception:
            return []
    semaphore = asyncio.Semaphore(limit_concurrency)
    open_ports: List[int] = []

    async def check(port: int) -> None:
        try:
            async with semaphore:
                await asyncio.wait_for(
                    asyncio.open_connection(host=target_for_connect, port=port),
                    timeout=connect_timeout_seconds,
                )
                open_ports.append(port)
        except Exception:
            return

    tasks = [asyncio.create_task(check(p)) for p in ports]
    if tasks:
        await asyncio.gather(*tasks)
    return sorted(open_ports)


async def http_probe(
    host: str,
    port: int,
    path: str = "/",
    timeout_seconds: Optional[float] = None,
) -> Optional[Dict[str, object]]:
    """Fetch HTTP(S) URL, returning status, title, headers subset.

    Returns None on failure.
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{path}"
    # allow env override
    if timeout_seconds is None:
        timeout_seconds = settings.http_timeout_seconds
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds, follow_redirects=True
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "EASM/0.2"})
            text = resp.text or ""
            title = None
            start = text.lower().find("<title>")
            if start != -1:
                end = text.lower().find("</title>", start)
                if end != -1:
                    title = text[start + 7 : end].strip()[:256]
            headers_subset = {k.lower(): v for k, v in resp.headers.items() if k.lower() in {"server", "content-type", "x-powered-by"}}
            return {
                "url": str(resp.url),
                "status": resp.status_code,
                "headers": headers_subset,
                "title": title,
            }
    except Exception:
        return None


def fetch_tls_certificate_summary(
    host: str,
    port: int = 443,
    timeout_seconds: Optional[float] = None,
) -> Optional[Dict[str, object]]:
    """Fetch TLS certificate using a blocking socket.

    Runs best in a thread pool when called from async.
    """
    if timeout_seconds is None:
        timeout_seconds = settings.tls_timeout_seconds
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")
                alt_names = [v for (t, v) in cert.get("subjectAltName", []) if t.lower() == "dns"]
                subject = ", ".join("{}={}".format(k, v) for tup in cert.get("subject", []) for (k, v) in tup)
                issuer = ", ".join("{}={}".format(k, v) for tup in cert.get("issuer", []) for (k, v) in tup)
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "subject_alt_names": alt_names,
                }
    except Exception:
        return None




def get_registered_domain_guess(hostname: str) -> Optional[str]:
    """Best-effort registered domain guess without public suffix list.

    Falls back to the last two labels. Returns None if input is not a hostname.
    """
    try:
        name = (hostname or "").strip().lower()
        if not name or any(c for c in name if c.isspace()):
            return None
        if name.endswith("."):
            name = name[:-1]
        parts = name.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return name or None
    except Exception:
        return None


async def fetch_domain_rdap_emails(domain: str, timeout_seconds: Optional[float] = None) -> Set[str]:
    """Fetch RDAP (WHOIS) for a domain and extract any contact emails.

    Uses rdap.org aggregator to avoid TLD-specific servers. Returns a set of
    emails (lowercased). Never raises; returns an empty set on error.
    """
    if timeout_seconds is None:
        timeout_seconds = 6.0  # Default timeout for RDAP
    emails: Set[str] = set()

    def collect_from_vcard_array(vcard_array: object) -> None:
        try:
            if not isinstance(vcard_array, list) or len(vcard_array) < 2:
                return
            entries = vcard_array[1]
            if not isinstance(entries, list):
                return
            for entry in entries:
                if not isinstance(entry, list) or len(entry) < 4:
                    continue
                field_name = str(entry[0]).lower()
                field_value = entry[3]
                if field_name == "email" and isinstance(field_value, str):
                    val = field_value.strip().lower()
                    if "@" in val:
                        emails.add(val)
        except Exception:
            return

    def collect_from_entity(entity: object) -> None:
        try:
            if not isinstance(entity, dict):
                return
            vcard = entity.get("vcardArray")
            if vcard is not None:
                collect_from_vcard_array(vcard)
            nested = entity.get("entities")
            if isinstance(nested, list):
                for sub in nested:
                    collect_from_entity(sub)
        except Exception:
            return

    try:
        import httpx  # already a dependency

        url = f"https://rdap.org/domain/{domain.strip().lower()}"
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return set()
            data = resp.json()
            # Top-level entities
            ents = data.get("entities") if isinstance(data, dict) else None
            if isinstance(ents, list):
                for ent in ents:
                    collect_from_entity(ent)
            # Some RDAP responses put vcard on the object itself
            if isinstance(data, dict) and "vcardArray" in data:
                collect_from_vcard_array(data.get("vcardArray"))
    except Exception:
        return set()

    return emails


async def enrich_company_from_domain(domain: str, timeout_seconds: Optional[float] = None) -> Dict[str, Any]:
    """Best-effort company enrichment from a domain.

    Signals used: Clearbit (if key), RDAP org hints, and fallback to split label.
    Returns {"company_name": str|None, "aliases": [..]}.
    """
    dom = (domain or "").strip().lower().rstrip(".")
    if not dom:
        return {"company_name": None, "aliases": []}
    aliases: List[str] = []
    name: Optional[str] = None
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 8.0)
    try:
        # Clearbit Enrichment (domain to company)
        token = os.getenv("CLEARBIT_API_KEY")
        if token:
            url = f"https://company.clearbit.com/v2/companies/find?domain={dom}"
            auth = (token, "")
            async with httpx.AsyncClient(timeout=timeout_seconds, auth=auth, headers={"User-Agent": "EASM/0.2"}) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    nm = (data or {}).get("name")
                    if isinstance(nm, str) and nm.strip():
                        name = nm.strip()
                    for k in ("domainAliases", "tags", "site", "legalName"):
                        v = (data or {}).get(k)
                        if isinstance(v, list):
                            for item in v:
                                if isinstance(item, str) and item.strip():
                                    aliases.append(item.strip())
                        elif isinstance(v, dict):
                            t = v.get("name")
                            if isinstance(t, str) and t.strip():
                                aliases.append(t.strip())
        # RDAP org fallback
        rdap_emails = await fetch_domain_rdap_emails(dom)
        for e in rdap_emails:
            try:
                local, edom = e.split("@", 1)
                lbl = edom.split(".")[0]
                if lbl and lbl not in aliases:
                    aliases.append(lbl)
            except Exception:
                continue
        # Default guess from domain label
        if not name:
            base = (get_registered_domain_guess(dom) or dom).split(".")[0]
            if base:
                name = base
        return {"company_name": name, "aliases": list(dict.fromkeys(aliases))}
    except Exception:
        return {"company_name": None, "aliases": []}


async def fetch_company_graph_wikidata(company_name: str, timeout_seconds: Optional[float] = None) -> Dict[str, Set[str]]:
    """Fetch parent/subsidiary relationships from Wikidata for a company name.

    Returns map with keys: parents, subsidiaries, brands, websites (all sets of strings).
    """
    name = (company_name or "").strip()
    if not name:
        return {"parents": set(), "subsidiaries": set(), "brands": set(), "websites": set()}
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 10.0)
    try:
        # Query: get entity, its subsidiaries (P355), parent org (P749), brands (P1716), official website (P856)
        sparql = (
            "SELECT ?item ?itemLabel ?subsLabel ?parentLabel ?brandLabel ?site WHERE { "
            "  ?item rdfs:label \"%s\"@en. "
            "  OPTIONAL { ?item wdt:P355 ?subs. } "
            "  OPTIONAL { ?item wdt:P749 ?parent. } "
            "  OPTIONAL { ?item wdt:P1716 ?brand. } "
            "  OPTIONAL { ?item wdt:P856 ?site. } "
            "  SERVICE wikibase:label { bd:serviceParam wikibase:language \"en\". } "
            "} LIMIT 200" % name.replace("\"", "")
        )
        url = "https://query.wikidata.org/sparql"
        headers = {"Accept": "application/sparql-results+json", "User-Agent": "EASM/0.2"}
        async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
            resp = await wikidata_breaker.call(client.get, url, params={"query": sparql})
            if resp is None or resp.status_code != 200:
                return {"parents": set(), "subsidiaries": set(), "brands": set(), "websites": set()}
            data = resp.json()
            parents: Set[str] = set()
            subs: Set[str] = set()
            brands: Set[str] = set()
            sites: Set[str] = set()
            bindings = (((data or {}).get("results") or {}).get("bindings"))
            if isinstance(bindings, list):
                for b in bindings:
                    try:
                        pl = (((b or {}).get("parentLabel") or {}).get("value"))
                        sl = (((b or {}).get("subsLabel") or {}).get("value"))
                        bl = (((b or {}).get("brandLabel") or {}).get("value"))
                        site = (((b or {}).get("site") or {}).get("value"))
                        if isinstance(pl, str) and pl.strip():
                            parents.add(pl.strip())
                        if isinstance(sl, str) and sl.strip():
                            subs.add(sl.strip())
                        if isinstance(bl, str) and bl.strip():
                            brands.add(bl.strip())
                        if isinstance(site, str) and site.strip():
                            sites.add(site.strip())
                    except Exception:
                        continue
            return {"parents": parents, "subsidiaries": subs, "brands": brands, "websites": sites}
    except Exception:
        return {"parents": set(), "subsidiaries": set(), "brands": set(), "websites": set()}


async def fetch_company_entities_opencorporates(company_name: str, timeout_seconds: Optional[float] = None, limit: int = 10) -> Set[str]:
    """Fetch related legal entities from OpenCorporates search (if token enabled)."""
    token = os.getenv("OPENCORPORATES_API_TOKEN")
    if not token or not company_name:
        return set()
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 10.0)
    try:
        url = "https://api.opencorporates.com/v0.4/companies/search"
        params = {"q": company_name.strip(), "api_token": token, "per_page": str(limit)}
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            resp = await opencorporates_breaker.call(client.get, url, params=params)
            if not resp or resp.status_code != 200:
                return set()
            data = resp.json()
            names: Set[str] = set()
            comps = (((data or {}).get("results") or {}).get("companies"))
            if isinstance(comps, list):
                for c in comps:
                    try:
                        n = (((c or {}).get("company") or {}).get("name"))
                        if isinstance(n, str) and n.strip():
                            names.add(n.strip())
                    except Exception:
                        continue
            return names
    except Exception:
        return set()


async def fetch_dns_records_doh(name: str, rtype: str, timeout_seconds: Optional[float] = None) -> List[str]:
    """Fetch DNS records via DNS-over-HTTPS (Google DoH).

    Returns a list of record data strings. Best-effort; returns empty list on error.
    """
    name_l = (name or "").strip().lower().rstrip(".")
    if not name_l:
        return []
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 6.0)
    try:
        url = "https://dns.google/resolve"
        params = {"name": name_l, "type": rtype}
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            resp = await doh_breaker.call(_get_with_retries, client, url, params=params)
            if not resp:
                return []
            data = resp.json()
            answers = data.get("Answer") if isinstance(data, dict) else None
            out: List[str] = []
            if isinstance(answers, list):
                for ans in answers:
                    try:
                        dat = str((ans or {}).get("data") or "").strip()
                        if dat:
                            out.append(dat)
                    except Exception:
                        continue
            return out
    except Exception:
        return []


async def resolve_cname_doh(name: str, timeout_seconds: Optional[float] = None) -> List[str]:
    """Resolve CNAME target(s) for a hostname via DoH."""
    try:
        records = await fetch_dns_records_doh(name, "CNAME", timeout_seconds=timeout_seconds)
        hosts: List[str] = []
        for r in records:
            # Google returns target with trailing dot sometimes
            h = r.strip().rstrip(".").lower()
            if h:
                hosts.append(h)
        return list(dict.fromkeys(hosts))
    except Exception:
        return []


def _parse_spf_includes(txt: str) -> Set[str]:
    includes: Set[str] = set()
    try:
        value = str(txt or "")
        tokens = value.replace("\"", "").split()
        for t in tokens:
            t = t.strip()
            if t.startswith("include:"):
                dom = t.split(":", 1)[1].strip().strip('"').rstrip('.')
                if dom:
                    includes.add(dom.lower())
            elif t.startswith("redirect="):
                dom = t.split("=", 1)[1].strip().strip('"').rstrip('.')
                if dom:
                    includes.add(dom.lower())
    except Exception:
        return includes
    return includes


async def enumerate_related_hosts_dns(domain: str, timeout_seconds: Optional[float] = None) -> Dict[str, Set[str]]:
    """Discover related hostnames via NS/MX/SPF relationships for a domain.

    Returns mapping host -> sources like {"dns:ns", "dns:mx", "dns:spf-include"}.
    """
    dom_l = (domain or "").strip().lower().rstrip(".")
    if not dom_l:
        return {}
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 6.0)
    sources: Dict[str, Set[str]] = {}
    seed_rd = get_registered_domain_guess(dom_l) or dom_l
    brand_label = seed_rd.split(".")[0]
    def _is_reasonably_related(host: str) -> bool:
        if host == dom_l or host.endswith("." + dom_l):
            return True
        # allow brand token presence as a label for third-party hosts (e.g., brand.mailgun.org)
        if brand_label and brand_label in host:
            return True
        return False
    try:
        # NS
        ns_records = await fetch_dns_records_doh(dom_l, "NS", timeout_seconds)
        for rec in ns_records:
            host = rec.strip().rstrip(".").lower()
            if not host:
                continue
            if _is_reasonably_related(host):
                sources.setdefault(host, set()).add("dns:ns")
        # MX
        mx_records = await fetch_dns_records_doh(dom_l, "MX", timeout_seconds)
        for rec in mx_records:
            try:
                parts = rec.split()
                target = parts[-1] if parts else rec
                host = target.strip().rstrip(".").lower()
                if host and _is_reasonably_related(host):
                    sources.setdefault(host, set()).add("dns:mx")
            except Exception:
                continue
        # SPF from TXT
        txt_records = await fetch_dns_records_doh(dom_l, "TXT", timeout_seconds)
        for txt in txt_records:
            incs = _parse_spf_includes(txt)
            for idom in incs:
                if _is_reasonably_related(idom):
                    sources.setdefault(idom, set()).add("dns:spf-include")
        return sources
    except Exception:
        return sources


async def discover_cloud_storage_hosts_for_domain(domain: str, timeout_seconds: Optional[float] = None) -> Dict[str, Set[str]]:
    """Heuristically check for cloud storage buckets related to a domain.

    Returns mapping host -> {"cloud:<provider>"} for candidates responding with 200/403.
    """
    dom = (domain or "").strip().lower().rstrip(".")
    if not dom:
        return {}
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 6.0)
    # Name candidates from registered domain
    rd = get_registered_domain_guess(dom) or dom
    base = rd.split(".")[0]
    candidates = list(dict.fromkeys([
        base,
        base.replace("-", ""),
        base.replace("_", ""),
        base + "-static",
        base + "-cdn",
        "static-" + base,
        base + "-assets",
        base + "assets",
        base + "cdn",
        base + "files",
        base + "-files",
        base + "-public",
        base + "public",
        base + "com",
        base + "-com",
    ]))
    # Providers and URL patterns
    patterns: List[Tuple[str, str]] = []
    for name in candidates:
        patterns.extend([
            ("aws-s3", f"https://{name}.s3.amazonaws.com/"),
            ("gcs", f"https://storage.googleapis.com/{name}/"),
            ("gcs", f"https://{name}.storage.googleapis.com/"),
            ("azure-blob", f"https://{name}.blob.core.windows.net/"),
            ("do-spaces", f"https://{name}.digitaloceanspaces.com/"),
            ("cloudflare-r2", f"https://{name}.r2.cloudflarestorage.com/"),
        ])
    results: Dict[str, Set[str]] = {}
    try:
        semaphore = asyncio.Semaphore(16)
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}) as client:
            async def check_one(provider: str, url: str) -> None:
                try:
                    async with semaphore:
                        resp = await client.head(url, follow_redirects=True)
                    status = resp.status_code
                    if status in (200, 204, 206, 301, 302, 401, 403):
                        host = urlparse(url).hostname or ""
                        if host:
                            results.setdefault(host.lower(), set()).add(f"cloud:{provider}")
                except Exception:
                    return
            tasks = [asyncio.create_task(check_one(p, u)) for (p, u) in patterns]
            if tasks:
                await asyncio.gather(*tasks)
        return results
    except Exception:
        return results


async def crawl_site_discover_hosts(domain: str, timeout_seconds: Optional[float] = None, max_bytes: int = 300_000) -> Dict[str, Set[str]]:
    """Fetch the homepage(s) for a domain and extract hostnames.

    Returns mapping host -> {"crawl"} limited to hosts under the domain suffix.
    """
    dom = (domain or "").strip().lower().rstrip(".")
    if not dom:
        return {}
    if timeout_seconds is None:
        timeout_seconds = min(settings.http_timeout_seconds, 8.0)
    urls = [f"https://{dom}/", f"http://{dom}/", f"https://www.{dom}/", f"http://www.{dom}/"]
    results: Dict[str, Set[str]] = {}
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "EASM/0.2"}, follow_redirects=True) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    text = (resp.text or "")[:max_bytes]
                    # rudimentary host extraction
                    import re
                    for match in re.findall(r"\b([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+)\b", text, flags=re.IGNORECASE):
                        h = match.strip().lower()
                        if h.startswith("*."):
                            h = h[2:]
                        if h == dom or h.endswith("." + dom):
                            results.setdefault(h, set()).add("crawl")
                except Exception:
                    continue
        return results
    except Exception:
        return results
