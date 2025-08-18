"""Service for handling scan operations."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings, COMMON_PORTS
from ..exceptions import ExternalServiceException
from ..models import AssetORM, AssetType, FindingORM, ScanORM, SeedORM, SeedType
from ..modules import (
    enumerate_subdomains_by_organization_crtsh,
    enumerate_subdomains_with_sources,
    enumerate_hostnames_shodan_by_org,
    expand_cidr,
    extract_organization_names_from_subject,
    fetch_tls_certificate_summary,
    http_probe,
    is_ip,
    resolve_hostnames,
    reverse_dns_ips,
    tcp_scan_ports,
)
from ..repos import AssetRepository, FindingRepository, ScanRepository, SeedRepository
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


class ScanService:
    """Service for managing scan operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.scan_repo = ScanRepository(session)
        self.finding_repo = FindingRepository(session)
        self.asset_repo = AssetRepository(session)
        self.seed_repo = SeedRepository(session)
    
    async def process_scan(self, scan_id: str, target: str, options: dict) -> None:
        """Process a scan with proper error handling and status updates."""
        scan = await self.scan_repo.get(scan_id)
        if not scan:
            logger.warning("scan.missing", extra={"scan_id": scan_id, "target": target})
            return
        
        try:
            # Mark scan as running
            await self._update_scan_status(scan, "running")
            await self._mark_asset_scan_started(target, scan_id)
            
            # Process the scan based on target type
            if "/" in target and not target.endswith("."):
                # CIDR scan
                await self._process_cidr_scan(scan, target, options)
            elif is_ip(target):
                # IP scan
                await self._process_ip_scan(scan, target, options)
            else:
                # Domain scan
                await self._process_domain_scan(scan, target, options)
            
            # Mark scan as completed
            await self._update_scan_status(scan, "completed")
            await self._mark_asset_scan_finished(target, scan_id, "completed")
            logger.info("scan.completed", extra={"scan_id": scan_id, "target": target})
            
        except Exception as e:
            logger.exception("scan.failed", extra={"scan_id": scan_id, "target": target})
            await self._update_scan_status(scan, "failed")
            await self._mark_asset_scan_finished(target, scan_id, "failed")
            raise
    
    async def _process_cidr_scan(self, scan: ScanORM, cidr: str, options: dict) -> None:
        """Process a CIDR range scan."""
        max_hosts = options.get("max_hosts", settings.max_cidr_hosts)
        ips = expand_cidr(cidr, max_hosts=max_hosts)
        
        # Create findings for expanded IPs
        for ip in ips[:200]:  # Limit findings to avoid spam
            await self._create_finding(
                scan_id=scan.id,
                category="cidr",
                title=f"Host {ip} in {cidr}",
                severity="info",
                data={"ip": ip}
            )
        
        # Process port scanning for IPs if enabled
        if options.get("scan_common_ports", True):
            await self._scan_hosts(scan, ips[:50], options)  # Limit to first 50 IPs
    
    async def _process_ip_scan(self, scan: ScanORM, ip: str, options: dict) -> None:
        """Process a single IP scan."""
        ips = [ip]
        
        # Reverse DNS
        if options.get("reverse_dns", True):
            await self._perform_reverse_dns(scan, ips)
        
        # Port scanning
        if options.get("scan_common_ports", True):
            await self._scan_hosts(scan, ips, options)
    
    async def _process_domain_scan(self, scan: ScanORM, domain: str, options: dict) -> None:
        """Process a domain scan."""
        hostnames = [domain]
        
        # Subdomain enumeration
        if options.get("enumerate_subdomains", True) and "." in domain:
            subdomains = await self._enumerate_subdomains(scan, domain)
            hostnames.extend(subdomains)
        
        # DNS resolution
        ips = []
        if options.get("resolve_dns", True) and hostnames:
            resolved_ips = await self._resolve_dns(scan, hostnames)
            ips.extend(resolved_ips)
        
        # Reverse DNS
        if options.get("reverse_dns", True) and ips:
            await self._perform_reverse_dns(scan, ips)
        
        # Port scanning
        if options.get("scan_common_ports", True):
            await self._scan_hosts(scan, hostnames + ips, options)
    
    async def _enumerate_subdomains(self, scan: ScanORM, domain: str) -> List[str]:
        """Enumerate subdomains and create findings."""
        try:
            subs_map = await enumerate_subdomains_with_sources(domain, timeout_seconds=settings.subdomain_enum_timeout)
            subdomains = list(subs_map.keys())
            
            # Create findings for discovered subdomains
            for subdomain in sorted(subdomains)[:500]:  # Limit to 500 findings
                await self._create_finding(
                    scan_id=scan.id,
                    category="subdomain",
                    title=f"Discovered subdomain {subdomain}",
                    severity="info",
                    data={
                        "hostname": subdomain,
                        "sources": sorted(list(subs_map.get(subdomain, set())))
                    }
                )
            
            return subdomains
        except Exception as e:
            logger.error("subdomain_enumeration_failed", extra={"domain": domain, "error": str(e)})
            return []
    
    async def _resolve_dns(self, scan: ScanORM, hostnames: List[str]) -> List[str]:
        """Resolve hostnames to IPs and create findings."""
        try:
            resolutions = await resolve_hostnames(hostnames)
            all_ips = []
            
            for host, ips in resolutions.items():
                if ips:
                    all_ips.extend(ips)
                    await self._create_finding(
                        scan_id=scan.id,
                        category="dns",
                        title=f"DNS resolution for {host}",
                        severity="info",
                        data={"ips": ips}
                    )
            
            return all_ips
        except Exception as e:
            logger.error("dns_resolution_failed", extra={"error": str(e)})
            return []
    
    async def _perform_reverse_dns(self, scan: ScanORM, ips: List[str]) -> Dict[str, Optional[str]]:
        """Perform reverse DNS lookups and create findings."""
        try:
            ptrs = await reverse_dns_ips(ips)
            
            for ip, ptr in ptrs.items():
                await self._create_finding(
                    scan_id=scan.id,
                    category="rdns",
                    title=f"PTR for {ip}: {ptr or 'None'}",
                    severity="info",
                    data={"ip": ip, "ptr": ptr}
                )
            
            return ptrs
        except Exception as e:
            logger.error("reverse_dns_failed", extra={"error": str(e)})
            return {}
    
    async def _scan_hosts(self, scan: ScanORM, hosts: List[str], options: dict) -> None:
        """Scan ports on hosts and perform additional probes."""
        common_ports = options.get("common_ports", COMMON_PORTS)
        aggregated_open_ports: Dict[str, List[int]] = {}
        
        for host in list(dict.fromkeys(hosts)):  # Remove duplicates
            try:
                # TCP port scan
                open_ports = await tcp_scan_ports(
                    host, 
                    common_ports,
                    connect_timeout_seconds=settings.tcp_scan_timeout,
                    limit_concurrency=settings.tcp_scan_concurrency
                )
                
                if open_ports:
                    aggregated_open_ports[host] = open_ports
                    await self._create_finding(
                        scan_id=scan.id,
                        category="network",
                        title=f"Open ports on {host}: {', '.join(map(str, open_ports))}",
                        severity="info",
                        data={"host": host, "open_ports": open_ports}
                    )
                    
                    # HTTP probe
                    if options.get("http_probe", True):
                        await self._http_probe_host(scan, host, open_ports)
                    
                    # TLS info
                    if options.get("tls_info", True) and 443 in open_ports:
                        await self._fetch_tls_info(scan, host)
                        
            except Exception as e:
                logger.error("host_scan_failed", extra={"host": host, "error": str(e)})
        
        # Detect port drift if this is a re-scan
        await self._detect_port_drift(scan, scan.target, aggregated_open_ports)
    
    async def _http_probe_host(self, scan: ScanORM, host: str, open_ports: List[int]) -> None:
        """Probe HTTP services on open web ports."""
        web_ports = [p for p in open_ports if p in {80, 443, 8080, 8443}]
        
        for port in web_ports:
            try:
                result = await http_probe(host, port, timeout_seconds=settings.http_timeout_seconds)
                if result:
                    await self._create_finding(
                        scan_id=scan.id,
                        category="http",
                        title=f"HTTP probe {host}:{port} {result['status']}",
                        severity="info",
                        data={"host": host, "port": port, **result}
                    )
            except Exception as e:
                logger.error("http_probe_failed", extra={"host": host, "port": port, "error": str(e)})
    
    async def _fetch_tls_info(self, scan: ScanORM, host: str) -> None:
        """Fetch TLS certificate information."""
        try:
            tls_info = await asyncio.to_thread(
                fetch_tls_certificate_summary, 
                host, 
                443, 
                timeout_seconds=settings.tls_timeout_seconds
            )
            
            if tls_info:
                await self._create_finding(
                    scan_id=scan.id,
                    category="tls",
                    title=f"TLS certificate for {host}",
                    severity="info",
                    data={"host": host, **tls_info}
                )
                
                # Extract organizations from certificate
                await self._process_tls_organizations(scan, host, tls_info)
                
        except Exception as e:
            logger.error("tls_fetch_failed", extra={"host": host, "error": str(e)})
    
    async def _process_tls_organizations(self, scan: ScanORM, host: str, tls_info: dict) -> None:
        """Process organizations found in TLS certificates."""
        orgs = extract_organization_names_from_subject(tls_info.get("subject"))
        if not orgs:
            return
        
        for org_name in orgs:
            org_name = org_name.strip()
            if not org_name:
                continue
            
            # Create or get organization seed
            existing_seed = await self.seed_repo.get_by_type_value(SeedType.organization, org_name)
            if not existing_seed:
                now = datetime.now(timezone.utc)
                org_seed = SeedORM(
                    id=str(uuid.uuid4()),
                    seed_type=SeedType.organization,
                    value=org_name,
                    note=f"origin_path=[seed:scan_target {host} -> organization:{org_name}]",
                    created_at=now,
                    updated_at=now,
                )
                await self.seed_repo.create(org_seed)
                await self.session.commit()
            
            # Enumerate organization assets
            await self._enumerate_organization_assets(org_name, host)
    
    async def _enumerate_organization_assets(self, org_name: str, origin_host: str) -> None:
        """Enumerate assets for an organization."""
        try:
            # Get hosts from multiple sources
            crt_hosts = await enumerate_subdomains_by_organization_crtsh(org_name)
            shodan_hosts = await enumerate_hostnames_shodan_by_org(org_name)
            
            logger.info("discovery.org_hosts", extra={
                "organization": org_name,
                "crt": len(crt_hosts),
                "shodan": len(shodan_hosts)
            })
            
            # Build source map
            sources_map: Dict[str, Set[str]] = {}
            for h in crt_hosts:
                sources_map.setdefault(h, set()).add("crtsh:organization")
            for h in shodan_hosts:
                sources_map.setdefault(h, set()).add("shodan:organization")
            
            # Create assets
            now = datetime.now(timezone.utc)
            for hostname in sorted(list(sources_map.keys()))[:500]:  # Limit to 500
                asset_id = str(uuid.uuid4())
                candidate = AssetORM(
                    id=asset_id,
                    asset_type=AssetType.domain,
                    value=hostname,
                    ownership_confidence=0.5,
                    sources=sorted(list(sources_map.get(hostname, {"organization"}))),
                    details={
                        "origin_path": [f"seed:scan_target {origin_host}", f"organization:{org_name}", f"asset:{hostname}"],
                        "organization": org_name,
                    },
                    created_at=now,
                    updated_at=now,
                )
                await self.asset_repo.create_or_merge(candidate)
            
            await self.session.commit()
            
        except Exception as e:
            logger.error("org_enumeration_failed", extra={"org": org_name, "error": str(e)})
    
    async def _detect_port_drift(self, scan: ScanORM, target: str, current_ports: Dict[str, List[int]]) -> None:
        """Detect changes in open ports compared to previous scans."""
        try:
            asset_type = AssetType.domain if "." in target and "/" not in target and not is_ip(target) else AssetType.ip
            asset = await self.asset_repo.get_by_type_value(asset_type, target)
            
            if not asset:
                return
            
            # Get previous port state
            details = dict(asset.details or {})
            last_ports_obj = details.get("last_open_ports_by_host")
            last_ports: Dict[str, List[int]] = {}
            
            if isinstance(last_ports_obj, dict):
                try:
                    last_ports = {str(k): [int(x) for x in (v or [])] for k, v in last_ports_obj.items()}
                except Exception:
                    last_ports = {}
            
            # Compare and create drift findings
            for host, current in current_ports.items():
                previous = set(last_ports.get(host, []))
                current_set = set(current)
                opened = sorted(list(current_set - previous))
                closed = sorted(list(previous - current_set))
                
                if opened or closed:
                    await self._create_finding(
                        scan_id=scan.id,
                        category="drift",
                        title=f"Port drift on {host}",
                        severity="info",
                        data={"opened": opened, "closed": closed}
                    )
            
            # Update asset with current port state
            details["last_open_ports_by_host"] = current_ports
            asset.details = details
            asset.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            
        except Exception as e:
            logger.error("drift_detection_failed", extra={"target": target, "error": str(e)})
    
    async def _create_finding(self, scan_id: str, category: str, title: str, severity: str, data: dict) -> None:
        """Create a finding and commit to database."""
        finding_id = str(uuid.uuid4())
        finding = FindingORM(
            id=finding_id,
            scan_id=scan_id,
            category=category,
            title=title,
            severity=severity,
            data=data,
        )
        await self.finding_repo.create(finding)
        await self.session.commit()
    
    async def _update_scan_status(self, scan: ScanORM, status: str) -> None:
        """Update scan status and commit."""
        scan.status = status
        scan.updated_at = datetime.now(timezone.utc)
        await self.session.commit()
    
    async def _mark_asset_scan_started(self, target: str, scan_id: str) -> None:
        """Mark asset as having a scan in progress."""
        try:
            asset_type = AssetType.domain if "." in target and "/" not in target and not is_ip(target) else AssetType.ip
            await self.asset_repo.mark_scan_started(asset_type, target, scan_id, datetime.now(timezone.utc))
            await self.session.commit()
        except Exception:
            pass  # Non-critical
    
    async def _mark_asset_scan_finished(self, target: str, scan_id: str, status: str) -> None:
        """Mark asset scan as finished."""
        try:
            asset_type = AssetType.domain if "." in target and "/" not in target and not is_ip(target) else AssetType.ip
            await self.asset_repo.mark_scan_finished(asset_type, target, scan_id, status, datetime.now(timezone.utc))
            await self.session.commit()
        except Exception:
            pass  # Non-critical
