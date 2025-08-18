"""Service for handling asset discovery operations."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import AssetORM, AssetType, ScanORM, SeedORM, SeedType
from ..modules import (
    enumerate_hostnames_shodan_by_asn,
    enumerate_hostnames_shodan_by_org,
    enumerate_subdomains_by_organization_crtsh,
    enumerate_subdomains_with_sources,
    enumerate_related_hosts_dns,
    discover_cloud_storage_hosts_for_domain,
    crawl_site_discover_hosts,
    expand_cidr,
    extract_organization_names_from_subject,
    fetch_asn_prefixes_bgpview,
    fetch_domain_rdap_emails,
    fetch_tls_certificate_summary,
    get_registered_domain_guess,
    resolve_cname_doh,
    enrich_company_from_domain,
    fetch_company_graph_wikidata,
    fetch_company_entities_opencorporates,
    is_ip,
    resolve_hostnames,
    reverse_dns_ips,
)
from ..repos import AssetRepository, ScanRepository, SeedRepository
from pydantic import BaseModel, Field


class ScanOptions(BaseModel):
    enumerate_subdomains: bool = Field(True)
    resolve_dns: bool = Field(True)
    reverse_dns: bool = Field(True)
    scan_common_ports: bool = Field(True)
    http_probe: bool = Field(True)
    tls_info: bool = Field(True)
    common_ports: list[int] = Field(default_factory=lambda: [80, 443, 22, 25, 53, 110, 143, 587, 993, 995, 3306, 5432, 6379, 8080, 8443])
    max_hosts: int = Field(4096, ge=1, le=20000)

from ..main import _run_scan
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


class DiscoveryService:
    """Service for managing asset discovery operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.seed_repo = SeedRepository(session)
        self.asset_repo = AssetRepository(session)
        self.scan_repo = ScanRepository(session)
    
    async def discover_from_seeds(self, confidence_threshold: float, include_scan: bool) -> Tuple[int, int]:
        """Discover assets from configured seeds."""
        discovered = 0
        scheduled = 0
        
        seeds = await self.seed_repo.list()
        if not seeds:
            return (0, 0)
        
        # Categorize seeds by type
        seed_groups = self._categorize_seeds(seeds)
        
        # Initialize tracking sets
        tracking = DiscoveryTracking()
        
        # Process different seed types
        discovered_domains = await self._discover_from_domain_seeds(
            seed_groups["domains"],
            seed_groups["orgs"],
            tracking,
            confidence_threshold,
            include_scan
        )
        discovered += discovered_domains["discovered"]
        scheduled += discovered_domains["scheduled"]
        
        # Process ASN seeds
        asn_results = await self._discover_from_asn_seeds(
            seed_groups["asns"],
            seed_groups["domains"],
            confidence_threshold,
            include_scan,
            tracking
        )
        discovered += asn_results["discovered"]
        scheduled += asn_results["scheduled"]
        
        # Process CIDR seeds
        cidr_results = await self._discover_from_cidr_seeds(
            seed_groups["cidrs"],
            seed_groups["asns"],
            confidence_threshold,
            include_scan
        )
        discovered += cidr_results["discovered"]
        scheduled += cidr_results["scheduled"]
        
        return (discovered, scheduled)
    
    def _categorize_seeds(self, seeds: List[SeedORM]) -> Dict[str, Set[str]]:
        """Categorize seeds by type."""
        return {
            "domains": set(
                s.value.strip().lower() 
                for s in seeds 
                if s.seed_type in {SeedType.root_domain, SeedType.acquisition_domain}
            ),
            "cidrs": set(s.value.strip() for s in seeds if s.seed_type == SeedType.cidr),
            "orgs": set(s.value.strip() for s in seeds if s.seed_type == SeedType.organization),
            "asns": set(s.value.strip() for s in seeds if s.seed_type == SeedType.asn),
        }
    
    async def _discover_from_domain_seeds(
        self,
        seed_domains: Set[str],
        seed_orgs: Set[str],
        tracking: 'DiscoveryTracking',
        confidence_threshold: float,
        include_scan: bool
    ) -> Dict[str, int]:
        """Discover assets from domain and organization seeds."""
        discovered = 0
        scheduled = 0
        
        # Initialize queues
        tracking.known_orgs.update(seed_orgs)
        pending_domains = [(d, [f"seed:domain {d}"]) for d in seed_domains]
        pending_orgs = [(o, [f"seed:organization {o}"]) for o in seed_orgs]
        
        # Process domains and organizations iteratively
        while pending_domains or pending_orgs:
            if pending_domains:
                domain, origin_path = pending_domains.pop(0)
                if domain in tracking.visited_domains:
                    continue
                
                results = await self._process_domain_discovery(
                    domain, origin_path, seed_domains, tracking, confidence_threshold, include_scan
                )
                discovered += results["discovered"]
                scheduled += results["scheduled"]
                
                # Add discovered domains and orgs to queues
                pending_domains.extend(results["new_domains"])
                pending_orgs.extend(results["new_orgs"])
            
            if pending_orgs:
                org_name, origin_path = pending_orgs.pop(0)
                if org_name in tracking.visited_orgs:
                    continue
                
                results = await self._process_organization_discovery(
                    org_name, origin_path, seed_domains, tracking, confidence_threshold, include_scan
                )
                discovered += results["discovered"]
                scheduled += results["scheduled"]
                
                # Add discovered domains and orgs to queues
                pending_domains.extend(results["new_domains"])
                pending_orgs.extend(results["new_orgs"])
        
        return {"discovered": discovered, "scheduled": scheduled}
    
    async def _process_domain_discovery(
        self,
        domain: str,
        origin_path: List[str],
        seed_domains: Set[str],
        tracking: 'DiscoveryTracking',
        confidence_threshold: float,
        include_scan: bool
    ) -> Dict[str, any]:
        """Process discovery for a single domain."""
        tracking.visited_domains.add(domain)
        discovered = 0
        scheduled = 0
        new_domains = []
        new_orgs = []
        
        # Enumerate subdomains
        names_by_source = await enumerate_subdomains_with_sources(domain, timeout_seconds=settings.subdomain_enum_timeout)
        names = set(names_by_source.keys())

        # Optional DNS relationship expansion (NS/MX/SPF)
        if settings.enable_dns_record_expansion:
            related_dns = await enumerate_related_hosts_dns(domain)
            for h, srcs in related_dns.items():
                names_by_source.setdefault(h, set()).update(srcs)
                names.add(h)

        # Optional CNAME expansion for discovered names
        if settings.enable_dns_record_expansion and names:
            for host in list(names)[:500]:
                try:
                    cnames = await resolve_cname_doh(host)
                    for target in cnames:
                        names_by_source.setdefault(target, set()).add("dns:cname")
                        names.add(target)
                except Exception:
                    continue

        # Optional cloud storage discovery
        if settings.enable_cloud_storage_discovery:
            cloud_map = await discover_cloud_storage_hosts_for_domain(domain)
            for h, srcs in cloud_map.items():
                names_by_source.setdefault(h, set()).update(srcs)
                names.add(h)

        # Optional shallow web crawl of seed domain(s) to extract first-party hosts
        if settings.enable_web_crawl:
            crawled = await crawl_site_discover_hosts(domain)
            for h, srcs in crawled.items():
                names_by_source.setdefault(h, set()).update(srcs)
                names.add(h)
        names.add(domain)
        
        for hostname in names:
            # Skip if already processed
            if hostname in tracking.processed_hosts:
                continue
            
            # Get additional information
            host_info = await self._gather_host_info(hostname)
            
            # Calculate ownership confidence
            confidence = self._calculate_ownership_confidence(
                hostname,
                host_info["san_list"],
                host_info["ptr"],
                seed_domains,
                host_info["rdap_emails"]
            )
            
            # Create or merge asset
            # Determine confidence; related hosts may have lower baseline
            base_conf = confidence
            if any(s.startswith("dns:") or s.startswith("cloud:") for s in names_by_source.get(hostname, set())):
                base_conf = max(base_conf, settings.related_asset_confidence_default)

            asset_data = self._build_asset_data(
                hostname,
                base_conf,
                sorted(list(names_by_source.get(hostname, set()))) or ["seed:domain"],
                origin_path,
                host_info
            )
            
            asset_row, created = await self.asset_repo.create_or_merge(asset_data)
            await self.session.commit()
            
            if created:
                discovered += 1
            
            # Schedule scan if confidence meets threshold
            if include_scan and asset_row.ownership_confidence >= confidence_threshold:
                if hostname not in tracking.scheduled_targets and not await self._has_existing_scan(hostname):
                    scan_id = await self._schedule_scan(hostname, asset_row.ownership_confidence, "discovery")
                    if scan_id:
                        scheduled += 1
                        tracking.scheduled_targets.add(hostname)
            
            # Extract organizations from TLS
            if host_info["tls"]:
                orgs = extract_organization_names_from_subject(host_info["tls"].get("subject"))
                for org in orgs:
                    org_key = org.strip()
                    if org_key and org_key not in tracking.known_orgs:
                        await self._create_organization_seed(org_key, origin_path)
                        tracking.known_orgs.add(org_key)
                        new_orgs.append((org_key, origin_path + [f"organization:{org_key}"]))
            
            # Mark as processed and potentially queue for subdomain enumeration
            tracking.processed_hosts.add(hostname)
            if hostname not in tracking.enqueued_domains:
                new_domains.append((hostname, origin_path))
                tracking.enqueued_domains.add(hostname)
        
        return {
            "discovered": discovered,
            "scheduled": scheduled,
            "new_domains": new_domains,
            "new_orgs": new_orgs,
        }
    
    async def _process_organization_discovery(
        self,
        org_name: str,
        origin_path: List[str],
        seed_domains: Set[str],
        tracking: 'DiscoveryTracking',
        confidence_threshold: float,
        include_scan: bool
    ) -> Dict[str, any]:
        """Process discovery for an organization."""
        tracking.visited_orgs.add(org_name)
        discovered = 0
        scheduled = 0
        new_domains = []
        new_orgs = []
        
        # Enumerate hostnames for organization
        logger.info("discovery.search_org", extra={"organization": org_name})
        org_hosts_crt = await enumerate_subdomains_by_organization_crtsh(org_name)
        org_hosts_shodan = await enumerate_hostnames_shodan_by_org(org_name)
        
        if not org_hosts_crt and not org_hosts_shodan:
            # Try knowledge graph enrichment for subsidiaries/brands and websites
            extra_domains: Set[str] = set()
            if settings.enable_wikidata:
                kg = await fetch_company_graph_wikidata(org_name)
                for site in kg.get("websites", set()):
                    try:
                        h = site.strip().lower()
                        # normalize hostname from URL if needed
                        from urllib.parse import urlparse
                        hh = urlparse(h).hostname or h
                        if hh and "." in hh:
                            extra_domains.add(hh)
                    except Exception:
                        continue
                # Add subsidiaries/brands as new org seeds
                for sub in sorted(kg.get("subsidiaries", set()) | kg.get("brands", set())):
                    sub_key = sub.strip()
                    if sub_key and sub_key not in tracking.known_orgs:
                        await self._create_organization_seed(sub_key, origin_path)
                        tracking.known_orgs.add(sub_key)
                        new_orgs.append((sub_key, origin_path + [f"organization:{sub_key}"]))
            # OpenCorporates related names → new org seeds
            if settings.enable_opencorporates:
                oc = await fetch_company_entities_opencorporates(org_name)
                for ocn in sorted(oc):
                    if ocn and ocn not in tracking.known_orgs:
                        await self._create_organization_seed(ocn, origin_path)
                        tracking.known_orgs.add(ocn)
                        new_orgs.append((ocn, origin_path + [f"organization:{ocn}"]))
            # Process any website domains discovered from Wikidata
            if extra_domains:
                for d in sorted(extra_domains)[:50]:
                    new_domains.append((d, origin_path + [f"website:{d}"]))
            return {"discovered": 0, "scheduled": 0, "new_domains": new_domains, "new_orgs": new_orgs}
        
        # Build source map
        org_sources: Dict[str, Set[str]] = {}
        for h in org_hosts_crt:
            org_sources.setdefault(h.strip().lower(), set()).add("crtsh:organization")
        for h in org_hosts_shodan:
            org_sources.setdefault(h.strip().lower(), set()).add("shodan:organization")
        
        # Process discovered hostnames
        for hostname in sorted(list(org_sources.keys()))[:500]:  # Limit to 500
            if hostname in tracking.processed_hosts:
                continue
            
            # Get additional information
            host_info = await self._gather_host_info(hostname)
            
            # Calculate ownership confidence
            confidence = self._calculate_ownership_confidence(
                hostname,
                host_info["san_list"],
                host_info["ptr"],
                seed_domains,
                host_info["rdap_emails"]
            )
            
            # Create or merge asset
            asset_data = self._build_asset_data(
                hostname,
                confidence,
                sorted(list(org_sources.get(hostname, {"organization"}))),
                origin_path,
                host_info,
                organization=org_name
            )
            
            asset_row, created = await self.asset_repo.create_or_merge(asset_data)
            await self.session.commit()
            
            if created:
                discovered += 1
            
            # Schedule scan if confidence meets threshold
            if include_scan and asset_row.ownership_confidence >= confidence_threshold:
                if hostname not in tracking.scheduled_targets and not await self._has_existing_scan(hostname):
                    scan_id = await self._schedule_scan(
                        hostname, 
                        asset_row.ownership_confidence, 
                        f"org discovery"
                    )
                    if scan_id:
                        scheduled += 1
                        tracking.scheduled_targets.add(hostname)
            
            # Extract new organizations from TLS
            if host_info["tls"]:
                orgs = extract_organization_names_from_subject(host_info["tls"].get("subject"))
                for new_org in orgs:
                    org_key = new_org.strip()
                    if org_key and org_key not in tracking.known_orgs:
                        await self._create_organization_seed(org_key, origin_path)
                        tracking.known_orgs.add(org_key)
                        new_orgs.append((org_key, origin_path + [f"organization:{org_key}"]))

            # Enrich org from host’s registered domain to discover official company name and potential aliases
            try:
                reg_dom = get_registered_domain_guess(hostname)
                if reg_dom:
                    info = await enrich_company_from_domain(reg_dom)
                    comp = info.get("company_name")
                    if comp and comp not in tracking.known_orgs:
                        await self._create_organization_seed(comp, origin_path)
                        tracking.known_orgs.add(comp)
                        new_orgs.append((comp, origin_path + [f"organization:{comp}"]))
            except Exception:
                pass
            
            # Mark as processed and queue for subdomain enumeration
            tracking.processed_hosts.add(hostname)
            if hostname not in tracking.enqueued_domains:
                new_domains.append((hostname, origin_path))
                tracking.enqueued_domains.add(hostname)
        
        return {
            "discovered": discovered,
            "scheduled": scheduled,
            "new_domains": new_domains,
            "new_orgs": new_orgs,
        }
    
    async def _discover_from_asn_seeds(
        self,
        seed_asns: Set[str],
        seed_domains: Set[str],
        confidence_threshold: float,
        include_scan: bool,
        tracking: 'DiscoveryTracking'
    ) -> Dict[str, int]:
        """Discover assets from ASN seeds."""
        discovered = 0
        scheduled = 0
        
        for asn in seed_asns:
            try:
                # Get prefixes for ASN
                prefixes = await fetch_asn_prefixes_bgpview(asn)
                logger.info("discovery.asn_prefixes", extra={"asn": asn, "count": len(prefixes)})
                
                # Enumerate hostnames via Shodan
                shodan_hosts = await enumerate_hostnames_shodan_by_asn(asn)
                logger.info("discovery.asn_hosts", extra={"asn": asn, "count": len(shodan_hosts)})
                
                # Process discovered hosts
                for hostname in sorted(list(shodan_hosts))[:500]:  # Limit to 500
                    host_info = await self._gather_host_info(hostname)
                    
                    confidence = self._calculate_ownership_confidence(
                        hostname,
                        host_info["san_list"],
                        host_info["ptr"],
                        seed_domains,
                        None  # No RDAP for ASN discovery
                    )
                    
                    asset_data = self._build_asset_data(
                        hostname,
                        max(0.6, confidence),  # Minimum 0.6 confidence for ASN discovery
                        ["shodan:asn"],
                        [f"seed:asn {asn}", f"asset:{hostname}"],
                        host_info,
                        asn=asn
                    )
                    
                    asset_row, created = await self.asset_repo.create_or_merge(asset_data)
                    await self.session.commit()
                    
                    if created:
                        discovered += 1
                    
                    if include_scan and asset_row.ownership_confidence >= confidence_threshold:
                        if hostname not in tracking.scheduled_targets and not await self._has_existing_scan(hostname):
                            scan_id = await self._schedule_scan(
                                hostname,
                                asset_row.ownership_confidence,
                                f"ASN discovery"
                            )
                            if scan_id:
                                scheduled += 1
                                tracking.scheduled_targets.add(hostname)
                
            except Exception as e:
                logger.error("asn_discovery_failed", extra={"asn": asn, "error": str(e)})
        
        return {"discovered": discovered, "scheduled": scheduled}
    
    async def _discover_from_cidr_seeds(
        self,
        seed_cidrs: Set[str],
        discovered_cidrs_from_asns: Set[str],
        confidence_threshold: float,
        include_scan: bool
    ) -> Dict[str, int]:
        """Discover assets from CIDR seeds."""
        discovered = 0
        scheduled = 0
        
        all_cidrs = seed_cidrs | discovered_cidrs_from_asns
        
        for cidr in all_cidrs:
            ips = expand_cidr(cidr, max_hosts=1024)
            
            for ip in ips[:256]:  # Cap to avoid explosion
                now = datetime.now(timezone.utc)
                asset_data = AssetORM(
                    id=str(uuid.uuid4()),
                    asset_type=AssetType.ip,
                    value=ip,
                    ownership_confidence=0.7,
                    sources=["seed:cidr"],
                    details={"cidr": cidr, "origin_path": [f"seed:cidr {cidr}"]},
                    created_at=now,
                    updated_at=now,
                )
                
                asset_row, created = await self.asset_repo.create_or_merge(asset_data)
                await self.session.commit()
                
                if created:
                    discovered += 1
                
                if include_scan and asset_row.ownership_confidence >= confidence_threshold:
                    if not await self._has_existing_scan(ip) and not await self._has_completed_scan(ip):
                        scan_id = await self._schedule_scan(ip, 0.7, "CIDR discovery")
                        if scan_id:
                            scheduled += 1
        
        return {"discovered": discovered, "scheduled": scheduled}
    
    async def _gather_host_info(self, hostname: str) -> Dict[str, any]:
        """Gather DNS, reverse DNS, and TLS information for a host."""
        info = {
            "ips": [],
            "ptr": None,
            "tls": None,
            "san_list": None,
            "rdap_emails": set(),
        }
        
        try:
            # DNS resolution
            ips_by_host = await resolve_hostnames([hostname])
            info["ips"] = ips_by_host.get(hostname, [])
            
            # Reverse DNS
            if info["ips"]:
                ptr_map = await reverse_dns_ips(info["ips"])
                info["ptr"] = next((v for v in ptr_map.values() if v), None)
            
            # TLS certificate
            if info["ips"]:
                info["tls"] = await asyncio.to_thread(
                    fetch_tls_certificate_summary,
                    hostname,
                    443,
                    timeout_seconds=settings.tls_timeout_seconds
                )
                if info["tls"]:
                    info["san_list"] = info["tls"].get("subject_alt_names")
            
            # RDAP/WHOIS emails
            reg_domain = get_registered_domain_guess(hostname)
            if reg_domain:
                info["rdap_emails"] = await fetch_domain_rdap_emails(reg_domain)
                
        except Exception as e:
            logger.error("host_info_gathering_failed", extra={"hostname": hostname, "error": str(e)})
        
        return info
    
    def _calculate_ownership_confidence(
        self,
        hostname: str,
        tls_alt_names: Optional[List[str]],
        ptr: Optional[str],
        seed_domains: Set[str],
        whois_emails: Optional[Set[str]] = None
    ) -> float:
        """Calculate ownership confidence score for a hostname."""
        score = 0.0
        hostname_l = hostname.lower()
        
        # rDNS suffix match
        if ptr:
            for d in seed_domains:
                if ptr.lower().endswith(d.lower()):
                    score += 0.4
                    break
        
        # Certificate SAN match
        if tls_alt_names:
            for san in tls_alt_names:
                for d in seed_domains:
                    if san.lower().endswith(d.lower()):
                        score += 0.5
                        break
        
        # WHOIS/RDAP email domain match
        if whois_emails:
            email_domains: Set[str] = set()
            for e in whois_emails:
                try:
                    _, dom = str(e).lower().split("@", 1)
                    rd = get_registered_domain_guess(dom)
                    if rd:
                        email_domains.add(rd)
                except Exception:
                    continue
            
            if email_domains:
                for d in seed_domains:
                    d_l = d.lower()
                    if any(ed == d_l or ed.endswith("." + d_l) for ed in email_domains):
                        score += 0.5
                        break
        
        # Domain suffix match
        for d in seed_domains:
            if hostname_l == d.lower() or hostname_l.endswith("." + d.lower()):
                score += 0.5
                break
        
        # Cap between 0 and 1
        return max(0.0, min(1.0, score))
    
    def _build_asset_data(
        self,
        hostname: str,
        confidence: float,
        sources: List[str],
        origin_path: List[str],
        host_info: Dict[str, any],
        organization: Optional[str] = None,
        asn: Optional[str] = None
    ) -> AssetORM:
        """Build asset ORM object."""
        now = datetime.now(timezone.utc)
        # Normalize sources to a JSON-serializable list of strings
        try:
            sources_list = sources if isinstance(sources, list) else sorted(list(sources))
            sources_list = [str(s) for s in sources_list]
        except Exception:
            sources_list = ["seed:domain"]
        details = {
            "ips": host_info["ips"],
            "ptr": host_info["ptr"],
            "tls": {"subject_alt_names": host_info["san_list"]} if host_info["san_list"] else {},
            "origin_path": origin_path + [f"asset:{hostname}"],
            "whois_emails": sorted(list(host_info["rdap_emails"])) if host_info["rdap_emails"] else [],
        }
        
        if organization:
            details["organization"] = organization
        if asn:
            details["asn"] = asn
        
        return AssetORM(
            id=str(uuid.uuid4()),
            asset_type=AssetType.domain,
            value=hostname,
            ownership_confidence=confidence,
            sources=sources_list,
            details=details,
            created_at=now,
            updated_at=now,
        )
    
    async def _create_organization_seed(self, org_name: str, origin_path: List[str]) -> None:
        """Create an organization seed."""
        now = datetime.now(timezone.utc)
        org_seed = SeedORM(
            id=str(uuid.uuid4()),
            seed_type=SeedType.organization,
            value=org_name,
            note=f"origin_path=[{' -> '.join(origin_path + [f'organization:{org_name}'])}]",
            created_at=now,
            updated_at=now,
        )
        await self.seed_repo.create(org_seed)
        await self.session.commit()
    
    async def _has_existing_scan(self, target: str) -> bool:
        """Check if target has an active or queued scan."""
        return await self.asset_repo.has_active_or_queued_scan_for_target(target)
    
    async def _has_completed_scan(self, target: str) -> bool:
        """Check if target has a completed scan."""
        return await self.asset_repo.has_completed_scan_for_target(target)
    
    async def _schedule_scan(self, target: str, confidence: float, source: str) -> Optional[str]:
        """Schedule a scan for the target."""
        try:
            scan_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            scan = ScanORM(
                id=scan_id,
                target=target,
                note=f"Auto scan from {source} (confidence={confidence:.2f})",
                status="queued",
                created_at=now,
                updated_at=now,
            )
            await self.scan_repo.create(scan)
            await self.session.commit()
            
            # Schedule background scan with minimal options
            opts = ScanOptions(enumerate_subdomains=False)
            asyncio.create_task(_run_scan(scan_id, target, opts))
            
            return scan_id
        except Exception as e:
            logger.error("scan_scheduling_failed", extra={"target": target, "error": str(e)})
            return None


class DiscoveryTracking:
    """Track discovery state to avoid loops and duplicates."""
    
    def __init__(self):
        self.known_orgs: Set[str] = set()
        self.visited_orgs: Set[str] = set()
        self.visited_domains: Set[str] = set()
        self.processed_hosts: Set[str] = set()
        self.enqueued_domains: Set[str] = set()
        self.scheduled_targets: Set[str] = set()
