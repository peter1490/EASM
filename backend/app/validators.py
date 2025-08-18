"""Input validation utilities."""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

from .exceptions import ValidationException


def validate_domain(domain: str, field_name: str = "domain") -> str:
    """Validate and normalize a domain name."""
    domain = domain.strip().lower()
    
    if not domain:
        raise ValidationException(f"{field_name} cannot be empty", field_name)
    
    # Basic domain validation
    if len(domain) > 253:
        raise ValidationException(f"{field_name} is too long (max 253 characters)", field_name)
    
    # Check for valid characters
    if not re.match(r'^[a-z0-9.-]+$', domain):
        raise ValidationException(f"{field_name} contains invalid characters", field_name)
    
    # Check structure
    if domain.startswith('.') or domain.endswith('.'):
        raise ValidationException(f"{field_name} cannot start or end with a dot", field_name)
    
    if '..' in domain:
        raise ValidationException(f"{field_name} cannot contain consecutive dots", field_name)
    
    # Must have at least one dot for a valid domain
    if '.' not in domain:
        raise ValidationException(f"{field_name} must be a fully qualified domain name", field_name)
    
    return domain


def validate_ip(ip: str, field_name: str = "ip") -> str:
    """Validate an IP address."""
    ip = ip.strip()
    
    if not ip:
        raise ValidationException(f"{field_name} cannot be empty", field_name)
    
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValidationException(f"{field_name} is not a valid IP address", field_name)


def validate_cidr(cidr: str, field_name: str = "cidr") -> str:
    """Validate a CIDR notation."""
    cidr = cidr.strip()
    
    if not cidr:
        raise ValidationException(f"{field_name} cannot be empty", field_name)
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network)
    except ValueError:
        raise ValidationException(f"{field_name} is not a valid CIDR notation", field_name)


def validate_asn(asn: str, field_name: str = "asn") -> str:
    """Validate and normalize an ASN."""
    asn = asn.strip().upper()
    
    if not asn:
        raise ValidationException(f"{field_name} cannot be empty", field_name)
    
    # Accept both "AS12345" and "12345" formats
    if asn.startswith("AS"):
        asn_number = asn[2:]
    else:
        asn_number = asn
    
    if not asn_number.isdigit():
        raise ValidationException(f"{field_name} must be numeric (e.g., AS12345 or 12345)", field_name)
    
    asn_int = int(asn_number)
    if asn_int < 1 or asn_int > 4294967295:  # Max 32-bit ASN
        raise ValidationException(f"{field_name} is out of valid range", field_name)
    
    return f"AS{asn_number}"


def validate_scan_target(target: str) -> tuple[str, str]:
    """Validate a scan target and return (normalized_target, target_type)."""
    target = target.strip()
    
    if not target:
        raise ValidationException("Scan target cannot be empty", "target")
    
    # Check if it's a CIDR
    if '/' in target:
        normalized = validate_cidr(target, "target")
        return normalized, "cidr"
    
    # Check if it's an IP
    try:
        normalized = validate_ip(target, "target")
        return normalized, "ip"
    except ValidationException:
        pass
    
    # Must be a domain
    normalized = validate_domain(target, "target")
    return normalized, "domain"


def validate_organization_name(name: str, field_name: str = "organization") -> str:
    """Validate an organization name."""
    name = name.strip()
    
    if not name:
        raise ValidationException(f"{field_name} cannot be empty", field_name)
    
    if len(name) > 200:
        raise ValidationException(f"{field_name} is too long (max 200 characters)", field_name)
    
    # Basic sanitization - allow letters, numbers, spaces, and common punctuation
    if not re.match(r'^[\w\s\-.,&()\'"]+$', name, re.UNICODE):
        raise ValidationException(f"{field_name} contains invalid characters", field_name)
    
    return name


def validate_evidence_filename(filename: str) -> str:
    """Validate and sanitize an evidence filename."""
    if not filename:
        raise ValidationException("Filename cannot be empty", "filename")
    
    # Remove path components
    filename = filename.split("/")[-1].split("\\")[-1]
    
    # Basic sanitization
    filename = re.sub(r'[^\w\s.-]', '_', filename)
    
    if len(filename) > 255:
        # Preserve extension if possible
        parts = filename.rsplit('.', 1)
        if len(parts) == 2 and len(parts[1]) < 10:
            base = parts[0][:240]
            filename = f"{base}.{parts[1]}"
        else:
            filename = filename[:255]
    
    return filename


def validate_confidence_score(score: float, field_name: str = "confidence") -> float:
    """Validate a confidence score (0.0 to 1.0)."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        raise ValidationException(f"{field_name} must be a number", field_name)
    
    if score < 0.0 or score > 1.0:
        raise ValidationException(f"{field_name} must be between 0.0 and 1.0", field_name)
    
    return score


def validate_port(port: int, field_name: str = "port") -> int:
    """Validate a port number."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValidationException(f"{field_name} must be a number", field_name)
    
    if port < 1 or port > 65535:
        raise ValidationException(f"{field_name} must be between 1 and 65535", field_name)
    
    return port


def validate_api_key(api_key: Optional[str]) -> Optional[str]:
    """Validate an API key format."""
    if not api_key:
        return None
    
    api_key = api_key.strip()
    
    # Basic length check
    if len(api_key) < 20:
        raise ValidationException("API key is too short", "api_key")
    
    if len(api_key) > 256:
        raise ValidationException("API key is too long", "api_key")
    
    # Check for basic character set
    if not re.match(r'^[A-Za-z0-9_\-]+$', api_key):
        raise ValidationException("API key contains invalid characters", "api_key")
    
    return api_key
