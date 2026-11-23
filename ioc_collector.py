"""Load and validate IOCs from a JSON file. Demo data only."""
import ipaddress
import json
import re
from pathlib import Path

VALID_TYPES = {"ip", "domain", "url", "hash"}
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$", re.I)
HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{64}$", re.I)


def validate_ioc(ioc):
    """Return (is_valid, reason)."""
    ioc_type = ioc.get("type")
    value = str(ioc.get("value", "")).strip()
    if ioc_type not in VALID_TYPES or not value:
        return False, "missing or unknown type/value"
    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False, "not a valid IP address"
    elif ioc_type == "domain":
        if not DOMAIN_RE.match(value):
            return False, "not a valid domain"
    elif ioc_type == "url":
        if not value.startswith(("http://", "https://")):
            return False, "URL must start with http:// or https://"
    elif ioc_type == "hash":
        if not HASH_RE.match(value):
            return False, "hash must be MD5 (32 hex) or SHA-256 (64 hex)"
    return True, ""


def load_iocs(path):
    data = json.loads(Path(path).read_text())
    valid, invalid = [], []
    for ioc in data:
        ok, reason = validate_ioc(ioc)
        if ok:
            valid.append(ioc)
        else:
            invalid.append({**ioc, "error": reason})
    return valid, invalid
