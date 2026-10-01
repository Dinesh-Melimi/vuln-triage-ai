"""Replace hosts and IP addresses with tokens before data leaves the environment."""
import re
from typing import Dict, List, Tuple

from .parser import Finding

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact(findings: List[Finding]) -> Tuple[List[dict], Dict[str, str]]:
    """Return AI-safe records plus a token->host map that never leaves the machine."""
    token_for: Dict[str, str] = {}
    records = []
    for f in findings:
        if f.host not in token_for:
            token_for[f.host] = f"HOST-{len(token_for) + 1:03d}"
        records.append({
            "host": token_for[f.host],
            "port": f.port,
            "name": IPV4.sub("[REDACTED-IP]", f.name),
            "severity": f.severity_name,
            "cvss": f.cvss,
            "cves": f.cves,
            "asset_criticality": f.asset_criticality,
            "risk_score": f.risk_score,
            "solution": IPV4.sub("[REDACTED-IP]", f.solution),
        })
    return records, {v: k for k, v in token_for.items()}


def contains_sensitive(text: str, hosts: List[str]) -> bool:
    """True if any real host name or IP address appears in text."""
    return bool(IPV4.search(text)) or any(h in text for h in hosts)
