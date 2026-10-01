"""Parse Nessus (.nessus v2) scan files safely.

Uses defusedxml to block XML External Entity (XXE) and billion-laughs attacks,
since scan files can come from untrusted sources.
"""
from dataclasses import dataclass, field
from typing import List

from defusedxml import ElementTree as ET

SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


@dataclass
class Finding:
    host: str
    port: str
    plugin_id: str
    name: str
    severity: int
    cvss: float
    cves: List[str] = field(default_factory=list)
    solution: str = ""
    asset_criticality: int = 1
    risk_score: float = 0.0

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, "Unknown")


def _text(item, tag: str, default: str = "") -> str:
    node = item.find(tag)
    return node.text.strip() if node is not None and node.text else default


def parse_nessus(path: str, min_severity: int = 1) -> List[Finding]:
    """Return findings at or above min_severity (default: Low)."""
    tree = ET.parse(path)
    findings: List[Finding] = []
    for host in tree.getroot().iter("ReportHost"):
        host_name = host.get("name", "unknown")
        for item in host.iter("ReportItem"):
            severity = int(item.get("severity", "0"))
            if severity < min_severity:
                continue
            cvss_raw = _text(item, "cvss3_base_score") or _text(item, "cvss_base_score") or "0"
            try:
                cvss = float(cvss_raw)
            except ValueError:
                cvss = 0.0
            findings.append(Finding(
                host=host_name,
                port=item.get("port", "0"),
                plugin_id=item.get("pluginID", ""),
                name=item.get("pluginName", "Unnamed finding"),
                severity=severity,
                cvss=cvss,
                cves=[c.text.strip() for c in item.findall("cve") if c.text],
                solution=_text(item, "solution"),
            ))
    return findings
