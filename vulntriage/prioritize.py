"""Risk-based prioritization: CVSS weighted by business criticality of the asset."""
import csv
from typing import Dict, List

from .parser import Finding


def load_asset_criticality(path: str) -> Dict[str, int]:
    """CSV with columns host,criticality (1=low ... 3=high)."""
    criticality: Dict[str, int] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                value = int(row["criticality"])
            except (KeyError, ValueError):
                continue
            criticality[row["host"].strip()] = max(1, min(3, value))
    return criticality


def prioritize(findings: List[Finding], criticality: Dict[str, int]) -> List[Finding]:
    """Score = CVSS x asset weight; highest risk first."""
    weights = {1: 1.0, 2: 1.25, 3: 1.5}
    for f in findings:
        f.asset_criticality = criticality.get(f.host, 1)
        f.risk_score = round(f.cvss * weights[f.asset_criticality], 2)
    return sorted(findings, key=lambda f: (f.risk_score, f.severity), reverse=True)
