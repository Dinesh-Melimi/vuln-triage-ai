"""Check AI output against the source scan before anyone acts on it.

Rejects hallucinated hosts or CVEs, severity downgrades, and leaked sensitive data.
"""
from typing import List

from .redact import contains_sensitive

RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def validate(ai_output: dict, records: List[dict], real_hosts: List[str]) -> List[str]:
    """Return a list of problems. An empty list means the output passed."""
    if not isinstance(ai_output, dict) or "top_findings" not in ai_output:
        return ["AI output is missing 'top_findings'."]

    problems: List[str] = []
    known_hosts = {r["host"] for r in records}
    known_cves = {c for r in records for c in r["cves"]}
    source_sev = {}
    for r in records:
        key = (r["host"], r["name"])
        source_sev[key] = max(source_sev.get(key, 0), RANK[r["severity"]])

    for i, f in enumerate(ai_output.get("top_findings", []), start=1):
        host, name = f.get("host"), f.get("name")
        if host not in known_hosts:
            problems.append(f"Finding {i}: host '{host}' is not in the scan.")
        for cve in f.get("cves", []):
            if cve not in known_cves:
                problems.append(f"Finding {i}: {cve} is not in the scan.")
        key = (host, name)
        if key in source_sev and RANK.get(f.get("severity"), -1) < source_sev[key]:
            problems.append(f"Finding {i}: severity was downgraded from the scan value.")

    if contains_sensitive(str(ai_output), real_hosts):
        problems.append("AI output contains a real host name or IP address.")
    return problems
