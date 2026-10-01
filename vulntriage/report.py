"""Write a Markdown report, re-mapping host tokens locally."""
from typing import Dict, List

from .parser import Finding


def write_report(path: str, findings: List[Finding], ai_output: dict,
                 problems: List[str], token_map: Dict[str, str]) -> None:
    lines = ["# Vulnerability Triage Report", ""]
    if problems:
        lines += ["## AI validation: FAILED", "",
                  "AI output was rejected. Use the deterministic ranking below.", ""]
        lines += [f"- {p}" for p in problems] + [""]
    else:
        lines += ["## Executive summary (AI-assisted, validated)", "", ai_output["summary"], "",
                  "## Top findings", ""]
        for f in ai_output["top_findings"]:
            host = token_map.get(f["host"], f["host"])
            cves = ", ".join(f["cves"]) or "none"
            lines.append(f"- **{f['severity']}** | {host} | {f['name']} | CVEs: {cves}  ")
            lines.append(f"  Fix: {f['remediation']}")
        lines.append("")
    lines += ["## All findings by risk", "",
              "| Rank | Host | Port | Finding | Severity | CVSS | Asset | Risk |",
              "|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, start=1):
        lines.append(f"| {i} | {f.host} | {f.port} | {f.name} | {f.severity_name} | "
                     f"{f.cvss} | {f.asset_criticality} | {f.risk_score} |")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
