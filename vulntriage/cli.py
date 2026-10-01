"""Command line entry point."""
import argparse
import json
import sys

from .ai import ai_summary, offline_summary
from .parser import parse_nessus
from .prioritize import load_asset_criticality, prioritize
from .redact import redact
from .report import write_report
from .validate import validate


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AI-assisted vulnerability triage")
    ap.add_argument("scan", help="Nessus .nessus file")
    ap.add_argument("--assets", help="CSV of host,criticality (1-3)")
    ap.add_argument("--out", default="report.md", help="Markdown report path")
    ap.add_argument("--top", type=int, default=5, help="Findings for the AI summary")
    ap.add_argument("--offline", action="store_true", help="Skip the AI call")
    args = ap.parse_args(argv)

    findings = parse_nessus(args.scan)
    criticality = load_asset_criticality(args.assets) if args.assets else {}
    findings = prioritize(findings, criticality)
    records, token_map = redact(findings)

    try:
        output = offline_summary(records, args.top) if args.offline else ai_summary(records, args.top)
    except (json.JSONDecodeError, KeyError) as exc:
        output = {}
        print(f"AI response could not be parsed: {exc}", file=sys.stderr)

    problems = validate(output, records, list(token_map.values()))
    write_report(args.out, findings, output, problems, token_map)
    status = "FAILED validation" if problems else "passed validation"
    print(f"{len(findings)} findings triaged; AI output {status}; report written to {args.out}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
