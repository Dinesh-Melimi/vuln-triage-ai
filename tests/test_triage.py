import os

import pytest
from defusedxml.common import EntitiesForbidden

from vulntriage.ai import offline_summary
from vulntriage.cli import main
from vulntriage.parser import parse_nessus
from vulntriage.prioritize import load_asset_criticality, prioritize
from vulntriage.redact import redact
from vulntriage.validate import validate

HERE = os.path.dirname(__file__)
SCAN = os.path.join(HERE, "..", "sample", "sample_scan.nessus")
ASSETS = os.path.join(HERE, "..", "sample", "assets.csv")


def _pipeline():
    findings = prioritize(parse_nessus(SCAN), load_asset_criticality(ASSETS))
    records, token_map = redact(findings)
    return findings, records, token_map


def test_parser_skips_info_findings():
    findings = parse_nessus(SCAN)
    assert len(findings) == 6
    assert all(f.severity >= 1 for f in findings)


def test_parser_blocks_xxe(tmp_path):
    evil = tmp_path / "evil.nessus"
    evil.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
                    '<NessusClientData_v2>&e;</NessusClientData_v2>')
    with pytest.raises(EntitiesForbidden):
        parse_nessus(str(evil))


def test_prioritize_weights_critical_assets_first():
    findings, _, _ = _pipeline()
    assert findings[0].name.startswith("Apache Log4j")
    assert findings[0].risk_score == 15.0


def test_redaction_hides_hosts_and_ips():
    _, records, token_map = _pipeline()
    blob = str(records)
    for real_host in token_map.values():
        assert real_host not in blob
    assert all(r["host"].startswith("HOST-") for r in records)


def test_offline_summary_passes_validation():
    _, records, token_map = _pipeline()
    assert validate(offline_summary(records), records, list(token_map.values())) == []


def test_validation_rejects_hallucinated_cve_and_host():
    _, records, token_map = _pipeline()
    bad = {"summary": "x", "top_findings": [
        {"host": "HOST-999", "name": "Fake", "severity": "High", "cves": ["CVE-2099-0001"], "remediation": "x"}]}
    problems = validate(bad, records, list(token_map.values()))
    assert any("HOST-999" in p for p in problems)
    assert any("CVE-2099-0001" in p for p in problems)


def test_validation_rejects_severity_downgrade():
    _, records, token_map = _pipeline()
    top = records[0]
    bad = {"summary": "x", "top_findings": [dict(top, severity="Low", remediation="x")]}
    assert any("downgraded" in p for p in validate(bad, records, list(token_map.values())))


def test_validation_rejects_leaked_ip():
    _, records, token_map = _pipeline()
    leak = offline_summary(records)
    leak["summary"] += " Patch 10.0.1.20 now."
    assert any("real host" in p for p in validate(leak, records, list(token_map.values())))


def test_cli_end_to_end(tmp_path):
    out = tmp_path / "report.md"
    assert main([SCAN, "--assets", ASSETS, "--out", str(out), "--offline"]) == 0
    text = out.read_text()
    assert "validated" in text and "web01.lab.local" in text
