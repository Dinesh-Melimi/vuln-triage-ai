# vuln-triage-ai

AI-assisted vulnerability triage that never trusts the AI blindly.

The tool parses Nessus scan results, ranks findings by risk, asks an LLM for an
executive summary and remediation guidance, and then **validates the AI output
against the original scan** before anything reaches a report.

## Why

AI can speed up vulnerability analysis, but it can also invent CVEs, mix up hosts,
downplay severity, or leak sensitive data. This project treats AI output as
untrusted input and checks it the same way a security engineer would.

## How it works

1. **Safe parsing**: reads `.nessus` files with `defusedxml` to block XXE attacks.
2. **Risk-based prioritization**: CVSS score weighted by asset criticality (1–3).
3. **Redaction**: host names and IPs are replaced with tokens (`HOST-001`) before
   any data is sent to the model. The real mapping stays on the local machine.
4. **AI summary**: the model returns structured JSON (executive summary plus top
   findings). Without an API key, a deterministic offline summary is used.
5. **Validation**: the output is rejected if it contains a host or CVE not in the
   scan, downgrades a finding's severity, or includes a real host name or IP.
6. **Report**: a Markdown report with the validated summary (or a clear failure
   notice) and the full ranked table.

## Usage

```bash
pip install -r requirements.txt
python -m vulntriage.cli sample/sample_scan.nessus --assets sample/assets.csv --offline

# With the AI step
export ANTHROPIC_API_KEY=your_key
python -m vulntriage.cli sample/sample_scan.nessus --assets sample/assets.csv
```

Exit code is `1` when AI output fails validation, so the tool can gate a pipeline.

## Security in the SDLC

Every push runs GitHub Actions with:
- unit tests (`pytest`), including XXE, hallucination, severity-downgrade, and data-leak cases
- static analysis (`bandit`)
- dependency vulnerability scanning (`pip-audit`)

## Sample data

`sample/` contains a synthetic scan for a lab environment. It includes no real
hosts or client data.

## Threat model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the STRIDE analysis of trust boundaries, threats, and mitigations.
