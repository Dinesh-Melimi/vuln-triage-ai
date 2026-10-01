# Threat Model: vuln-triage-ai

Method: STRIDE, applied to each component and the data flowing between them.

## System overview

```
Nessus scan file ──► Parser ──► Prioritizer ──► Redactor ──► LLM API (external)
  (untrusted)                                      │               │
asset CSV ─────────────────────────────────────────┘               ▼
                                                Validator ◄── AI response (untrusted)
                                                    │
                                                    ▼
                                             Markdown report (local)
```

## Trust boundaries

1. **Scan file → Parser.** Scan files may come from shared drives or other teams, so they are untrusted input.
2. **Local machine → LLM API.** Anything sent crosses into a third-party service.
3. **LLM API → Validator.** Model output is untrusted. It can be wrong, invented, or manipulated by prompt injection inside the scan data.

## Assets

- Host names and IP addresses (reveal internal network layout)
- Vulnerability details (a map of what is exploitable)
- Report integrity (people act on it)
- API key

## STRIDE analysis

| Threat | Where | Risk | Mitigation in this project |
|---|---|---|---|
| **Spoofing** | Fake scan file posing as a real one | Medium | Out of scope for a local tool; a production version should verify the scan source or file signature |
| **Tampering** | Malicious XML in scan file (XXE, billion laughs) | High | `defusedxml` blocks external entities and entity expansion; covered by `test_parser_blocks_xxe` |
| **Tampering** | Prompt injection in finding names changes the AI's answer | High | AI output is never trusted: the validator checks every host, CVE, and severity against the source scan |
| **Repudiation** | No record of what the AI said vs. what was reported | Low | Report clearly states whether AI output passed or failed validation; failed output is not shown as findings |
| **Information disclosure** | Real hosts or IPs sent to the LLM provider | High | Redactor replaces hosts with tokens (`HOST-001`) and strips IPs before the API call; the token map never leaves the machine |
| **Information disclosure** | AI response leaks a real host or IP into the report | Medium | Validator rejects output containing any real host name or IPv4 address; covered by `test_validation_rejects_leaked_ip` |
| **Information disclosure** | API key exposed in code or repo | High | Key is read from the `ANTHROPIC_API_KEY` environment variable only; `.env` is in `.gitignore` |
| **Denial of service** | Huge or malformed scan file | Low | `defusedxml` limits entity expansion; only the top 25 findings are sent to the model |
| **Elevation of privilege** | AI downgrades a Critical finding so it gets ignored | High | Validator rejects any severity lower than the scan value; covered by `test_validation_rejects_severity_downgrade` |
| **Elevation of privilege** | Vulnerable third-party dependency | Medium | CI runs `pip-audit` on every push; `bandit` scans the code itself |

## Residual risks and next steps

- **Hallucinated remediation advice.** The validator checks facts (hosts, CVEs, severity) but cannot verify that a suggested fix is correct. Remediation text should be reviewed by a person before it is acted on.
- **Redaction is pattern-based.** It covers host names from the scan and IPv4 addresses. IPv6 addresses and hostnames embedded inside free-text plugin output are not yet covered.
- **No scan authenticity check.** A production version should verify where scan files come from.
