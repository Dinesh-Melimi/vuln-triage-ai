"""LLM summarization. The model sees only redacted data and must return JSON.

If no API key is set, a deterministic offline summary is produced so the tool
always works and its output can be compared against the AI version.
"""
import json
import os
from typing import List

PROMPT = """You are a vulnerability analyst. Below are redacted scan findings, already
sorted by risk. Return ONLY a JSON object with this shape, no other text:
{{"summary": "<3 sentence executive summary>",
  "top_findings": [{{"host": "<host token>", "name": "<finding name>",
                    "severity": "<severity>", "cves": ["<CVE ids>"],
                    "remediation": "<one-sentence fix>"}}]}}
Use only hosts, names, severities, and CVEs that appear in the data. Include at most {top_n} findings.

DATA:
{data}"""


def offline_summary(records: List[dict], top_n: int = 5) -> dict:
    top = records[:top_n]
    crit = sum(1 for r in records if r["severity"] == "Critical")
    high = sum(1 for r in records if r["severity"] == "High")
    return {
        "summary": (f"{len(records)} findings analyzed: {crit} critical and {high} high. "
                    "Findings are ranked by CVSS weighted by asset criticality. "
                    "Address the top-ranked items first."),
        "top_findings": [{"host": r["host"], "name": r["name"], "severity": r["severity"],
                          "cves": r["cves"], "remediation": r["solution"] or "See vendor guidance."}
                         for r in top],
    }


def ai_summary(records: List[dict], top_n: int = 5) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return offline_summary(records, top_n)
    import anthropic  # imported lazily so the tool runs without the SDK

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=os.environ.get("VULNTRIAGE_MODEL", "claude-sonnet-5"),
        max_tokens=1500,
        messages=[{"role": "user", "content": PROMPT.format(
            top_n=top_n, data=json.dumps(records[:25], indent=1))}],
    )
    text = "".join(block.text for block in message.content if block.type == "text")
    text = text.strip().removeprefix("```json").removesuffix("```").strip()
    return json.loads(text)
