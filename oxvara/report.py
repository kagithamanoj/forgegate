"""Machine-readable output: JSON and SARIF 2.1.0.

SARIF lets ``validate`` and ``drift`` findings show up as GitHub code
scanning alerts (``github/codeql-action/upload-sarif``) next to the
gateway config that caused them.
"""

from __future__ import annotations

import json

from . import __version__

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {"error": "error", "warning": "warning", "note": "note"}


def sarif(findings: list[dict], tool_name: str = "oxvara") -> str:
    """Render findings as SARIF.

    Each finding is a dict with rule, level, message, uri and optionally
    a 'tool' (the MCP tool or operation it concerns).
    """
    rules = sorted({f["rule"] for f in findings})
    results = []
    for f in findings:
        text = f["message"]
        if f.get("tool"):
            text = f"[{f['tool']}] {text}"
        results.append({
            "ruleId": f["rule"],
            "level": _LEVELS.get(f.get("level", "error"), "error"),
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f.get("uri") or "."}}
            }],
        })
    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": __version__,
                "informationUri": "https://github.com/kagithamanoj/oxvara",
                "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules],
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def as_json(findings: list[dict]) -> str:
    return json.dumps({"oxvara": __version__, "findings": findings}, indent=2)
