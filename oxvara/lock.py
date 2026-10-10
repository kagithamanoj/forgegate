"""Lockfiles and drift detection.

``oxvara lock`` records the agent-facing surface of an estate: every
tool, the gateway it calls, the policy it inherits, and a hash of the
description and input schema the agent is shown. ``oxvara drift``
re-imports the estate and compares it with the lock.

Two kinds of drift matter:

- **Policy drift.** Someone changed a gateway policy (auth removed, a
  rate limit loosened, a route pointed elsewhere) after the agent-facing
  server was reviewed. Weakening is an error; tightening is a note.
- **Tool drift.** A tool's description or schema changed, or a tool
  appeared. Agents read descriptions as instructions, so an unreviewed
  change is how tool poisoning and "rug pull" updates land (OWASP MCP
  Top 10, MCP03). Pinning the hash and failing on change is the defence.

The lockfile is deterministic (sorted keys, no timestamps) so it diffs
cleanly in code review.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from . import __version__
from .codegen import tool_names
from .models import AUTH_STRENGTH, ApiEstate, Endpoint

LOCK_VERSION = 1
SEVERITY_ORDER = {"note": 0, "warning": 1, "error": 2}


def _sha(value) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _schema(ep: Endpoint) -> list:
    params = [[p.name, p.location, p.required, p.schema_type] for p in ep.parameters]
    body = [[b.name, "body", b.required, b.schema_type] for b in ep.body_properties]
    raw = [["body", "raw", False, "string"]] if ep.body_raw else []
    return sorted(params + body + raw)


def tool_record(estate: ApiEstate, ep: Endpoint) -> dict:
    rl = ep.policy.rate_limit
    return {
        "source": ep.source or f"{estate.kind}:{estate.slug}",
        "method": ep.method,
        "path": ep.path,
        "base_url": estate.base_for(ep),
        "auth": {
            "kind": ep.policy.auth.kind,
            "name": ep.policy.auth.name,
            "location": ep.policy.auth.location,
        },
        "rate_limit": {"requests": rl.requests, "per": rl.per} if rl else None,
        "timeout": ep.policy.timeout,
        # Only the spec-authored text: policy changes are reported by their
        # own rules, not double-counted as a description change.
        "description_sha256": _sha([ep.summary, ep.description]),
        "schema_sha256": _sha(_schema(ep)),
    }


def build_lock(estate: ApiEstate) -> dict:
    tools = {
        name: tool_record(estate, ep)
        for ep, name in zip(estate.endpoints, tool_names(estate))
    }
    return {
        "lock_version": LOCK_VERSION,
        "generated_by": f"oxvara {__version__}",
        "tools": tools,
    }


def write_lock(estate: ApiEstate, path: str) -> dict:
    lock = build_lock(estate)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(lock, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return lock


def read_lock(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            lock = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} is not a valid lockfile: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("lock_version") != LOCK_VERSION:
        raise ValueError(f"{path} is not an oxvara lockfile (lock_version {LOCK_VERSION})")
    return lock


@dataclass
class Change:
    severity: str  # "error" | "warning" | "note"
    rule: str
    tool: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity:7} {self.rule} [{self.tool}]: {self.message}"


def _per_second(rate: dict | None) -> float:
    if not rate:
        return float("inf")
    window = {"second": 1, "minute": 60, "hour": 3600}.get(rate["per"], 60)
    return rate["requests"] / window


def _fmt_rate(rate: dict | None) -> str:
    return f"{rate['requests']}/{rate['per']}" if rate else "none"


def _compare(tool: str, old: dict, new: dict) -> list[Change]:
    changes: list[Change] = []
    old_auth, new_auth = old["auth"], new["auth"]
    old_s = AUTH_STRENGTH.get(old_auth["kind"], 0)
    new_s = AUTH_STRENGTH.get(new_auth["kind"], 0)
    if new_s < old_s:
        changes.append(Change("error", "auth-weakened", tool,
                              f"auth went from {old_auth['kind']} to {new_auth['kind']}"))
    elif new_s > old_s:
        changes.append(Change("note", "auth-tightened", tool,
                              f"auth went from {old_auth['kind']} to {new_auth['kind']}"))
    elif old_auth != new_auth:
        changes.append(Change("warning", "auth-changed", tool,
                              f"auth details changed: {old_auth} -> {new_auth}"))

    old_rate, new_rate = _per_second(old["rate_limit"]), _per_second(new["rate_limit"])
    rates = f"{_fmt_rate(old['rate_limit'])} -> {_fmt_rate(new['rate_limit'])}"
    if new_rate > old_rate:
        what = "removed" if new["rate_limit"] is None else "loosened"
        changes.append(Change("error", "rate-limit-loosened", tool,
                              f"rate limit {what}: {rates}"))
    elif new_rate < old_rate:
        changes.append(Change("note", "rate-limit-tightened", tool,
                              f"rate limit tightened: {rates}"))

    if old["base_url"] != new["base_url"]:
        changes.append(Change("error", "target-changed", tool,
                              f"tool now calls {new['base_url'] or '(no base URL)'} "
                              f"instead of {old['base_url'] or '(no base URL)'}"))
    if (old["method"], old["path"]) != (new["method"], new["path"]):
        changes.append(Change("error", "route-changed", tool,
                              f"{old['method']} {old['path']} -> {new['method']} {new['path']}"))
    if old["description_sha256"] != new["description_sha256"]:
        changes.append(Change("warning", "description-changed", tool,
                              "tool description changed; review it before agents see it "
                              "(OWASP MCP03 tool poisoning)"))
    if old["schema_sha256"] != new["schema_sha256"]:
        changes.append(Change("warning", "schema-changed", tool,
                              "tool input schema changed"))
    if old["timeout"] != new["timeout"]:
        changes.append(Change("note", "timeout-changed", tool,
                              f"timeout {old['timeout']}s -> {new['timeout']}s"))
    return changes


def detect_drift(lock: dict, estate: ApiEstate) -> list[Change]:
    """Compare a lockfile with the estate as it is now."""
    current = build_lock(estate)["tools"]
    locked = lock.get("tools", {})
    changes: list[Change] = []
    for tool in sorted(set(locked) | set(current)):
        if tool not in current:
            changes.append(Change("note", "tool-removed", tool,
                                  "tool is no longer in the estate"))
        elif tool not in locked:
            changes.append(Change("warning", "tool-added", tool,
                                  "new tool exposed to agents; not in the lockfile"))
        else:
            changes.extend(_compare(tool, locked[tool], current[tool]))
    return changes


def exceeds(changes: list[Change], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[c.severity] >= threshold for c in changes)
