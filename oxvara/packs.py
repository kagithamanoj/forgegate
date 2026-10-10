"""Policy packs: named sets of governance rules an estate must satisfy.

A pack inspects a normalized ApiEstate and returns a list of violations.
Packs are how teams encode "every API we expose to agents must meet this
bar" before a compile ever runs. The CLI's `validate` command runs them,
and several packs can run together.

- ``strict``: every operation authenticated, rate limited and capped,
  with a gateway URL to call.
- ``owasp-mcp``: rules mapped to the OWASP MCP Top 10 (2025, v0.1) that
  can be checked from gateway configuration alone. Each rule id carries
  the OWASP item it addresses.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import AUTH_STRENGTH, ApiEstate

# The strict pack caps every operation at this many requests per minute.
STRICT_MAX_PER_MINUTE = 1000

# Methods that change or delete state.
_WRITE_METHODS = {"PUT", "PATCH", "DELETE"}


@dataclass
class Violation:
    rule: str
    operation_id: str  # "" for estate-wide violations
    message: str
    source: str = ""

    def __str__(self) -> str:
        where = f" [{self.operation_id}]" if self.operation_id else ""
        return f"{self.rule}{where}: {self.message}"


def _per_minute(requests: int, per: str) -> float:
    return {"second": requests * 60, "minute": requests,
            "hour": requests / 60}.get(per, float("inf"))


def strict_pack(estate: ApiEstate) -> list[Violation]:
    """Every operation must be authenticated, rate limited, and capped."""
    violations: list[Violation] = []
    if not estate.base_url and not any(ep.base_url for ep in estate.endpoints):
        violations.append(
            Violation("base-url", "", "estate has no base URL set")
        )
    for ep in estate.endpoints:
        label = f"{ep.method} {ep.path}"
        if estate.base_url and not estate.base_for(ep):
            violations.append(Violation(
                "base-url", ep.operation_id, f"{label} has no base URL", ep.source))
        if ep.policy.auth.kind == "none":
            violations.append(Violation(
                "require-auth", ep.operation_id,
                f"{label} has no auth configured", ep.source))
        limit = ep.policy.rate_limit
        if limit is None:
            violations.append(Violation(
                "require-rate-limit", ep.operation_id,
                f"{label} has no rate limit configured", ep.source))
        elif _per_minute(limit.requests, limit.per) > STRICT_MAX_PER_MINUTE:
            violations.append(Violation(
                "cap-rate-limit", ep.operation_id,
                f"{label} allows {limit.requests}/{limit.per}, above the "
                f"{STRICT_MAX_PER_MINUTE}/minute cap", ep.source))
    return violations


def owasp_mcp_pack(estate: ApiEstate) -> list[Violation]:
    """Checks mapped to the OWASP MCP Top 10 that config alone can answer."""
    violations: list[Violation] = []
    upstream = estate.upstream_url.rstrip("/")
    for ep in estate.endpoints:
        label = f"{ep.method} {ep.path}"
        base = estate.base_for(ep)
        auth = ep.policy.auth
        if auth.kind == "apiKey" and auth.location == "query":
            violations.append(Violation(
                "MCP01-no-query-credentials", ep.operation_id,
                f"{label} sends its API key in the query string, where "
                "proxies and access logs record it", ep.source))
        if base.startswith("http://"):
            violations.append(Violation(
                "MCP01-require-tls", ep.operation_id,
                f"{label} calls {base} over plain HTTP; credentials travel "
                "in clear text", ep.source))
        if not ep.read_only and auth.kind == "none":
            violations.append(Violation(
                "MCP07-auth-on-writes", ep.operation_id,
                f"{label} changes state with no authentication", ep.source))
        if ep.method in _WRITE_METHODS and AUTH_STRENGTH.get(auth.kind, 0) < AUTH_STRENGTH["bearer"]:
            violations.append(Violation(
                "MCP02-scoped-auth-on-destructive", ep.operation_id,
                f"{label} can modify or delete data under a shared static "
                f"secret ({auth.kind}); use a scoped token (bearer/oauth2)",
                ep.source))
        if upstream and base and base.rstrip("/").startswith(upstream):
            violations.append(Violation(
                "MCP07-gateway-bypass", ep.operation_id,
                f"{label} calls the backend {upstream} directly, skipping "
                "the gateway and every policy on it", ep.source))
    return violations


PACKS = {"strict": strict_pack, "owasp-mcp": owasp_mcp_pack}


def run_pack(estate: ApiEstate, name: str = "strict") -> list[Violation]:
    """Run a named pack against an estate."""
    try:
        pack = PACKS[name]
    except KeyError:
        raise ValueError(
            f"unknown policy pack {name!r} "
            f"(available: {', '.join(sorted(PACKS))})"
        ) from None
    return pack(estate)


def run_packs(estate: ApiEstate, names: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for name in names:
        violations.extend(run_pack(estate, name))
    return violations
