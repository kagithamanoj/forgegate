"""Policy packs: named sets of governance rules an estate must satisfy.

A pack inspects a normalized ApiEstate and returns a list of violations.
Packs are how teams encode "every API we expose to agents must meet this
bar" before a compile ever runs. The CLI's `validate` command runs them.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import ApiEstate

# The strict pack caps every operation at this many requests per minute.
STRICT_MAX_PER_MINUTE = 1000


@dataclass
class Violation:
    rule: str
    operation_id: str  # "" for estate-wide violations
    message: str

    def __str__(self) -> str:
        where = f" [{self.operation_id}]" if self.operation_id else ""
        return f"{self.rule}{where}: {self.message}"


def _per_minute(requests: int, per: str) -> float:
    return {"second": requests * 60, "minute": requests,
            "hour": requests / 60}.get(per, float("inf"))


def strict_pack(estate: ApiEstate) -> list[Violation]:
    """Every operation must be authenticated, rate limited, and capped."""
    violations: list[Violation] = []
    if not estate.base_url:
        violations.append(
            Violation("base-url", "", "estate has no base URL set")
        )
    for ep in estate.endpoints:
        if ep.policy.auth.kind == "none":
            violations.append(
                Violation(
                    "require-auth",
                    ep.operation_id,
                    f"{ep.method} {ep.path} has no auth configured",
                )
            )
        limit = ep.policy.rate_limit
        if limit is None:
            violations.append(
                Violation(
                    "require-rate-limit",
                    ep.operation_id,
                    f"{ep.method} {ep.path} has no rate limit configured",
                )
            )
        elif _per_minute(limit.requests, limit.per) > STRICT_MAX_PER_MINUTE:
            violations.append(
                Violation(
                    "cap-rate-limit",
                    ep.operation_id,
                    f"{ep.method} {ep.path} allows "
                    f"{limit.requests}/{limit.per}, above the "
                    f"{STRICT_MAX_PER_MINUTE}/minute cap",
                )
            )
    return violations


PACKS = {"strict": strict_pack}


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
