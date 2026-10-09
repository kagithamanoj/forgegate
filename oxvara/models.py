"""Internal model for a normalized API estate.

The parser turns an OpenAPI document plus x-oxvara policy annotations
into these objects. The code generator only ever sees these, which keeps
the compiler decoupled from any one spec format or API management vendor.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RateLimit:
    requests: int
    per: str  # "second" | "minute" | "hour"

    def window_seconds(self) -> int:
        return {"second": 1, "minute": 60, "hour": 3600}.get(self.per, 60)


@dataclass
class AuthPolicy:
    kind: str = "none"  # "apiKey" | "bearer" | "oauth2" | "none"
    name: str = ""  # header or query name for apiKey
    location: str = "header"  # "header" | "query"


@dataclass
class Policy:
    auth: AuthPolicy = field(default_factory=AuthPolicy)
    rate_limit: RateLimit | None = None
    timeout: int = 30

    def merge(self, override: "Policy") -> "Policy":
        """Return a new Policy where the override fills in anything it sets."""
        auth = override.auth if override.auth.kind != "none" else self.auth
        rate_limit = override.rate_limit or self.rate_limit
        timeout = override.timeout if override.timeout != 30 else self.timeout
        return Policy(auth=auth, rate_limit=rate_limit, timeout=timeout)


@dataclass
class Parameter:
    name: str
    location: str  # "path" | "query"
    required: bool
    schema_type: str  # "string" | "integer" | "number" | "boolean"


@dataclass
class BodyProperty:
    name: str
    required: bool
    schema_type: str


@dataclass
class Endpoint:
    operation_id: str
    tool_name: str
    method: str  # uppercase HTTP verb
    path: str  # e.g. "/pets/{petId}"
    summary: str
    description: str
    parameters: list[Parameter] = field(default_factory=list)
    body_properties: list[BodyProperty] = field(default_factory=list)
    body_raw: bool = False  # True when the body is not a flat object
    policy: Policy = field(default_factory=Policy)


@dataclass
class ApiEstate:
    title: str
    slug: str
    version: str
    base_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
