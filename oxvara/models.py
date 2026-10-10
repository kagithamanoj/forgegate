"""Internal model for a normalized API estate.

The parser and the gateway exporters turn their inputs into these
objects. The code generator, the policy packs and drift detection only
ever see these, which keeps Oxvara decoupled from any one spec format
or API management vendor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Relative strength of each auth kind, used by drift detection to tell a
# tightened policy from a weakened one. apiKey and basic are both shared
# static secrets; bearer is a presented token; oauth2 is an issued,
# scoped, expiring token.
AUTH_STRENGTH = {"none": 0, "apiKey": 1, "basic": 1, "bearer": 2, "oauth2": 3}

READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class RateLimit:
    requests: int
    per: str  # "second" | "minute" | "hour"

    def window_seconds(self) -> int:
        return {"second": 1, "minute": 60, "hour": 3600}.get(self.per, 60)

    def per_second(self) -> float:
        return self.requests / self.window_seconds()


@dataclass
class AuthPolicy:
    kind: str = "none"  # "apiKey" | "bearer" | "basic" | "oauth2" | "none"
    name: str = ""  # header or query name for apiKey
    location: str = "header"  # "header" | "query"


@dataclass
class Policy:
    auth: AuthPolicy = field(default_factory=AuthPolicy)
    rate_limit: RateLimit | None = None
    timeout: int = 30

    def merge(self, override: Policy) -> Policy:
        """Return a new Policy where the override fills in anything it sets."""
        auth = override.auth if override.auth.kind != "none" else self.auth
        rate_limit = override.rate_limit or self.rate_limit
        timeout = override.timeout if override.timeout != 30 else self.timeout
        return Policy(auth=auth, rate_limit=rate_limit, timeout=timeout)


@dataclass
class Parameter:
    name: str
    location: str  # "path" | "query" | "header"
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
    # Set when estates from several gateways are merged: each endpoint
    # then keeps the base URL and source label of the estate it came from.
    base_url: str = ""
    source: str = ""

    @property
    def read_only(self) -> bool:
        return self.method in READ_ONLY_METHODS


@dataclass
class ApiEstate:
    title: str
    slug: str
    version: str
    base_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    # Which importer produced this estate: openapi | apigee | apim | kong | merged
    kind: str = "openapi"
    # The backend behind the gateway, when the export reveals it. Tools must
    # never call this directly: that would bypass every gateway policy.
    upstream_url: str = ""
    # Import-time findings worth surfacing (skipped routes, unsupported
    # plugins, missing gateway URL, ...).
    notes: list[str] = field(default_factory=list)

    def base_for(self, ep: Endpoint) -> str:
        return ep.base_url or self.base_url
