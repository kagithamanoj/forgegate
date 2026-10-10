"""Import an Azure API Management export into a normalized ApiEstate.

Expected layout, which mirrors the APIM git export structure::

    <dir>/openapi.yaml                      # the API's OpenAPI document
    <dir>/policy.xml                         # API-level policy
    <dir>/operations/<operationId>/policy.xml  # per-operation overrides

Only ``<inbound>`` policies are read, since those are the ones that
govern what a caller (or an agent) may do. Mapping:

- ``<rate-limit>`` / ``<rate-limit-by-key>``: calls + renewal-period
  (seconds) become a rate limit.
- ``<quota>`` / ``<quota-by-key>``: same shape; when both a quota and a
  rate limit apply, the tighter one wins.
- ``<check-header name="...">``: an API key expected in that header.
- ``<authentication-basic>``: basic auth.
- ``<validate-jwt>``: oauth2 (the generated server obtains a token; see
  the README for the supported grants).

The base URL comes from the OpenAPI document's ``servers`` entry, which
is the APIM gateway URL APIM writes on export, so tools call through the
gateway. A gateway URL passed by the caller overrides it.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

import yaml

from ..models import ApiEstate, AuthPolicy, Policy, RateLimit
from ..parser import _servers_base_url, parse_document
from ..util import normalize_rate

_RATE_TAGS = ("rate-limit", "rate-limit-by-key", "quota", "quota-by-key")


def _int(value: str | None, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _tightest(limits: list[RateLimit | None]) -> RateLimit | None:
    """Keep the limit with the fewest requests per second."""
    best: RateLimit | None = None
    best_rate = float("inf")
    for limit in limits:
        if limit is None:
            continue
        rate = limit.requests / limit.window_seconds()
        if rate < best_rate:
            best, best_rate = limit, rate
    return best


def _inbound_policy(path: str) -> Policy:
    """Parse one APIM policy file's <inbound> section into a Policy."""
    policy = Policy()
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return policy
    inbound = root.find("inbound")
    if inbound is None:
        return policy

    limits = []
    for tag in _RATE_TAGS:
        for el in inbound.findall(tag):
            limits.append(
                normalize_rate(
                    _int(el.get("calls")),
                    _int(el.get("renewal-period")),
                )
            )
    policy.rate_limit = _tightest(limits)

    if inbound.find("validate-jwt") is not None:
        policy.auth = AuthPolicy(kind="oauth2")
    elif inbound.find("authentication-basic") is not None:
        policy.auth = AuthPolicy(kind="basic")
    else:
        check = inbound.find("check-header")
        if check is not None and check.get("name"):
            policy.auth = AuthPolicy(
                kind="apiKey",
                name=str(check.get("name")),
                location="header",
            )
    return policy


def _find_openapi(apim_dir: str) -> str:
    for name in ("openapi.yaml", "openapi.yml", "openapi.json"):
        path = os.path.join(apim_dir, name)
        if os.path.isfile(path):
            return path
    raise ValueError(
        f"{apim_dir!r} does not look like an APIM export "
        "(no openapi.yaml/yml/json found)"
    )


def load_apim(apim_dir: str, gateway_url: str = "") -> ApiEstate:
    """Load an APIM export directory into an ApiEstate."""
    openapi_path = _find_openapi(apim_dir)
    with open(openapi_path, "r", encoding="utf-8") as fh:
        try:
            doc = yaml.safe_load(fh.read())
        except yaml.YAMLError as exc:
            raise ValueError(f"could not parse {openapi_path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise TypeError(f"{openapi_path} must contain a mapping")

    api_policy = _inbound_policy(os.path.join(apim_dir, "policy.xml"))
    estate = parse_document(
        doc, api_policy, gateway_url.rstrip("/") or _servers_base_url(doc)
    )
    estate.kind = "apim"

    operations_dir = os.path.join(apim_dir, "operations")
    for ep in estate.endpoints:
        op_policy_path = os.path.join(
            operations_dir, ep.operation_id, "policy.xml"
        )
        if os.path.isfile(op_policy_path):
            ep.policy = ep.policy.merge(_inbound_policy(op_policy_path))
    return estate
