"""Import an Apigee API proxy bundle into a normalized ApiEstate.

Reads an exported bundle directory, the layout produced by the Apigee
management API export:

    <bundle>/apiproxy/<name>.xml
    <bundle>/apiproxy/proxies/*.xml
    <bundle>/apiproxy/targets/*.xml
    <bundle>/apiproxy/policies/*.xml

Operations come from proxy flow conditions of the form::

    (proxy.pathsuffix MatchesPath "/pets") and (request.verb = "GET")

Governance comes from the policies attached in PreFlow (applied to every
operation) and in per-flow Request steps (applied to that operation only).
VerifyAPIKey and OAuthV2 map to auth; Quota and SpikeArrest map to rate
limits. Flow-level policies override the global ones, mirroring how
Apigee evaluates them.

Two honest simplifications are documented rather than hidden:

- Quota policies that only carry a ``countRef`` (a per-product quota the
  bundle cannot resolve) contribute no rate limit.
- SpikeArrest is burst protection, not a quota. It is imported as the
  operation's rate limit only when no Quota policy applies, which keeps
  every generated tool under a real ceiling instead of none.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from ..models import (
    ApiEstate,
    AuthPolicy,
    Endpoint,
    Parameter,
    Policy,
    RateLimit,
)
from ..util import camel_to_snake, path_params, slugify

_VERB_RE = re.compile(r'request\.verb\s*=\s*"([A-Za-z]+)"')
_PATH_RE = re.compile(r'proxy\.pathsuffix\s+MatchesPath\s+"([^"]+)"')
_SPIKE_RE = re.compile(r"^\s*(\d+)\s*p([sm])\s*$", re.IGNORECASE)

# Quota TimeUnit values in seconds.
_TIME_UNITS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "month": 2592000,  # 30 days, Apigee's documented approximation
}


def _normalize_rate(requests: int, window_seconds: int) -> RateLimit | None:
    """Fit an arbitrary (requests, window) pair into the model."""
    if requests <= 0 or window_seconds <= 0:
        return None
    if window_seconds <= 1:
        return RateLimit(requests=requests, per="second")
    if window_seconds <= 60:
        return RateLimit(
            requests=max(1, round(requests * 60 / window_seconds)),
            per="minute",
        )
    return RateLimit(
        requests=max(1, round(requests * 3600 / window_seconds)),
        per="hour",
    )


def _text(root: ET.Element, path: str) -> str:
    el = root.find(path)
    return (el.text or "").strip() if el is not None else ""


def _parse_verify_api_key(policy: ET.Element) -> AuthPolicy | None:
    key_el = policy.find("APIKey")
    if key_el is None:
        return None
    ref = (key_el.get("ref") or "").strip()
    match = re.fullmatch(r"request\.(queryparam|header)\.(.+)", ref)
    if not match:
        return None
    location = "query" if match.group(1) == "queryparam" else "header"
    return AuthPolicy(kind="apiKey", name=match.group(2), location=location)


def _parse_oauth(policy: ET.Element) -> AuthPolicy | None:
    operation = _text(policy, "Operation")
    if operation == "VerifyAccessToken":
        return AuthPolicy(kind="oauth2")
    return None  # token endpoints are not API operations


def _parse_quota(policy: ET.Element) -> RateLimit | None:
    allow = policy.find("Allow")
    if allow is None:
        return None
    count = allow.get("count")
    if not count:
        # A bare countRef points at a per-product quota the bundle
        # cannot resolve; report no limit rather than a wrong one.
        return None
    interval = _text(policy, "Interval")
    unit = _text(policy, "TimeUnit").lower() or "minute"
    try:
        window = int(interval or "1") * _TIME_UNITS.get(unit, 60)
        return _normalize_rate(int(count), window)
    except ValueError:
        return None


def _parse_spike_arrest(policy: ET.Element) -> RateLimit | None:
    match = _SPIKE_RE.match(_text(policy, "Rate"))
    if not match:
        return None
    requests = int(match.group(1))
    window = 1 if match.group(2).lower() == "s" else 60
    return _normalize_rate(requests, window)


def _policy_from_file(path: str) -> Policy:
    """Read one Apigee policy file into a partial Policy."""
    policy = Policy()
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return policy
    tag = root.tag
    if tag == "VerifyAPIKey":
        auth = _parse_verify_api_key(root)
        if auth:
            policy.auth = auth
    elif tag == "OAuthV2":
        auth = _parse_oauth(root)
        if auth:
            policy.auth = auth
    elif tag == "Quota":
        limit = _parse_quota(root)
        if limit:
            policy.rate_limit = limit
    elif tag == "SpikeArrest":
        limit = _parse_spike_arrest(root)
        if limit:
            policy.rate_limit = limit
    return policy


def _step_names(flow_el: ET.Element) -> list[str]:
    names = []
    for step in flow_el.findall("Request/Step"):
        name = _text(step, "Name")
        if name:
            names.append(name)
    return names


def _policies_for(names: list[str], policies_dir: str) -> Policy:
    merged = Policy()
    for name in names:
        path = os.path.join(policies_dir, f"{name}.xml")
        if os.path.isfile(path):
            merged = merged.merge(_policy_from_file(path))
    return merged


def load_bundle(bundle_dir: str) -> ApiEstate:
    """Load an Apigee bundle directory into an ApiEstate."""
    root = bundle_dir
    if os.path.isdir(os.path.join(bundle_dir, "apiproxy")):
        root = os.path.join(bundle_dir, "apiproxy")
    proxies_dir = os.path.join(root, "proxies")
    targets_dir = os.path.join(root, "targets")
    policies_dir = os.path.join(root, "policies")
    if not os.path.isdir(proxies_dir):
        raise ValueError(
            f"{bundle_dir!r} does not look like an Apigee bundle "
            "(no apiproxy/proxies directory)"
        )

    proxy_files = sorted(
        f for f in os.listdir(proxies_dir) if f.endswith(".xml")
    )
    if not proxy_files:
        raise ValueError(f"no proxy endpoints found in {proxies_dir!r}")

    # Base URL comes from the first target endpoint's backend URL.
    base_url = ""
    if os.path.isdir(targets_dir):
        for name in sorted(os.listdir(targets_dir)):
            if not name.endswith(".xml"):
                continue
            try:
                target = ET.parse(os.path.join(targets_dir, name)).getroot()
            except ET.ParseError:
                continue
            base_url = _text(target, "HTTPTargetConnection/URL").rstrip("/")
            if base_url:
                break

    title = "API"
    version = "1"
    for name in sorted(os.listdir(root)):
        if name.endswith(".xml"):
            try:
                proxy = ET.parse(os.path.join(root, name)).getroot()
            except ET.ParseError:
                continue
            if proxy.tag == "APIProxy":
                title = proxy.get("name") or title
                version = proxy.get("revision") or version
                break

    slug = slugify(title)
    estate = ApiEstate(
        title=title, slug=slug, version=version, base_url=base_url
    )

    for proxy_file in proxy_files:
        proxy = ET.parse(os.path.join(proxies_dir, proxy_file)).getroot()
        preflow = proxy.find("PreFlow")
        global_policy = Policy()
        if preflow is not None:
            global_policy = _policies_for(_step_names(preflow), policies_dir)

        for flow in proxy.findall("Flows/Flow"):
            condition = _text(flow, "Condition")
            verb = _VERB_RE.search(condition)
            path = _PATH_RE.search(condition)
            if not verb or not path:
                continue  # not a routable API flow
            flow_policy = _policies_for(
                _step_names(flow), policies_dir
            )
            policy = global_policy.merge(flow_policy)

            flow_name = flow.get("name") or ""
            operation_id = camel_to_snake(flow_name) or (
                f"{verb.group(1).lower()}_{path.group(1)}"
            )
            parameters = [
                Parameter(
                    name=name,
                    location="path",
                    required=True,
                    schema_type="string",
                )
                for name in path_params(path.group(1))
            ]
            estate.endpoints.append(
                Endpoint(
                    operation_id=operation_id,
                    tool_name=f"{slug}_{operation_id}",
                    method=verb.group(1).upper(),
                    path=path.group(1),
                    summary=_text(flow, "Description"),
                    description="",
                    parameters=parameters,
                    policy=policy,
                )
            )

    if not estate.endpoints:
        raise ValueError(
            f"no routable flows found in {proxies_dir!r} "
            "(expected proxy.pathsuffix MatchesPath conditions)"
        )
    return estate
