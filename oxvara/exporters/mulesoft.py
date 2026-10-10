"""Import a MuleSoft Anypoint API into a normalized ApiEstate.

Input is a directory holding what Anypoint gives you for one managed API::

    <dir>/openapi.json      # the API spec, downloaded from Exchange
                            # (or openapi.yaml)
    <dir>/policies.json     # the policies applied in API Manager

The spec carries the routes. Governance travels separately: API Manager
policies are not part of the Exchange download, so ``policies.json``
lists them in a small schema Oxvara defines::

    [
      {"type": "client-id-enforcement",
       "config": {"headers": ["client_id", "client_secret"]}},
      {"type": "rate-limiting",
       "config": {"limit": 100, "window": "minute"}},
      {"type": "jwt-validation"},
      {"type": "ip-allowlist",
       "config": {"ips": ["10.0.0.0/8"]},
       "methods": ["POST"], "paths": ["/orders"]}
    ]

``type`` is the Anypoint policy name, lowercased with spaces and
underscores turned into hyphens. ``config`` holds the policy settings.
``methods`` and ``paths`` are optional: without them a policy applies to
every operation, matching how API Manager applies a policy to the whole
API unless you scope it to methods and resources.

Mapping:

- ``client-id-enforcement``: apiKey, sent in the first configured
  header (Anypoint's default pair is ``client_id``/``client_secret``).
  The model holds one key name, so any further required headers are
  reported, not guessed at.
- ``rate-limiting``: the ``limit`` per ``window`` (``second``,
  ``minute``, ``hour``, ``day``, or a number of seconds).
- ``jwt-validation``: bearer. The client presents a JWT Anypoint verifies.
- ``basic-authentication``: basic.
- ``oauth2``: oauth2. The client presents an access token Anypoint enforces.
- ``ip-allowlist``, ``ip-blacklist``, ``cors``, header injection/removal
  and message logging are recognized but not modeled; they are reported
  as notes. Anything else is an unknown policy and is reported too.

When several auth policies apply to one operation the strongest wins;
when several rate limits apply the tightest wins.

Tools call the Anypoint gateway URL, which the Exchange spec does not
name, so the caller supplies it as the gateway URL. The spec's own
``servers`` URL is kept as the upstream, so a configuration that would
bypass API Manager is caught.
"""

from __future__ import annotations

import json
import os

import yaml

from ..models import AUTH_STRENGTH, ApiEstate, AuthPolicy, Policy, RateLimit
from ..parser import parse_document
from ..util import normalize_rate

_EXPORT_NAMES = ("openapi.json", "openapi.yaml", "openapi.yml")
_POLICY_FILE = "policies.json"
_WINDOWS = {
    "second": 1, "seconds": 1,
    "minute": 60, "minutes": 60,
    "hour": 3600, "hours": 3600,
    "day": 86400, "days": 86400,
}
# Recognized Anypoint policy names that Oxvara does not model. They are
# reported as notes rather than silently dropped.
_UNMODELED = {
    "ip-allowlist", "ip-blacklist", "cors", "header-injection",
    "header-removal", "message-logging",
}
_AUTH_ALIASES = {
    "basic-auth": "basic-authentication",
    "oauth-2.0-access-token-enforcement": "oauth2",
}


def is_mulesoft_export(path: str) -> bool:
    """True when a directory holds an Anypoint export (spec + policies)."""
    if not os.path.isdir(path):
        return False
    if not os.path.isfile(os.path.join(path, _POLICY_FILE)):
        return False
    return any(
        os.path.isfile(os.path.join(path, name)) for name in _EXPORT_NAMES
    )


def _load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text) if path.endswith(".json") else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc


def _spec_url(doc: dict) -> str:
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict):
        return str(servers[0].get("url", "")).rstrip("/")
    return ""


def _canon(raw) -> str:
    return str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")


def _window_seconds(raw) -> int | None:
    if isinstance(raw, (int, float)) and raw > 0:
        return int(raw)
    seconds = _WINDOWS.get(str(raw or "").strip().lower())
    return seconds


def _strength(auth: AuthPolicy) -> int:
    return AUTH_STRENGTH.get(auth.kind, 0)


def _auth_from(ptype: str, config: dict, notes: list[str]) -> AuthPolicy | None:
    ptype = _AUTH_ALIASES.get(ptype, ptype)
    if ptype == "client-id-enforcement":
        headers = [str(h) for h in (config.get("headers") or ["client_id"]) if h]
        if len(headers) > 1:
            notes.append(
                "client-id-enforcement also requires header(s) "
                + ", ".join(headers[1:])
                + "; only the first is modeled"
            )
        return AuthPolicy(kind="apiKey", name=headers[0], location="header")
    if ptype == "jwt-validation":
        return AuthPolicy(kind="bearer")
    if ptype == "basic-authentication":
        return AuthPolicy(kind="basic")
    if ptype == "oauth2":
        return AuthPolicy(kind="oauth2")
    return None


def _rate_from(ptype: str, config: dict, notes: list[str]) -> RateLimit | None:
    if ptype != "rate-limiting":
        return None
    limit = config.get("limit")
    window = _window_seconds(config.get("window"))
    if not isinstance(limit, (int, float)) or limit <= 0:
        notes.append("rate-limiting has no positive limit; ignored")
        return None
    if window is None:
        notes.append("rate-limiting has an unknown window; ignored")
        return None
    return normalize_rate(int(limit), window)


def _applies(policy: dict, method: str, path: str) -> bool:
    methods = policy.get("methods")
    if methods and method.upper() not in {str(m).upper() for m in methods}:
        return False
    paths = policy.get("paths")
    if not paths:
        return True
    return any(
        path == str(p) or path.startswith(str(p).rstrip("/") + "/")
        for p in paths
    )


def _tightest(limits: list[RateLimit | None]) -> RateLimit | None:
    real = [lim for lim in limits if lim is not None]
    return min(real, key=lambda lim: lim.per_second()) if real else None


def _policy_effects(
    policies: list[dict], notes: list[str]
) -> tuple[AuthPolicy | None, list[RateLimit | None], list[tuple]]:
    """Split policies into API-wide effects and operation-scoped ones.

    Returns (default auth, default rate limits, scoped effects). Each
    scoped effect is (auth or None, rate limit or None, selector dict).
    """
    default_auth: AuthPolicy | None = None
    default_rates: list[RateLimit | None] = []
    scoped: list[tuple] = []
    for raw in policies:
        if not isinstance(raw, dict):
            notes.append(f"policy entry {raw!r} is not an object; ignored")
            continue
        ptype = _canon(raw.get("type"))
        if not ptype:
            notes.append("a policy entry has no type; ignored")
            continue
        config = raw.get("config") or {}
        if not isinstance(config, dict):
            notes.append(f"policy {ptype}: config is not an object; ignored")
            continue
        auth = _auth_from(ptype, config, notes)
        rate = _rate_from(ptype, config, notes)
        if auth is None and rate is None:
            if ptype in _UNMODELED:
                notes.append(
                    f"policy {ptype} is not modeled; operations it guards "
                    "are reported without it"
                )
            else:
                notes.append(
                    f"unknown policy type {ptype!r}; not modeled, "
                    "reported rather than guessed at"
                )
            continue
        if raw.get("methods") or raw.get("paths"):
            scoped.append((auth, rate, raw))
            continue
        # API-wide: strongest auth wins, tightest rate limit wins.
        if auth and (default_auth is None or _strength(auth) > _strength(default_auth)):
            default_auth = auth
        default_rates.append(rate)
    return default_auth, default_rates, scoped


def load_mulesoft(export_dir: str, gateway_url: str = "") -> ApiEstate:
    """Load an Anypoint export directory into an ApiEstate."""
    export = next(
        (os.path.join(export_dir, n) for n in _EXPORT_NAMES
         if os.path.isfile(os.path.join(export_dir, n))),
        None,
    )
    if export is None:
        raise ValueError(
            f"{export_dir!r} does not look like an Anypoint export "
            "(no openapi.json/yaml found)"
        )
    policies_path = os.path.join(export_dir, _POLICY_FILE)
    if not os.path.isfile(policies_path):
        raise ValueError(
            f"{export_dir!r} has no {_POLICY_FILE}: export the applied "
            "policies from API Manager alongside the spec"
        )
    doc = _load(export)
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3."):
        raise ValueError(f"{export} is not an OpenAPI 3 spec")
    policies = _load(policies_path)
    if not isinstance(policies, list):
        raise TypeError(f"{policies_path} must hold a list of policies")

    gateway_url = gateway_url.rstrip("/")
    spec_url = _spec_url(doc)
    base = gateway_url or spec_url
    estate = parse_document(doc, Policy(), base)
    estate.kind = "mulesoft"
    notes = estate.notes
    if gateway_url and spec_url and spec_url != gateway_url:
        estate.upstream_url = spec_url
    if not gateway_url:
        notes.append(
            "no gateway URL given for this Anypoint API; pass --gateway-url "
            "(or PATH@https://host) so tools call the Anypoint gateway and "
            "its policies are enforced"
        )

    default_auth, default_rates, scoped = _policy_effects(policies, notes)
    for ep in estate.endpoints:
        # Policies stack in API Manager: every applicable policy applies,
        # so keep the strongest auth and the tightest rate limit.
        auths = [default_auth] if default_auth else []
        rates = list(default_rates)
        for auth, rate, selector in scoped:
            if _applies(selector, ep.method, ep.path):
                if auth:
                    auths.append(auth)
                rates.append(rate)
        best = max(auths, key=_strength) if auths else AuthPolicy()
        ep.policy = Policy(auth=best, rate_limit=_tightest(rates))
    return estate
