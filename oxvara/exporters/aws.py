"""Import an Amazon API Gateway REST API into a normalized ApiEstate.

Input is a directory holding what the AWS CLI returns for one API stage::

    <dir>/openapi.json      # aws apigateway get-export --rest-api-id ID \
                            #   --stage-name STAGE --export-type oas30 \
                            #   --parameters extensions=apigateway openapi.json
    <dir>/stage.json        # aws apigateway get-stage --rest-api-id ID \
                            #   --stage-name STAGE            (optional)
    <dir>/usage-plans.json  # aws apigateway get-usage-plans  (optional)

The export carries routes, authorizers and API-key requirements. Throttling
does not travel with it: it lives on the stage (``methodSettings``) and in
usage plans, which is why those two files are read alongside.

Auth, from each operation's ``security`` (or the document default):

- a plain ``apiKey`` scheme (API key required): apiKey in its header,
  normally ``x-api-key``
- ``x-amazon-apigateway-authtype: cognito_user_pools``: oauth2 (Cognito
  issues the tokens)
- any other authtype with an ``x-amazon-apigateway-authorizer`` (a Lambda
  authorizer): bearer, a token the client presents
- ``awsSigv4`` (IAM): not modeled; reported as a note

OpenAPI ``security`` is a list of alternatives, any one of which grants
access. The effective protection is therefore the *weakest* alternative,
and within one alternative (all schemes required) the strongest scheme.

Rate limits: the tightest of the stage default (``*/*``), the stage
method setting, the usage plan's API-stage method throttle, the usage
plan throttle and the usage plan quota. Usage-plan limits apply per API
key, which is exactly what an agent holding one key is held to.

Tools call the invoke URL from the export's ``servers`` entry, which is
the API Gateway endpoint; integration URIs are recorded as the upstream
only, so a configuration that would bypass API Gateway is caught.
"""

from __future__ import annotations

import json
import os

import yaml

from ..models import AUTH_STRENGTH, ApiEstate, AuthPolicy, Policy, RateLimit
from ..parser import parse_document
from ..util import normalize_rate

_EXPORT_NAMES = ("openapi.json", "openapi.yaml", "openapi.yml")
_QUOTA_PERIODS = {"DAY": 86400, "WEEK": 604800, "MONTH": 2592000}


def is_aws_export(path: str) -> bool:
    """True when a directory holds an API Gateway export."""
    if not os.path.isdir(path):
        return False
    if os.path.isfile(os.path.join(path, "stage.json")):
        return True
    for name in _EXPORT_NAMES:
        export = os.path.join(path, name)
        if os.path.isfile(export):
            with open(export, "r", encoding="utf-8") as fh:
                return "x-amazon-apigateway" in fh.read()
    return False


def _load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text) if path.endswith(".json") else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc


def _optional(path: str):
    return _load(path) if os.path.isfile(path) else None


def _invoke_url(doc: dict) -> str:
    """Resolve the export's servers[0].url template with variable defaults."""
    servers = doc.get("servers") or []
    if not servers or not isinstance(servers[0], dict):
        return ""
    url = str(servers[0].get("url", ""))
    for name, var in (servers[0].get("variables") or {}).items():
        default = str((var or {}).get("default", "")).strip("/")
        url = url.replace("/{" + name + "}", "/" + default if default else "")
        url = url.replace("{" + name + "}", default)
    return url.rstrip("/")


def _per_second(rate: float) -> RateLimit | None:
    """API Gateway rates are requests per second and may be fractional."""
    if rate is None or rate <= 0:
        return None
    if float(rate).is_integer():
        return RateLimit(requests=int(rate), per="second")
    return normalize_rate(max(1, round(rate * 60)), 60)


def _tightest(limits: list[RateLimit | None]) -> RateLimit | None:
    real = [lim for lim in limits if lim is not None]
    return min(real, key=lambda lim: lim.per_second()) if real else None


def _method_key(path: str, method: str) -> str:
    """Normalize stage (``~1pets/GET``) and usage plan (``/pets/GET``) keys."""
    return f"{path.replace('~1', '/').rstrip('/') or '/'}|{method.upper()}"


def _split_key(raw: str) -> str:
    path, _, method = raw.rpartition("/")
    path = path.replace("~1", "/")
    if not path.startswith("/"):
        path = "/" + path
    return _method_key(path, method)


def _scheme_auth(name: str, scheme: dict, notes: list[str]) -> AuthPolicy | None:
    authtype = str(scheme.get("x-amazon-apigateway-authtype", "")).strip()
    if authtype == "cognito_user_pools":
        return AuthPolicy(kind="oauth2")
    if authtype.lower() == "awssigv4":
        notes.append(
            f"security scheme {name}: IAM (SigV4) auth is not modeled; "
            "operations using only it are reported as unauthenticated"
        )
        return None
    if authtype or scheme.get("x-amazon-apigateway-authorizer"):
        return AuthPolicy(kind="bearer")  # Lambda authorizer: client token
    if scheme.get("type") == "apiKey":
        return AuthPolicy(
            kind="apiKey",
            name=str(scheme.get("name", "x-api-key")),
            location=str(scheme.get("in", "header")).lower(),
        )
    if scheme.get("type") == "oauth2" or scheme.get("type") == "openIdConnect":
        return AuthPolicy(kind="oauth2")
    if scheme.get("type") == "http":
        return AuthPolicy(kind="basic" if scheme.get("scheme") == "basic" else "bearer")
    return None


def _strength(auth: AuthPolicy | None) -> int:
    return AUTH_STRENGTH.get(auth.kind, 0) if auth else 0


def _effective_auth(security, schemes: dict, notes: list[str]) -> AuthPolicy:
    """Weakest alternative; strongest scheme inside an alternative."""
    if not security:
        return AuthPolicy()
    alternatives = []
    for requirement in security:
        if not requirement:  # {} means anonymous access is allowed
            return AuthPolicy()
        best = None
        for name in requirement:
            auth = _scheme_auth(name, schemes.get(name) or {}, notes)
            if _strength(auth) > _strength(best):
                best = auth
        alternatives.append(best or AuthPolicy())
    return min(alternatives, key=_strength)


def _stage_limits(stage: dict | None) -> tuple[RateLimit | None, dict[str, RateLimit]]:
    if not stage:
        return None, {}
    default = None
    per_method: dict[str, RateLimit] = {}
    for key, setting in (stage.get("methodSettings") or {}).items():
        limit = _per_second((setting or {}).get("throttlingRateLimit"))
        if key in ("*/*", "~1*/*"):
            default = limit
        elif limit:
            per_method[_split_key(key)] = limit
    return default, per_method


def _plan_limits(
    plans: dict | None, api_id: str, stage_name: str
) -> tuple[RateLimit | None, dict[str, RateLimit], list[str]]:
    """Limits from every usage plan attached to this API stage."""
    if not plans:
        return None, {}, []
    # Several plans can cover one stage and a key belongs to one plan, so
    # the ceiling an agent could reach is the most generous plan's limit.
    plan_limits: list[RateLimit | None] = []
    method_limits: dict[str, list[RateLimit | None]] = {}
    names = []
    for plan in plans.get("items") or []:
        stages = [
            s for s in plan.get("apiStages") or []
            if (not api_id or s.get("apiId") == api_id)
            and (not stage_name or s.get("stage") == stage_name)
        ]
        if not stages:
            continue
        names.append(str(plan.get("name") or plan.get("id")))
        quota = plan.get("quota") or {}
        window = _QUOTA_PERIODS.get(str(quota.get("period", "")).upper())
        plan_limits.append(_tightest([
            _per_second((plan.get("throttle") or {}).get("rateLimit")),
            normalize_rate(int(quota["limit"]), window)
            if window and quota.get("limit") else None,
        ]))
        for s in stages:
            for key, throttle in (s.get("throttle") or {}).items():
                method_limits.setdefault(_split_key(key), []).append(
                    _per_second((throttle or {}).get("rateLimit"))
                )
    return (
        _most_generous(plan_limits),
        {k: _most_generous(v) for k, v in method_limits.items()},
        names,
    )


def _most_generous(limits: list[RateLimit | None]) -> RateLimit | None:
    """None (unlimited) wins; otherwise the highest sustained rate."""
    if not limits or any(lim is None for lim in limits):
        return None
    return max(limits, key=lambda lim: lim.per_second())


def _upstream(doc: dict) -> str:
    for path_item in (doc.get("paths") or {}).values():
        for op in (path_item or {}).values():
            if not isinstance(op, dict):
                continue
            integration = op.get("x-amazon-apigateway-integration") or {}
            if str(integration.get("type", "")).lower() in ("http", "http_proxy"):
                uri = str(integration.get("uri", ""))
                if uri.startswith("http"):
                    return uri.split("{")[0].rstrip("/")
    return ""


def load_aws(export_dir: str, gateway_url: str = "") -> ApiEstate:
    """Load an API Gateway export directory into an ApiEstate."""
    export = next(
        (os.path.join(export_dir, n) for n in _EXPORT_NAMES
         if os.path.isfile(os.path.join(export_dir, n))),
        None,
    )
    if export is None:
        raise ValueError(
            f"{export_dir!r} does not look like an API Gateway export "
            "(no openapi.json/yaml found)"
        )
    doc = _load(export)
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3."):
        raise ValueError(f"{export} is not an OpenAPI 3 export (use --export-type oas30)")
    stage = _optional(os.path.join(export_dir, "stage.json"))
    plans = _optional(os.path.join(export_dir, "usage-plans.json"))

    base = gateway_url.rstrip("/") or _invoke_url(doc)
    estate = parse_document(doc, Policy(), base)
    estate.kind = "aws"
    estate.upstream_url = _upstream(doc)
    notes = estate.notes

    stage_name = str((stage or {}).get("stageName", ""))
    api_id = str((stage or {}).get("restApiId", "") or doc.get("x-amazon-apigateway-rest-api-id", ""))
    if not stage_name:
        notes.append("no stage.json: stage throttling is unknown")
    if plans is None:
        notes.append("no usage-plans.json: usage plan throttling and quotas are unknown")
    if str(doc.get("x-amazon-apigateway-api-key-source", "HEADER")).upper() == "AUTHORIZER":
        notes.append("API key source is AUTHORIZER: keys come from a Lambda authorizer, "
                     "not the x-api-key header")

    stage_default, stage_methods = _stage_limits(stage)
    plan_overall, plan_methods, plan_names = _plan_limits(plans, api_id, stage_name)
    if plans is not None and not plan_names:
        notes.append("no usage plan is attached to this API stage")

    schemes = ((doc.get("components") or {}).get("securitySchemes")) or {}
    root_security = doc.get("security")
    paths = doc.get("paths") or {}
    seen_notes: set[str] = set()
    for ep in estate.endpoints:
        op = (paths.get(ep.path) or {}).get(ep.method.lower()) or {}
        security = op.get("security", root_security)
        scheme_notes: list[str] = []
        ep.policy.auth = _effective_auth(security, schemes, scheme_notes)
        for n in scheme_notes:
            if n not in seen_notes:
                seen_notes.add(n)
                notes.append(n)
        key = _method_key(ep.path, ep.method)
        ep.policy.rate_limit = _tightest([
            stage_default, stage_methods.get(key), plan_overall, plan_methods.get(key),
        ])
        integration = op.get("x-amazon-apigateway-integration") or {}
        timeout_ms = integration.get("timeoutInMillis")
        if isinstance(timeout_ms, int) and timeout_ms > 0:
            ep.policy.timeout = max(1, round(timeout_ms / 1000))
    return estate
