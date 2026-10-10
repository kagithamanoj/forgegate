"""Import an Amazon API Gateway HTTP API (v2) into a normalized ApiEstate.

Input is a directory holding what the AWS CLI returns for one API stage::

    <dir>/openapi.json      # aws apigatewayv2 export-api --api-id ID \
                            #   --stage-name '$default' --specification OAS30 \
                            #   --output-type JSON openapi.json
    <dir>/stage.json        # aws apigatewayv2 get-stage --api-id ID \
                            #   --stage-name '$default'       (optional)

HTTP APIs use routes rather than resources and methods. The export is
OpenAPI 3.0; authorizers ride on security schemes:

- ``x-amazon-apigateway-authtype: jwt``: oauth2 (a JWT bearer token)
- a Lambda authorizer (``x-amazon-apigateway-authorizer`` with type
  ``request``): bearer, a token the client presents
- ``awsSigv4`` (IAM): sigv4, signed with the caller's AWS credentials
- a plain ``apiKey`` scheme: apiKey in its header

Throttling for HTTP APIs lives on the stage, not in the export:
``DefaultRouteSettings`` carries the stage default and ``RouteSettings``
carries per-route overrides, keyed like ``"GET /pets"``. There are no
usage plans for HTTP APIs.

Note: this importer is built from the AWS API documentation for
``apigatewayv2 export-api`` and ``get-stage``. The sample in
``examples/aws/http-api`` follows that documented shape.
"""

from __future__ import annotations

import json
import os

import yaml

from ..models import AUTH_STRENGTH, ApiEstate, AuthPolicy, Policy, RateLimit
from ..parser import parse_document
from ..util import normalize_rate

_EXPORT_NAMES = ("openapi.json", "openapi.yaml", "openapi.yml")


def is_aws_v2_export(path: str) -> bool:
    """True when a directory holds an API Gateway HTTP API (v2) export."""
    if not os.path.isdir(path):
        return False
    stage = os.path.join(path, "stage.json")
    if os.path.isfile(stage):
        with open(stage, "r", encoding="utf-8") as fh:
            text = fh.read()
            if "DefaultRouteSettings" in text or "RouteSettings" in text:
                return True
    for name in _EXPORT_NAMES:
        export = os.path.join(path, name)
        if os.path.isfile(export):
            with open(export, "r", encoding="utf-8") as fh:
                text = fh.read()
                # v2 JWT authorizers are the clearest marker; the v1
                # importer claims anything else with x-amazon-apigateway.
                if '"x-amazon-apigateway-authtype": "jwt"' in text:
                    return True
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
    servers = doc.get("servers") or []
    if not servers or not isinstance(servers[0], dict):
        return ""
    return str(servers[0].get("url", "")).rstrip("/")


def _per_second(rate: float) -> RateLimit | None:
    if rate is None or rate <= 0:
        return None
    if float(rate).is_integer():
        return RateLimit(requests=int(rate), per="second")
    return normalize_rate(max(1, round(rate * 60)), 60)


def _tightest(limits: list[RateLimit | None]) -> RateLimit | None:
    real = [lim for lim in limits if lim is not None]
    return min(real, key=lambda lim: lim.per_second()) if real else None


def _route_key(route: str) -> str:
    """Normalize a v2 route key (``GET /pets``) to ``/pets|GET``."""
    method, _, path = route.partition(" ")
    path = path.strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"{path.rstrip('/') or '/'}|{method.strip().upper()}"


def _scheme_auth(scheme: dict, notes: list[str]) -> AuthPolicy | None:
    authtype = str(scheme.get("x-amazon-apigateway-authtype", "")).strip().lower()
    if authtype == "jwt":
        return AuthPolicy(kind="oauth2")  # JWT bearer token
    if authtype == "awssigv4":
        return AuthPolicy(kind="sigv4")
    authorizer = scheme.get("x-amazon-apigateway-authorizer") or {}
    if str(authorizer.get("type", "")).lower() == "request":
        return AuthPolicy(kind="bearer")  # Lambda authorizer: client token
    if authtype == "custom" or authorizer:
        return AuthPolicy(kind="bearer")
    if scheme.get("type") == "apiKey":
        return AuthPolicy(
            kind="apiKey",
            name=str(scheme.get("name", "x-api-key")),
            location=str(scheme.get("in", "header")).lower(),
        )
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
            auth = _scheme_auth(schemes.get(name) or {}, notes)
            if _strength(auth) > _strength(best):
                best = auth
        alternatives.append(best or AuthPolicy())
    return min(alternatives, key=_strength)


def _stage_limits(stage: dict | None) -> tuple[RateLimit | None, dict[str, RateLimit]]:
    """Default and per-route throttling from a v2 stage description."""
    if not stage:
        return None, {}
    default = _per_second(
        (stage.get("DefaultRouteSettings") or {}).get("ThrottlingRateLimit")
    )
    per_route: dict[str, RateLimit] = {}
    for route, settings in (stage.get("RouteSettings") or {}).items():
        limit = _per_second((settings or {}).get("ThrottlingRateLimit"))
        if limit and route.strip() != "$default":
            per_route[_route_key(route)] = limit
    return default, per_route


def load_aws_v2(export_dir: str, gateway_url: str = "") -> ApiEstate:
    """Load an API Gateway HTTP API (v2) export directory into an ApiEstate."""
    export = next(
        (os.path.join(export_dir, n) for n in _EXPORT_NAMES
         if os.path.isfile(os.path.join(export_dir, n))),
        None,
    )
    if export is None:
        raise ValueError(
            f"{export_dir!r} does not look like an HTTP API export "
            "(no openapi.json/yaml found)"
        )
    doc = _load(export)
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3."):
        raise ValueError(f"{export} is not an OpenAPI 3 export (use --specification OAS30)")
    stage = _optional(os.path.join(export_dir, "stage.json"))

    base = gateway_url.rstrip("/") or _invoke_url(doc)
    estate = parse_document(doc, Policy(), base)
    estate.kind = "aws"
    notes = estate.notes

    if stage is None:
        notes.append("no stage.json: route throttling is unknown")
    else:
        api_id = str(stage.get("ApiId", ""))
        stage_name = str(stage.get("StageName", ""))
        if api_id or stage_name:
            notes.append(
                f"stage {stage_name or '?'} of API {api_id or '?'}: "
                "throttling from DefaultRouteSettings and RouteSettings"
            )

    default_limit, route_limits = _stage_limits(stage)
    schemes = ((doc.get("components") or {}).get("securitySchemes")) or {}
    root_security = doc.get("security")
    paths = doc.get("paths") or {}
    for ep in estate.endpoints:
        op = (paths.get(ep.path) or {}).get(ep.method.lower()) or {}
        ep.policy.auth = _effective_auth(op.get("security", root_security), schemes, notes)
        key = f"{ep.path.rstrip('/') or '/'}|{ep.method}"
        ep.policy.rate_limit = _tightest([default_limit, route_limits.get(key)])
    return estate
