"""Parse an OpenAPI 3.x document into a normalized ApiEstate.

Governance is read from `x-oxvara` extension blocks. A block at the
document root sets the defaults for the whole estate; a block on an
operation overrides the defaults for that operation only. Operations
without an explicit block simply inherit.

Example:

    x-oxvara:
      baseUrl: https://api.example.com/v1
      auth:
        kind: apiKey
        name: X-API-Key
        in: header
      rateLimit:
        requests: 100
        per: minute
      timeout: 30
"""

from __future__ import annotations

import json
import re

import yaml

from .models import (
    ApiEstate,
    AuthPolicy,
    BodyProperty,
    Endpoint,
    Parameter,
    Policy,
    RateLimit,
)

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "api"


def _camel_to_snake(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    name = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower().strip("_") or "operation"


def _parse_rate_limit(raw: dict | None) -> RateLimit | None:
    if not raw:
        return None
    requests = int(raw.get("requests", 0))
    per = str(raw.get("per", "minute")).lower()
    if requests <= 0 or per not in ("second", "minute", "hour"):
        return None
    return RateLimit(requests=requests, per=per)


def _parse_auth(raw: dict | None) -> AuthPolicy:
    if not raw:
        return AuthPolicy(kind="none")
    kind = str(raw.get("kind", "none")).lower()
    if kind not in ("apikey", "bearer", "oauth2", "none"):
        raise ValueError(f"unsupported x-oxvara auth kind: {kind!r}")
    kind = "apiKey" if kind == "apikey" else kind
    return AuthPolicy(
        kind=kind,
        name=str(raw.get("name", "")),
        location=str(raw.get("in", "header")).lower(),
    )


def _parse_policy(raw: dict | None) -> Policy:
    raw = raw or {}
    return Policy(
        auth=_parse_auth(raw.get("auth")),
        rate_limit=_parse_rate_limit(raw.get("rateLimit")),
        timeout=int(raw.get("timeout", 30)),
    )


def _schema_type(schema: dict) -> str:
    t = str(schema.get("type", "string")).lower()
    return t if t in ("string", "integer", "number", "boolean") else "string"


def parse_spec(text: str) -> ApiEstate:
    """Parse OpenAPI YAML or JSON text into an ApiEstate."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"could not parse spec: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("spec must be a mapping")
    openapi = str(doc.get("openapi", ""))
    if not openapi.startswith("3."):
        raise ValueError(
            f"oxvara currently supports OpenAPI 3.x, got {openapi!r}"
        )

    info = doc.get("info", {}) or {}
    title = str(info.get("title", "API"))
    slug = _slugify(title)
    version = str(info.get("version", "0"))

    default_policy = _parse_policy(doc.get("x-oxvara"))
    base_url = str((doc.get("x-oxvara") or {}).get("baseUrl", ""))
    if not base_url:
        servers = doc.get("servers") or []
        if servers and isinstance(servers[0], dict):
            base_url = str(servers[0].get("url", ""))

    estate = ApiEstate(
        title=title, slug=slug, version=version, base_url=base_url
    )

    paths = doc.get("paths", {}) or {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters", []) or []
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            estate.endpoints.append(
                _parse_operation(
                    slug, path, method, operation, shared_params,
                    default_policy,
                )
            )

    if not estate.endpoints:
        raise ValueError("spec contains no operations to compile")
    return estate


def _parse_operation(
    slug: str,
    path: str,
    method: str,
    operation: dict,
    shared_params: list,
    default_policy: Policy,
) -> Endpoint:
    operation_id = str(
        operation.get("operationId")
        or f"{method}_{path}".replace("/", "_").strip("_")
    )
    tool_name = f"{slug}_{_camel_to_snake(operation_id)}"
    policy = default_policy.merge(_parse_policy(operation.get("x-oxvara")))

    parameters: list[Parameter] = []
    for raw in list(shared_params) + list(operation.get("parameters", []) or []):
        if not isinstance(raw, dict):
            continue
        parameters.append(
            Parameter(
                name=str(raw.get("name", "")),
                location=str(raw.get("in", "query")).lower(),
                required=bool(raw.get("required", False))
                or str(raw.get("in", "")).lower() == "path",
                schema_type=_schema_type(raw.get("schema", {}) or {}),
            )
        )

    body_properties: list[BodyProperty] = []
    body_raw = False
    request_body = operation.get("requestBody") or {}
    content = request_body.get("content", {}) or {}
    media = content.get("application/json") or {}
    schema = media.get("schema", {}) or {}
    if schema:
        required = set(schema.get("required", []) or [])
        props = schema.get("properties") or {}
        if props:
            for name, prop in props.items():
                body_properties.append(
                    BodyProperty(
                        name=str(name),
                        required=str(name) in required,
                        schema_type=_schema_type(prop or {}),
                    )
                )
        else:
            body_raw = True

    return Endpoint(
        operation_id=operation_id,
        tool_name=tool_name,
        method=method.upper(),
        path=path,
        summary=str(operation.get("summary", "")),
        description=str(operation.get("description", "")),
        parameters=parameters,
        body_properties=body_properties,
        body_raw=body_raw,
        policy=policy,
    )


def load_spec_file(path: str) -> ApiEstate:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_spec(fh.read())
