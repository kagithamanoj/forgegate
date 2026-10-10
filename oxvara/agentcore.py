"""Emit Bedrock AgentCore Gateway targets from a validated estate.

After ``oxvara validate`` passes, this module turns the governed
operations into AgentCore Gateway target definitions: one per input
estate, each carrying an OpenAPI 3.x document for the operations that
passed the strict pack plus the outbound auth mapping AgentCore needs.

The output follows the ``CreateGatewayTarget`` shape from the
bedrock-agentcore-control API as documented by AWS (verified against
the AWS blog "Introducing Amazon Bedrock AgentCore Gateway" and the
AgentCore developer guide, October 2026):

- ``targetConfiguration.mcp.openApiSchema.inlinePayload`` holds the
  OpenAPI document as a JSON string.
- ``credentialProviderConfigurations`` holds one entry per distinct
  auth kind, each naming the credential provider type AgentCore
  expects (``API_KEY``, ``OAUTH``) and the fields that type needs.

Two values in every target must be filled in from the AWS account
before the target can be created, and the output marks them clearly:

- ``gatewayIdentifier``: the AgentCore gateway to attach the target to.
- each credential provider's ``providerArn``: the ARN of a credential
  provider already created in AgentCore Identity. Oxvara cannot create
  these; it only describes which kind each operation needs.
"""

from __future__ import annotations

import json

from . import __version__
from .models import ApiEstate, Endpoint
from .packs import Violation, strict_pack

# Placeholder ARNs. The real ARNs come from credential providers the
# user creates in AgentCore Identity; Oxvara has no AWS credentials and
# never invents them.
PROVIDER_ARN_PLACEHOLDER = (
    "arn:aws:bedrock-agentcore:REGION:ACCOUNT_ID:"
    "token-vault/DEFAULT/PROVIDER_TYPE/PROVIDER_NAME"
)

# Oxvara auth kinds that map onto AgentCore's API_KEY provider type.
# bearer and basic travel as an Authorization header with a prefix;
# this is the pattern AWS documents for token-style credentials.
_API_KEY_KINDS = {"apiKey", "bearer", "basic"}


def validated_endpoints(estate: ApiEstate) -> tuple[list[Endpoint], list[Violation]]:
    """Split an estate into operations that pass the strict pack and the
    violations that exclude the rest."""
    violations = strict_pack(estate)
    bad_ids = {v.operation_id for v in violations if v.operation_id}
    passing = [ep for ep in estate.endpoints if ep.operation_id not in bad_ids]
    estate_wide = [v for v in violations if not v.operation_id]
    return passing, estate_wide + [v for v in violations if v.operation_id]


def _security_schemes(endpoints: list[Endpoint]) -> tuple[dict, list[str]]:
    """OpenAPI securitySchemes for the auth kinds in use.

    Returns (schemes, notes). oauth2 flows cannot be known from gateway
    config alone, so the scheme carries an empty flows object and a note
    saying the token and authorization URLs must be filled in.
    """
    schemes: dict = {}
    notes: list[str] = []
    for ep in endpoints:
        auth = ep.policy.auth
        if auth.kind == "apiKey":
            schemes.setdefault("oxvaraApiKey", {
                "type": "apiKey",
                "in": auth.location,
                "name": auth.name or "x-api-key",
            })
        elif auth.kind == "bearer":
            schemes.setdefault("oxvaraBearer", {
                "type": "http", "scheme": "bearer",
            })
        elif auth.kind == "basic":
            schemes.setdefault("oxvaraBasic", {
                "type": "http", "scheme": "basic",
            })
        elif auth.kind == "oauth2" and "oxvaraOauth2" not in schemes:
            schemes["oxvaraOauth2"] = {"type": "oauth2", "flows": {}}
            notes.append(
                "oauth2 security scheme has empty flows: fill in the "
                "token and authorization URLs for your identity "
                "provider before registering the target"
            )
    return schemes, notes


def _operation_security(ep: Endpoint) -> list[dict]:
    auth = ep.policy.auth
    if auth.kind == "apiKey":
        return [{"oxvaraApiKey": []}]
    if auth.kind == "bearer":
        return [{"oxvaraBearer": []}]
    if auth.kind == "basic":
        return [{"oxvaraBasic": []}]
    if auth.kind == "oauth2":
        return [{"oxvaraOauth2": []}]
    return []


def openapi_for_endpoints(estate: ApiEstate, endpoints: list[Endpoint]) -> tuple[dict, list[str]]:
    """Build an OpenAPI 3.x document covering exactly these endpoints."""
    schemes, notes = _security_schemes(endpoints)
    paths: dict = {}
    for ep in endpoints:
        item = paths.setdefault(ep.path, {})
        op: dict = {
            "operationId": ep.operation_id,
            "summary": ep.summary or f"{ep.method} {ep.path}",
        }
        if ep.description:
            op["description"] = ep.description
        params = []
        for p in ep.parameters:
            params.append({
                "name": p.name,
                "in": p.location,
                "required": p.required,
                "schema": {"type": p.schema_type},
            })
        if params:
            op["parameters"] = params
        security = _operation_security(ep)
        if security:
            op["security"] = security
        item[ep.method.lower()] = op
    doc = {
        "openapi": "3.0.3",
        "info": {
            "title": estate.title or estate.slug,
            "version": estate.version or "1.0.0",
            "description": (
                f"Governed operations from {estate.kind} estate "
                f"'{estate.slug}', exported by oxvara {__version__}. "
                "Only operations that passed the strict policy pack are included."
            ),
        },
        "servers": [{"url": estate.base_url}] if estate.base_url else [],
        "paths": paths,
    }
    if schemes:
        doc["components"] = {"securitySchemes": schemes}
    return doc, notes


def credential_configs(endpoints: list[Endpoint]) -> tuple[list[dict], list[str]]:
    """Map Oxvara auth kinds to AgentCore credential provider configs.

    Returns (configs, warnings). One config per distinct auth kind.
    providerArn is always the placeholder: the user must create the
    credential provider in AgentCore Identity and fill in the real ARN.
    Auth kinds with no clean mapping produce a warning instead of a guess.
    """
    kinds = {ep.policy.auth.kind for ep in endpoints}
    configs: list[dict] = []
    warnings: list[str] = []
    if "apiKey" in kinds:
        names = {ep.policy.auth.name or "x-api-key" for ep in endpoints
                 if ep.policy.auth.kind == "apiKey"}
        locations = {ep.policy.auth.location for ep in endpoints
                     if ep.policy.auth.kind == "apiKey"}
        if len(names) > 1 or len(locations) > 1:
            warnings.append(
                "operations use different API key names or locations "
                f"({sorted(names)} in {sorted(locations)}); the target "
                "uses the first one, split the estate if they differ"
            )
        auth = next(ep.policy.auth for ep in endpoints
                    if ep.policy.auth.kind == "apiKey")
        configs.append({
            "credentialProviderType": "API_KEY",
            "credentialProvider": {
                "apiKeyCredentialProvider": {
                    "providerArn": PROVIDER_ARN_PLACEHOLDER,
                    "credentialLocation": ("QUERY_PARAMETER"
                                           if auth.location == "query"
                                           else "HEADER"),
                    "credentialParameterName": auth.name or "x-api-key",
                }
            },
        })
    if "bearer" in kinds:
        configs.append({
            "credentialProviderType": "API_KEY",
            "credentialProvider": {
                "apiKeyCredentialProvider": {
                    "providerArn": PROVIDER_ARN_PLACEHOLDER,
                    "credentialLocation": "HEADER",
                    "credentialParameterName": "Authorization",
                    "credentialPrefix": "Bearer",
                }
            },
        })
    if "basic" in kinds:
        configs.append({
            "credentialProviderType": "API_KEY",
            "credentialProvider": {
                "apiKeyCredentialProvider": {
                    "providerArn": PROVIDER_ARN_PLACEHOLDER,
                    "credentialLocation": "HEADER",
                    "credentialParameterName": "Authorization",
                    "credentialPrefix": "Basic",
                }
            },
        })
    if "oauth2" in kinds:
        configs.append({
            "credentialProviderType": "OAUTH",
            "credentialProvider": {
                "oauthCredentialProvider": {
                    "providerArn": PROVIDER_ARN_PLACEHOLDER,
                    "scopes": [],
                }
            },
        })
        warnings.append(
            "oauth2 maps to an OAUTH credential provider: create it in "
            "AgentCore Identity with your token endpoint, client ID and "
            "scopes, then fill in the providerArn"
        )
    if "none" in kinds:
        warnings.append(
            "some operations have no auth configured; they were excluded "
            "from the target because the strict pack fails them"
        )
    return configs, warnings


def target_for_estate(
    estate: ApiEstate,
    endpoints: list[Endpoint],
    gateway_id: str = "",
) -> tuple[dict, list[str]]:
    """Build one AgentCore target definition for these endpoints."""
    doc, doc_notes = openapi_for_endpoints(estate, endpoints)
    configs, auth_warnings = credential_configs(endpoints)
    target = {
        "name": f"oxvara-{estate.slug}",
        "description": (
            f"Governed tools from {estate.kind} estate '{estate.slug}' "
            f"({len(endpoints)} operations, strict pack passed)"
        ),
        "gatewayIdentifier": gateway_id or "<GATEWAY_ID>",
        "targetConfiguration": {
            "mcp": {
                "openApiSchema": {
                    "inlinePayload": json.dumps(doc),
                }
            }
        },
        "credentialProviderConfigurations": configs,
    }
    notes = doc_notes + auth_warnings
    if not gateway_id:
        notes.append(
            "gatewayIdentifier is a placeholder: pass --gateway-id with "
            "your AgentCore gateway ID"
        )
    notes.append(
        "providerArn values are placeholders: create the matching "
        "credential providers in AgentCore Identity first"
    )
    return target, notes


def build_targets(
    estates: list[ApiEstate], gateway_id: str = ""
) -> dict:
    """Build AgentCore targets for every estate, validated first.

    Returns a dict with 'targets', 'skipped' (operations excluded by
    validation) and 'notes'. Only operations passing the strict pack
    are emitted.
    """
    targets: list[dict] = []
    skipped: list[dict] = []
    notes: list[str] = []
    for estate in estates:
        passing, violations = validated_endpoints(estate)
        for v in violations:
            skipped.append({
                "rule": v.rule,
                "operation": v.operation_id,
                "message": v.message,
                "estate": estate.slug,
            })
        if not passing:
            notes.append(
                f"estate '{estate.slug}': no operations passed validation, "
                "no target emitted"
            )
            continue
        target, target_notes = target_for_estate(estate, passing, gateway_id)
        targets.append(target)
        notes.extend(f"[{estate.slug}] {n}" for n in target_notes)
        for n in estate.notes:
            notes.append(f"[{estate.slug}] import note: {n}")
    return {
        "oxvara": __version__,
        "targets": targets,
        "skipped": skipped,
        "notes": notes,
    }
