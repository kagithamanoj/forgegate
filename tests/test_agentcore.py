"""Tests for the Bedrock AgentCore Gateway target emitter."""

import json

from oxvara.agentcore import (
    build_targets,
    credential_configs,
    openapi_for_endpoints,
    target_for_estate,
    validated_endpoints,
)
from oxvara.models import ApiEstate, AuthPolicy, Endpoint, Policy, RateLimit

_counter = [0]


def _ep(method="GET", path="/pets", auth="apiKey", name="x-api-key",
        location="header", rate=True):
    _counter[0] += 1
    return Endpoint(
        operation_id=f"{method.lower()}_pets_{_counter[0]}",
        tool_name="get_pets",
        method=method,
        path=path,
        summary="List pets",
        description="Returns all pets",
        policy=Policy(
            auth=AuthPolicy(kind=auth, name=name, location=location),
            rate_limit=RateLimit(requests=100, per="minute") if rate else None,
        ),
    )


def _estate(endpoints, base_url="https://api.example.com"):
    return ApiEstate(
        title="Pets", slug="pets", version="1.0.0",
        base_url=base_url, endpoints=endpoints, kind="aws",
    )


def test_validated_endpoints_passes_clean_estate():
    estate = _estate([_ep()])
    passing, violations = validated_endpoints(estate)
    assert len(passing) == 1
    assert violations == []


def test_validated_endpoints_excludes_unauthenticated():
    estate = _estate([_ep(), _ep(auth="none")])
    passing, violations = validated_endpoints(estate)
    assert len(passing) == 1
    assert any(v.rule == "require-auth" for v in violations)


def test_validated_endpoints_excludes_unlimited():
    estate = _estate([_ep(rate=False)])
    passing, violations = validated_endpoints(estate)
    assert passing == []
    assert any(v.rule == "require-rate-limit" for v in violations)


def test_openapi_document_structure():
    estate = _estate([_ep()])
    doc, _notes = openapi_for_endpoints(estate, estate.endpoints)
    assert doc["openapi"] == "3.0.3"
    assert doc["info"]["title"] == "Pets"
    assert doc["servers"] == [{"url": "https://api.example.com"}]
    assert "/pets" in doc["paths"]
    assert doc["paths"]["/pets"]["get"]["operationId"].startswith("get_pets")


def test_openapi_security_schemes_apikey():
    estate = _estate([_ep(auth="apiKey", name="x-api-key", location="header")])
    doc, _ = openapi_for_endpoints(estate, estate.endpoints)
    scheme = doc["components"]["securitySchemes"]["oxvaraApiKey"]
    assert scheme == {"type": "apiKey", "in": "header", "name": "x-api-key"}
    assert doc["paths"]["/pets"]["get"]["security"] == [{"oxvaraApiKey": []}]


def test_openapi_oauth2_empty_flows_with_note():
    estate = _estate([_ep(auth="oauth2")])
    doc, notes = openapi_for_endpoints(estate, estate.endpoints)
    assert doc["components"]["securitySchemes"]["oxvaraOauth2"]["flows"] == {}
    assert any("flows" in n for n in notes)


def test_credential_config_apikey_header():
    configs, _warnings = credential_configs([_ep(auth="apiKey")])
    assert len(configs) == 1
    cfg = configs[0]
    assert cfg["credentialProviderType"] == "API_KEY"
    inner = cfg["credentialProvider"]["apiKeyCredentialProvider"]
    assert inner["credentialLocation"] == "HEADER"
    assert inner["credentialParameterName"] == "x-api-key"
    assert "providerArn" in inner


def test_credential_config_apikey_query():
    configs, _ = credential_configs([_ep(auth="apiKey", location="query")])
    inner = configs[0]["credentialProvider"]["apiKeyCredentialProvider"]
    assert inner["credentialLocation"] == "QUERY_PARAMETER"


def test_credential_config_bearer_uses_bearer_prefix():
    configs, _ = credential_configs([_ep(auth="bearer")])
    inner = configs[0]["credentialProvider"]["apiKeyCredentialProvider"]
    assert inner["credentialParameterName"] == "Authorization"
    assert inner["credentialPrefix"] == "Bearer"


def test_credential_config_basic_uses_basic_prefix():
    configs, _ = credential_configs([_ep(auth="basic")])
    inner = configs[0]["credentialProvider"]["apiKeyCredentialProvider"]
    assert inner["credentialPrefix"] == "Basic"


def test_credential_config_oauth2_warns():
    configs, warnings = credential_configs([_ep(auth="oauth2")])
    assert configs[0]["credentialProviderType"] == "OAUTH"
    assert any("OAUTH" in w for w in warnings)


def test_credential_config_none_warns():
    _, warnings = credential_configs([_ep(auth="none")])
    assert any("no auth" in w for w in warnings)


def test_target_shape_matches_create_gateway_target():
    estate = _estate([_ep()])
    target, _notes = target_for_estate(estate, estate.endpoints,
                                      gateway_id="gw-123")
    assert target["gatewayIdentifier"] == "gw-123"
    assert target["name"] == "oxvara-pets"
    mcp = target["targetConfiguration"]["mcp"]
    payload = json.loads(mcp["openApiSchema"]["inlinePayload"])
    assert payload["openapi"] == "3.0.3"
    assert isinstance(target["credentialProviderConfigurations"], list)


def test_target_placeholder_gateway_id_noted():
    estate = _estate([_ep()])
    target, notes = target_for_estate(estate, estate.endpoints)
    assert target["gatewayIdentifier"] == "<GATEWAY_ID>"
    assert any("gatewayIdentifier" in n for n in notes)


def test_build_targets_skips_failing_operations():
    estate = _estate([_ep(), _ep(auth="none"), _ep(path="/orders", rate=False)])
    result = build_targets([estate], gateway_id="gw-1")
    assert len(result["targets"]) == 1
    assert len(result["skipped"]) == 2
    payload = json.loads(result["targets"][0]
                         ["targetConfiguration"]["mcp"]
                         ["openApiSchema"]["inlinePayload"])
    assert list(payload["paths"]) == ["/pets"]


def test_build_targets_empty_estate_no_target():
    estate = _estate([_ep(auth="none")])
    result = build_targets([estate])
    assert result["targets"] == []
    assert any("no operations passed" in n for n in result["notes"])


def test_build_targets_multiple_estates():
    e1 = _estate([_ep()], base_url="https://one.example.com")
    e2 = _estate([_ep()], base_url="https://two.example.com")
    e2.slug = "orders"
    result = build_targets([e1, e2], gateway_id="gw-1")
    assert len(result["targets"]) == 2
    assert {t["name"] for t in result["targets"]} == {
        "oxvara-pets", "oxvara-orders"}
