"""Tests for the Amazon API Gateway importer."""

import json
import os
import shutil

import pytest

from oxvara.cli import main
from oxvara.exporters.aws import _split_key, load_aws
from oxvara.inputs import detect_source, load_inputs

EXPORT = os.path.join(os.path.dirname(__file__), "..", "examples", "aws", "orders-api")
INVOKE = "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/prod"


def _ops(estate):
    return {ep.operation_id: ep for ep in estate.endpoints}


def _copy(tmp_path):
    target = tmp_path / "api"
    shutil.copytree(EXPORT, target)
    return target


def test_detected_as_aws():
    assert detect_source(EXPORT) == "aws"


def test_tools_call_the_invoke_url_not_the_integration():
    estate = load_aws(EXPORT)
    assert estate.kind == "aws"
    assert estate.base_url == INVOKE
    assert estate.upstream_url == "http://orders.internal.example.com/orders"


def test_gateway_url_override():
    estate = load_aws(EXPORT, "https://api.example.com/orders/")
    assert estate.base_url == "https://api.example.com/orders"


def test_auth_mapping_and_security_semantics():
    ops = _ops(load_aws(EXPORT))
    key = ops["listOrders"].policy.auth
    assert (key.kind, key.name, key.location) == ("apiKey", "x-api-key", "header")
    # api_key AND Cognito: both are required, the strongest governs
    assert ops["createOrder"].policy.auth.kind == "oauth2"
    # api_key OR Lambda authorizer: either one gets in, the weakest governs
    assert ops["getOrder"].policy.auth.kind == "apiKey"
    assert ops["cancelOrder"].policy.auth.kind == "oauth2"


def test_rate_limits_take_the_tightest_layer():
    ops = _ops(load_aws(EXPORT))

    def rate(op):
        rl = ops[op].policy.rate_limit
        return (rl.requests, rl.per)

    assert rate("listOrders") == (2, "second")     # usage plan method throttle
    assert rate("createOrder") == (5, "second")    # stage method setting
    assert rate("getOrder") == (10, "second")      # usage plan throttle
    assert rate("cancelOrder") == (30, "minute")   # stage 0.5 rps


def test_usage_plans_for_other_apis_are_ignored():
    ops = _ops(load_aws(EXPORT))
    # billing-internal (1000 rps) is attached to another API id
    assert all(ep.policy.rate_limit.per_second() <= 10 for ep in ops.values())


def test_integration_timeout_is_inherited():
    ops = _ops(load_aws(EXPORT))
    assert ops["listOrders"].policy.timeout == 29
    assert ops["cancelOrder"].policy.timeout == 10


def test_ref_request_body_is_resolved():
    body = {b.name: (b.required, b.schema_type) for b in _ops(load_aws(EXPORT))["createOrder"].body_properties}
    assert body == {"sku": (True, "string"), "quantity": (True, "integer")}


def test_stage_and_usage_plan_keys_normalize_to_the_same_form():
    assert _split_key("~1orders~1{orderId}/DELETE") == _split_key("/orders/{orderId}/DELETE")
    assert _split_key("~1orders/GET") == "/orders|GET"


def test_missing_stage_and_plans_are_reported(tmp_path):
    api = _copy(tmp_path)
    (api / "stage.json").unlink()
    (api / "usage-plans.json").unlink()
    estate = load_aws(str(api))
    assert any("stage throttling is unknown" in n for n in estate.notes)
    assert any("usage plan throttling" in n for n in estate.notes)
    assert all(ep.policy.rate_limit is None for ep in estate.endpoints)


def test_iam_and_anonymous_operations(tmp_path):
    api = _copy(tmp_path)
    doc = json.loads((api / "openapi.json").read_text())
    doc["components"]["securitySchemes"]["sigv4"] = {
        "type": "apiKey", "name": "Authorization", "in": "header",
        "x-amazon-apigateway-authtype": "awsSigv4",
    }
    doc["paths"]["/reindex"] = {"post": {
        "operationId": "reindex", "security": [{"sigv4": []}],
        "responses": {"200": {"description": "ok"}},
    }}
    doc["paths"]["/health"] = {"get": {
        "operationId": "health", "responses": {"200": {"description": "ok"}},
    }}
    (api / "openapi.json").write_text(json.dumps(doc))
    estate = load_aws(str(api))
    ops = _ops(estate)
    assert ops["reindex"].policy.auth.kind == "none"
    assert any("IAM (SigV4)" in n for n in estate.notes)
    assert ops["health"].policy.auth.kind == "none"


def test_multiple_plans_on_one_stage_use_the_most_generous(tmp_path):
    api = _copy(tmp_path)
    plans = json.loads((api / "usage-plans.json").read_text())
    plans["items"].append({
        "id": "big", "name": "bulk",
        "apiStages": [{"apiId": "a1b2c3d4e5", "stage": "prod"}],
        "throttle": {"rateLimit": 50.0, "burstLimit": 100},
    })
    (api / "usage-plans.json").write_text(json.dumps(plans))
    rl = _ops(load_aws(str(api)))["getOrder"].policy.rate_limit
    assert (rl.requests, rl.per) == (50, "second")


def test_aws_passes_strict_and_owasp_packs(capsys):
    assert main(["validate", "--pack", "strict", "--pack", "owasp-mcp", EXPORT]) == 0
    assert "no violations" in capsys.readouterr().out


def test_drift_catches_api_key_requirement_removed(tmp_path, capsys):
    api = _copy(tmp_path)
    lock = str(tmp_path / "oxvara.lock.json")
    assert main(["lock", str(api), "-o", lock]) == 0
    doc = json.loads((api / "openapi.json").read_text())
    doc["paths"]["/orders"]["get"]["security"] = []  # "API key required" switched off
    (api / "openapi.json").write_text(json.dumps(doc))
    capsys.readouterr()
    assert main(["drift", str(api), "--lock", lock]) == 1
    out = capsys.readouterr().out
    assert "auth-weakened" in out and "orders_api_list_orders" in out


def test_aws_merges_with_other_gateways():
    kong = os.path.join(os.path.dirname(EXPORT), "..", "kong", "kong.yaml") + "@https://kong.example.com"
    merged, estates = load_inputs([EXPORT, kong])
    assert [e.kind for e in estates] == ["aws", "kong"]
    assert {ep.source.split(":")[0] for ep in merged.endpoints} == {"aws", "kong"}


def test_not_an_export_raises(tmp_path):
    with pytest.raises(ValueError, match="does not look like an API Gateway export"):
        load_aws(str(tmp_path))
