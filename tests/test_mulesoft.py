"""Tests for the MuleSoft Anypoint exporter."""

import json
import os

import pytest

from oxvara.exporters.mulesoft import is_mulesoft_export, load_mulesoft
from oxvara.inputs import detect_source, load_input

EXAMPLE = os.path.join(
    os.path.dirname(__file__), "..", "examples", "mulesoft", "orders-api"
)
GW = "https://anypoint.example.com"

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Widget API", "version": "1"},
    "servers": [{"url": "https://impl.internal/widgets"}],
    "paths": {
        "/widgets": {
            "get": {"operationId": "listWidgets"},
            "post": {"operationId": "createWidget"},
        },
        "/widgets/{id}": {
            "get": {"operationId": "getWidget"},
        },
    },
}


def _write(tmp_path, policies, spec=None):
    d = tmp_path / "anypoint"
    d.mkdir()
    (d / "openapi.json").write_text(json.dumps(spec or SPEC))
    (d / "policies.json").write_text(json.dumps(policies))
    return str(d)


def _by_id(estate):
    return {ep.operation_id: ep for ep in estate.endpoints}


def test_detects_mulesoft_export():
    assert is_mulesoft_export(EXAMPLE)
    assert detect_source(EXAMPLE) == "mulesoft"
    assert detect_source(EXAMPLE + "@" + GW) == "mulesoft"


def test_not_detected_without_policies_json(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "openapi.json").write_text(json.dumps(SPEC))
    assert not is_mulesoft_export(str(d))


def test_load_input_sets_kind_and_endpoints():
    estate = load_input(EXAMPLE + "@" + GW)
    assert estate.kind == "mulesoft"
    assert estate.title == "Orders API"
    assert set(_by_id(estate)) == {"listOrders", "createOrder", "getOrder"}


def test_client_id_enforcement_maps_to_apikey():
    ops = _by_id(load_mulesoft(EXAMPLE, GW))
    # createOrder carries a scoped jwt-validation, which is stronger;
    # the other two keep the API-wide client ID enforcement.
    for op in ("listOrders", "getOrder"):
        auth = ops[op].policy.auth
        assert (auth.kind, auth.name, auth.location) == (
            "apiKey", "client_id", "header",
        )


def test_extra_required_header_is_reported_not_guessed():
    estate = load_mulesoft(EXAMPLE, GW)
    assert any("client_secret" in n for n in estate.notes)


def test_rate_limiting_maps_to_rate_limit():
    estate = load_mulesoft(EXAMPLE, GW)
    for ep in estate.endpoints:
        rl = ep.policy.rate_limit
        assert (rl.requests, rl.per) == (100, "minute")


def test_jwt_validation_scoped_to_post_orders_only():
    ops = _by_id(load_mulesoft(EXAMPLE, GW))
    assert ops["createOrder"].policy.auth.kind == "bearer"
    assert ops["listOrders"].policy.auth.kind == "apiKey"
    assert ops["getOrder"].policy.auth.kind == "apiKey"


def test_ip_allowlist_reported_not_modeled():
    estate = load_mulesoft(EXAMPLE, GW)
    assert any("ip-allowlist" in n for n in estate.notes)


def test_unknown_policy_type_reported_not_guessed():
    estate = load_mulesoft(EXAMPLE, GW)
    assert any("response-cache" in n for n in estate.notes)


def test_strongest_auth_wins(tmp_path):
    d = _write(tmp_path, [
        {"type": "client-id-enforcement"},
        {"type": "jwt-validation"},
    ])
    estate = load_mulesoft(d, GW)
    for ep in estate.endpoints:
        assert ep.policy.auth.kind == "bearer"


def test_tightest_rate_limit_wins(tmp_path):
    d = _write(tmp_path, [
        {"type": "rate-limiting", "config": {"limit": 10, "window": "second"}},
        {"type": "rate-limiting", "config": {"limit": 100, "window": "minute"}},
    ])
    estate = load_mulesoft(d, GW)
    for ep in estate.endpoints:
        rl = ep.policy.rate_limit
        assert (rl.requests, rl.per) == (100, "minute")


def test_missing_openapi_raises_clear_error(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    (d / "policies.json").write_text("[]")
    with pytest.raises(ValueError, match="openapi.json"):
        load_mulesoft(str(d))


def test_missing_policies_json_raises_clear_error(tmp_path):
    d = tmp_path / "nospec"
    d.mkdir()
    (d / "openapi.json").write_text(json.dumps(SPEC))
    with pytest.raises(ValueError, match="policies.json"):
        load_mulesoft(str(d))


def test_missing_gateway_url_is_reported():
    estate = load_mulesoft(EXAMPLE)
    assert estate.base_url == "https://orders-impl.internal.example.com/api"
    assert any("no gateway URL" in n for n in estate.notes)


def test_gateway_url_sets_base_and_keeps_upstream():
    estate = load_mulesoft(EXAMPLE, GW)
    assert estate.base_url == GW
    assert estate.upstream_url == "https://orders-impl.internal.example.com/api"
