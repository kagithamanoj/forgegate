"""Tests for the API Gateway HTTP API (v2) importer and SigV4 auth."""

import os
import shutil

from oxvara.exporters.aws_v2 import (
    _route_key,
    is_aws_v2_export,
    load_aws_v2,
)
from oxvara.inputs import detect_source, load_inputs

EXPORT = os.path.join(os.path.dirname(__file__), "..", "examples", "aws", "http-api")
INVOKE = "https://z9y8x7w6v5.execute-api.us-east-1.amazonaws.com"


def _ops(estate):
    return {ep.operation_id: ep for ep in estate.endpoints}


def test_detected_as_aws():
    assert detect_source(EXPORT) == "aws"


def test_v2_markers_win_over_v1_detection():
    from oxvara.exporters.aws import is_aws_export
    # The sample carries x-amazon-apigateway markers, so the v1 check
    # also fires; the v2 check must run first in detect_source.
    assert is_aws_v2_export(EXPORT)
    assert is_aws_export(EXPORT)


def test_not_v2_for_plain_openapi(tmp_path):
    d = tmp_path / "api"
    d.mkdir()
    (d / "openapi.json").write_text('{"openapi": "3.0.1", "paths": {}}')
    assert not is_aws_v2_export(str(d))


def test_base_url_from_servers():
    estate = load_aws_v2(EXPORT)
    assert estate.kind == "aws"
    assert estate.base_url == INVOKE


def test_gateway_url_override():
    estate = load_aws_v2(EXPORT, "https://api.example.com/items/")
    assert estate.base_url == "https://api.example.com/items"


def test_jwt_maps_to_oauth2():
    ops = _ops(load_aws_v2(EXPORT))
    assert ops["listItems"].policy.auth.kind == "oauth2"


def test_lambda_authorizer_maps_to_bearer():
    ops = _ops(load_aws_v2(EXPORT))
    assert ops["getItem"].policy.auth.kind == "bearer"


def test_iam_maps_to_sigv4():
    ops = _ops(load_aws_v2(EXPORT))
    assert ops["createItem"].policy.auth.kind == "sigv4"


def test_no_security_means_no_auth():
    ops = _ops(load_aws_v2(EXPORT))
    assert ops["deleteItem"].policy.auth.kind == "none"


def test_route_throttling_default_and_override():
    ops = _ops(load_aws_v2(EXPORT))
    default = ops["listItems"].policy.rate_limit
    assert (default.requests, default.per) == (100, "second")
    tight = ops["deleteItem"].policy.rate_limit
    assert (tight.requests, tight.per) == (5, "second")


def test_route_key_normalization():
    assert _route_key("GET /pets") == "/pets|GET"
    assert _route_key("DELETE /items/{itemId}") == "/items/{itemId}|DELETE"
    assert _route_key("GET /") == "/|GET"


def test_missing_stage_warns_but_loads(tmp_path):
    target = tmp_path / "api"
    shutil.copytree(EXPORT, target)
    os.remove(target / "stage.json")
    estate = load_aws_v2(str(target))
    assert any("stage.json" in n for n in estate.notes)
    assert len(estate.endpoints) == 4


def test_end_to_end_inventory(tmp_path):
    target = tmp_path / "api"
    shutil.copytree(EXPORT, target)
    merged, _ = load_inputs([str(target)])
    assert merged.kind == "aws"
    assert len(merged.endpoints) == 4


def test_v1_rest_api_still_detected_as_v1():
    rest = os.path.join(os.path.dirname(__file__), "..", "examples", "aws", "orders-api")
    assert not is_aws_v2_export(rest)
    assert detect_source(rest) == "aws"

