"""Tests for input detection and the diff command."""

import os

from oxvara.cli import build_parser
from oxvara.inputs import detect_source, load_input

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def test_detect_source():
    assert detect_source(os.path.join(EXAMPLES, "apigee")) == "apigee"
    assert detect_source(os.path.join(EXAMPLES, "apim")) == "apim"
    assert detect_source(os.path.join(EXAMPLES, "petstore.yaml")) == "openapi"
    assert detect_source(os.path.join(EXAMPLES, "kong", "kong.yaml")) == "kong"


def test_gateway_url_suffix_overrides_openapi_base():
    estate = load_input(
        os.path.join(EXAMPLES, "petstore.yaml") + "@https://gw.example.com/pets/"
    )
    assert estate.base_url == "https://gw.example.com/pets"


def test_load_input_apigee():
    estate = load_input(os.path.join(EXAMPLES, "apigee"))
    assert estate.title == "petstore"
    assert len(estate.endpoints) == 3


def test_load_input_apim():
    estate = load_input(os.path.join(EXAMPLES, "apim"))
    assert estate.title == "Petstore"
    assert len(estate.endpoints) == 3


def test_load_input_openapi():
    estate = load_input(os.path.join(EXAMPLES, "petstore.yaml"))
    assert len(estate.endpoints) == 3


def test_diff_prints_plan_and_writes_nothing(capsys, tmp_path):
    spec = os.path.join(EXAMPLES, "petstore.yaml")
    out_file = str(tmp_path / "should_not_exist.py")
    args = build_parser().parse_args(["diff", spec])
    assert args.func(args) == 0
    captured = capsys.readouterr()
    assert "Nothing will be written" in captured.out
    assert "petstore_list_pets" in captured.out
    assert "auth:" in captured.out
    assert "rate:" in captured.out
    assert not os.path.exists(out_file)


def test_diff_warns_about_missing_governance(capsys, tmp_path):
    spec = tmp_path / "bare.yaml"
    spec.write_text(
        "openapi: 3.0.0\n"
        "info: {title: Bare, version: '1'}\n"
        "paths:\n"
        "  /things:\n"
        "    get:\n"
        "      operationId: listThings\n"
        "      responses: {'200': {description: ok}}\n",
        encoding="utf-8",
    )
    args = build_parser().parse_args(["diff", str(spec)])
    assert args.func(args) == 0
    out = capsys.readouterr().out
    assert "Warnings:" in out
    assert "has no auth configured" in out
    assert "has no rate limit configured" in out
    assert "base URL is not set" in out


def test_diff_flags_oauth2_as_unimplemented(capsys, tmp_path):
    spec = tmp_path / "oauth.yaml"
    spec.write_text(
        "openapi: 3.0.0\n"
        "info: {title: OAuthed, version: '1'}\n"
        "x-oxvara:\n"
        "  baseUrl: https://api.example.com\n"
        "  auth: {kind: oauth2}\n"
        "paths:\n"
        "  /things:\n"
        "    get:\n"
        "      operationId: listThings\n"
        "      responses: {'200': {description: ok}}\n",
        encoding="utf-8",
    )
    args = build_parser().parse_args(["diff", str(spec)])
    assert args.func(args) == 0
    out = capsys.readouterr().out
    assert "oauth2" in out
    assert "OXVARA_OAUTH_TOKEN_URL" in out
