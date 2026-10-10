"""Tests for policy packs and the validate command."""

import os

import pytest

from oxvara.cli import build_parser
from oxvara.models import (
    ApiEstate,
    AuthPolicy,
    Endpoint,
    Policy,
    RateLimit,
)
from oxvara.packs import run_pack, strict_pack

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def _estate() -> ApiEstate:
    estate = ApiEstate(
        title="T", slug="t", version="1", base_url="https://x.example"
    )
    estate.endpoints.append(
        Endpoint(
            operation_id="good",
            tool_name="t_good",
            method="GET",
            path="/good",
            summary="",
            description="",
            policy=Policy(
                auth=AuthPolicy(kind="apiKey", name="X-Key"),
                rate_limit=RateLimit(requests=100, per="minute"),
            ),
        )
    )
    return estate


def test_strict_pack_passes_clean_estate():
    assert strict_pack(_estate()) == []


def test_strict_pack_flags_missing_auth():
    estate = _estate()
    estate.endpoints[0].policy.auth = AuthPolicy(kind="none")
    violations = strict_pack(estate)
    assert any(v.rule == "require-auth" for v in violations)


def test_strict_pack_flags_missing_rate_limit():
    estate = _estate()
    estate.endpoints[0].policy.rate_limit = None
    violations = strict_pack(estate)
    assert any(v.rule == "require-rate-limit" for v in violations)


def test_strict_pack_caps_generous_limits():
    estate = _estate()
    estate.endpoints[0].policy.rate_limit = RateLimit(
        requests=5000, per="minute"
    )
    violations = strict_pack(estate)
    assert any(v.rule == "cap-rate-limit" for v in violations)


def test_strict_pack_flags_missing_base_url():
    estate = _estate()
    estate.base_url = ""
    violations = strict_pack(estate)
    assert any(v.rule == "base-url" for v in violations)


def test_run_pack_rejects_unknown_pack():
    with pytest.raises(ValueError, match="unknown policy pack"):
        run_pack(_estate(), "nonexistent")


def test_validate_command_passes_on_apigee_example(capsys):
    args = build_parser().parse_args(
        ["validate", os.path.join(EXAMPLES, "apigee") + "@https://apigee.example.com"]
    )
    assert args.func(args) == 0
    assert "no violations" in capsys.readouterr().out


def test_validate_fails_apigee_without_gateway_url(capsys):
    args = build_parser().parse_args(["validate", os.path.join(EXAMPLES, "apigee")])
    assert args.func(args) == 1
    assert "base-url" in capsys.readouterr().out


def test_owasp_pack_rules():
    from oxvara.packs import owasp_mcp_pack

    estate = _estate()
    estate.base_url = "http://backend.internal"
    estate.upstream_url = "http://backend.internal"
    estate.endpoints[0].policy.auth = AuthPolicy(kind="apiKey", name="k", location="query")
    estate.endpoints.append(Endpoint(
        operation_id="wipe", tool_name="t_wipe", method="DELETE", path="/all",
        summary="", description="", policy=Policy(auth=AuthPolicy(kind="basic")),
    ))
    estate.endpoints.append(Endpoint(
        operation_id="open", tool_name="t_open", method="POST", path="/x",
        summary="", description="",
    ))
    rules = {v.rule for v in owasp_mcp_pack(estate)}
    assert rules == {
        "MCP01-no-query-credentials",
        "MCP01-require-tls",
        "MCP02-scoped-auth-on-destructive",
        "MCP07-auth-on-writes",
        "MCP07-gateway-bypass",
    }


def test_validate_runs_several_packs_with_sarif(capsys):
    import json

    kong = os.path.join(EXAMPLES, "kong", "kong.yaml") + "@https://kong.example.com"
    args = build_parser().parse_args(
        ["validate", kong, "--pack", "strict", "--pack", "owasp-mcp", "--format", "sarif"]
    )
    assert args.func(args) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["runs"][0]["results"] == []


def test_validate_command_fails_on_bare_spec(capsys, tmp_path):
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
    args = build_parser().parse_args(["validate", str(spec)])
    assert args.func(args) == 1
    out = capsys.readouterr().out
    assert "require-auth" in out
    assert "require-rate-limit" in out


def test_validate_rejects_unknown_pack(capsys):
    args = build_parser().parse_args(
        ["validate", "--pack", "nope",
         os.path.join(EXAMPLES, "petstore.yaml")]
    )
    with pytest.raises(ValueError, match="unknown policy pack"):
        args.func(args)
    # main() converts it to exit code 1
    from oxvara.cli import main

    assert main(["validate", "--pack", "nope",
                 os.path.join(EXAMPLES, "petstore.yaml")]) == 1
