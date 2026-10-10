"""Tests for SigV4 signing in generated servers (Issue #5)."""

import os
import urllib as urllib_mod

import pytest

from oxvara import codegen
from oxvara.exporters.aws import _scheme_auth
from oxvara.models import AUTH_STRENGTH, ApiEstate, AuthPolicy, Endpoint, Policy


def _sigv4_fn():
    """Extract _sigv4_headers from the codegen RUNTIME template."""
    src = codegen.RUNTIME
    start = src.index("def _sigv4_headers")
    lines = src[start:].split("\n")
    end = len(lines)
    for i, line in enumerate(lines[1:], 1):
        if line.startswith("def "):
            end = i
            break
    ns = {"os": os, "urllib": urllib_mod}
    exec(  # noqa: S102 - testing the generated server's embedded function
        "class OxvaraError(Exception): pass\n" + "\n".join(lines[:end]), ns
    )
    return ns["_sigv4_headers"]


def _estate_with_sigv4():
    ep = Endpoint(
        operation_id="createItem",
        tool_name="create_item",
        method="POST",
        path="/items",
        summary="Create an item",
        description="",
        policy=Policy(auth=AuthPolicy(kind="sigv4")),
    )
    return ApiEstate(
        title="Items", slug="items", version="1",
        base_url="https://z9y8x7w6v5.execute-api.us-east-1.amazonaws.com",
        endpoints=[ep], kind="aws",
    )


def test_v1_importer_models_sigv4():
    notes = []
    auth = _scheme_auth("iam", {"x-amazon-apigateway-authtype": "awsSigv4"}, notes)
    assert auth.kind == "sigv4"
    assert notes == []  # the "not modeled" note is gone


def test_sigv4_strength_matches_oauth2():
    assert AUTH_STRENGTH["sigv4"] == 3


def test_generated_server_signs_sigv4():
    src = codegen.generate_server(_estate_with_sigv4())
    assert "_sigv4_headers" in src
    assert "_ox_headers.update(_sigv4_headers('POST', _ox_url," in src
    assert "_auth_headers('sigv4'" not in src


def test_sigv4_runtime_uses_env_credentials():
    assert "AWS_ACCESS_KEY_ID" in codegen.RUNTIME
    assert "AWS_SECRET_ACCESS_KEY" in codegen.RUNTIME
    assert "AWS_SESSION_TOKEN" in codegen.RUNTIME
    assert "AWS_REGION" in codegen.RUNTIME


def test_sigv4_header_structure(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY",
                       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    sign = _sigv4_fn()
    headers = sign(
        "GET",
        "https://z9y8x7w6v5.execute-api.us-east-1.amazonaws.com/items",
        {"q": "x"}, b"",
    )
    auth = headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
    assert "/us-east-1/execute-api/aws4_request" in auth
    assert "SignedHeaders=host;x-amz-date" in auth
    sig = auth.split("Signature=")[1]
    assert len(sig) == 64 and all(c in "0123456789abcdef" for c in sig)
    assert headers["x-amz-date"].endswith("Z")


def test_sigv4_requires_credentials(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    sign = _sigv4_fn()
    with pytest.raises(Exception, match="AWS_ACCESS_KEY_ID"):
        sign("GET", "https://x.execute-api.us-east-1.amazonaws.com/", {}, b"")


def test_sigv4_region_from_hostname(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    sign = _sigv4_fn()
    headers = sign(
        "GET", "https://abc.execute-api.eu-west-1.amazonaws.com/items", {}, b"")
    assert "/eu-west-1/execute-api/aws4_request" in headers["Authorization"]


def test_sigv4_session_token_header(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "session123")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    sign = _sigv4_fn()
    headers = sign("GET", "https://x.execute-api.us-east-1.amazonaws.com/", {}, b"")
    assert headers["x-amz-security-token"] == "session123"
    assert "x-amz-security-token" in headers["Authorization"].split("SignedHeaders=")[1]
