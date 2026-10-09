"""Tests for the Azure APIM exporter."""

import os
import textwrap
import xml.etree.ElementTree as ET

import pytest

from oxvara.exporters.apim import _inbound_policy, load_apim

APIM = os.path.join(
    os.path.dirname(__file__), "..", "examples", "apim"
)


def test_apim_loads_three_operations():
    estate = load_apim(APIM)
    assert estate.title == "Petstore"
    assert estate.base_url == "https://petstore-apim.azure-api.net/petstore"
    assert len(estate.endpoints) == 3
    by_id = {ep.operation_id: ep for ep in estate.endpoints}
    assert by_id["listPets"].method == "GET"
    assert by_id["createPet"].method == "POST"
    assert by_id["getPet"].path == "/pets/{petId}"


def test_api_level_policy_applies_to_every_operation():
    estate = load_apim(APIM)
    for ep in estate.endpoints:
        auth = ep.policy.auth
        assert auth.kind == "apiKey"
        assert auth.name == "Ocp-Apim-Subscription-Key"
        assert auth.location == "header"


def test_api_level_rate_limit_is_inherited():
    estate = load_apim(APIM)
    by_id = {ep.operation_id: ep for ep in estate.endpoints}
    for op_id in ("listPets", "getPet"):
        limit = by_id[op_id].policy.rate_limit
        assert limit is not None
        assert (limit.requests, limit.per) == (200, "minute")


def test_operation_quota_overrides_when_tighter():
    estate = load_apim(APIM)
    by_id = {ep.operation_id: ep for ep in estate.endpoints}
    limit = by_id["createPet"].policy.rate_limit
    assert limit is not None
    # 5000/hour is tighter than the API-level 200/minute (12000/hour).
    assert (limit.requests, limit.per) == (5000, "hour")


def test_missing_openapi_raises(tmp_path):
    with pytest.raises(ValueError, match="does not look like an APIM export"):
        load_apim(str(tmp_path))


def _policy_file(tmp_path, body):
    path = tmp_path / "policy.xml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(path)


def test_validate_jwt_maps_to_oauth2(tmp_path):
    path = _policy_file(
        tmp_path,
        """<policies><inbound><base />
        <validate-jwt header-name="Authorization">
            <openid-config url="https://login.example.com/.well-known/openid-configuration" />
        </validate-jwt>
        </inbound></policies>""",
    )
    assert _inbound_policy(path).auth.kind == "oauth2"


def test_authentication_basic_maps_to_basic(tmp_path):
    path = _policy_file(
        tmp_path,
        """<policies><inbound><base />
        <authentication-basic username="svc" password="secret" />
        </inbound></policies>""",
    )
    assert _inbound_policy(path).auth.kind == "basic"


def test_quota_normalizes_to_closest_window(tmp_path):
    path = _policy_file(
        tmp_path,
        """<policies><inbound><base />
        <quota calls="10" renewal-period="3600" />
        </inbound></policies>""",
    )
    limit = _inbound_policy(path).rate_limit
    assert (limit.requests, limit.per) == (10, "hour")


def test_tighter_of_quota_and_rate_limit_wins(tmp_path):
    path = _policy_file(
        tmp_path,
        """<policies><inbound><base />
        <rate-limit calls="100" renewal-period="60" />
        <quota calls="10" renewal-period="60" />
        </inbound></policies>""",
    )
    limit = _inbound_policy(path).rate_limit
    assert (limit.requests, limit.per) == (10, "minute")


def test_policy_without_inbound_is_empty(tmp_path):
    path = _policy_file(
        tmp_path, "<policies><backend><base /></backend></policies>"
    )
    policy = _inbound_policy(path)
    assert policy.auth.kind == "none"
    assert policy.rate_limit is None


def test_broken_policy_file_is_empty_policy(tmp_path):
    path = tmp_path / "policy.xml"
    path.write_text("<policies><inbound>", encoding="utf-8")
    policy = _inbound_policy(str(path))
    assert policy.auth.kind == "none"
    assert policy.rate_limit is None
