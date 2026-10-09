"""Tests for the Apigee bundle exporter."""

import os

import pytest

from avouch.exporters.apigee import load_bundle

BUNDLE = os.path.join(
    os.path.dirname(__file__), "..", "examples", "apigee"
)


def test_bundle_loads_three_operations():
    estate = load_bundle(BUNDLE)
    assert estate.title == "petstore"
    assert estate.base_url == "https://petstore.example.com/api"
    assert len(estate.endpoints) == 3
    by_id = {ep.operation_id: ep for ep in estate.endpoints}
    assert by_id["list_pets"].method == "GET"
    assert by_id["list_pets"].path == "/pets"
    assert by_id["create_pet"].method == "POST"
    assert by_id["get_pet"].path == "/pets/{petId}"


def test_global_verify_api_key_applies_to_every_operation():
    estate = load_bundle(BUNDLE)
    for ep in estate.endpoints:
        auth = ep.policy.auth
        assert auth.kind == "apiKey"
        assert auth.name == "x-api-key"
        assert auth.location == "header"


def test_flow_quota_overrides_global_spike_arrest():
    estate = load_bundle(BUNDLE)
    by_id = {ep.operation_id: ep for ep in estate.endpoints}
    quota = by_id["list_pets"].policy.rate_limit
    assert quota is not None
    assert (quota.requests, quota.per) == (200, "minute")
    # Operations without a flow-level Quota keep the global SpikeArrest.
    for op_id in ("create_pet", "get_pet"):
        spike = by_id[op_id].policy.rate_limit
        assert spike is not None
        assert (spike.requests, spike.per) == (10, "second")


def test_path_template_parameters_are_extracted():
    estate = load_bundle(BUNDLE)
    by_id = {ep.operation_id: ep for ep in estate.endpoints}
    params = by_id["get_pet"].parameters
    assert len(params) == 1
    assert params[0].name == "petId"
    assert params[0].location == "path"
    assert params[0].required is True


def test_tool_names_are_namespaced():
    estate = load_bundle(BUNDLE)
    names = {ep.tool_name for ep in estate.endpoints}
    assert names == {
        "petstore_list_pets",
        "petstore_create_pet",
        "petstore_get_pet",
    }


def test_non_bundle_directory_raises(tmp_path):
    with pytest.raises(ValueError, match="does not look like an Apigee bundle"):
        load_bundle(str(tmp_path))


def test_quota_with_only_count_ref_contributes_no_limit(tmp_path):
    import xml.etree.ElementTree as ET

    from avouch.exporters.apigee import _parse_quota

    policy = ET.fromstring(
        '<Quota name="q"><Allow countRef="verifyapikey.key.quota"/>'
        "<Interval>1</Interval><TimeUnit>minute</TimeUnit></Quota>"
    )
    assert _parse_quota(policy) is None


def test_spike_arrest_rate_forms():
    import xml.etree.ElementTree as ET

    from avouch.exporters.apigee import _parse_spike_arrest

    ten_per_second = ET.fromstring(
        '<SpikeArrest name="s"><Rate>10ps</Rate></SpikeArrest>'
    )
    per_minute = ET.fromstring(
        '<SpikeArrest name="s"><Rate>100pm</Rate></SpikeArrest>'
    )
    assert (_parse_spike_arrest(ten_per_second).requests,
            _parse_spike_arrest(ten_per_second).per) == (10, "second")
    assert (_parse_spike_arrest(per_minute).requests,
            _parse_spike_arrest(per_minute).per) == (100, "minute")
    bad = ET.fromstring('<SpikeArrest name="s"><Rate>fast</Rate></SpikeArrest>')
    assert _parse_spike_arrest(bad) is None
