"""Tests for the OpenAPI parser and x-oxvara policy inheritance."""

import os

import pytest

from oxvara.parser import load_spec_file, parse_spec

EXAMPLE = os.path.join(
    os.path.dirname(__file__), "..", "examples", "petstore.yaml"
)


def test_example_parses_to_three_endpoints():
    estate = load_spec_file(EXAMPLE)
    assert estate.title == "Petstore"
    assert estate.slug == "petstore"
    assert estate.base_url == "https://petstore.example.com/api/v1"
    assert len(estate.endpoints) == 3


def test_tool_names_are_sanitized():
    estate = load_spec_file(EXAMPLE)
    names = {ep.operation_id: ep.tool_name for ep in estate.endpoints}
    assert names == {
        "listPets": "petstore_list_pets",
        "createPet": "petstore_create_pet",
        "getPet": "petstore_get_pet",
    }


def test_auth_policy_is_inherited():
    estate = load_spec_file(EXAMPLE)
    for ep in estate.endpoints:
        assert ep.policy.auth.kind == "apiKey"
        assert ep.policy.auth.name == "X-API-Key"
        assert ep.policy.auth.location == "header"


def test_rate_limit_override_applies_only_to_that_operation():
    estate = load_spec_file(EXAMPLE)
    by_op = {ep.operation_id: ep for ep in estate.endpoints}
    assert by_op["createPet"].policy.rate_limit.requests == 10
    assert by_op["listPets"].policy.rate_limit.requests == 100
    assert by_op["getPet"].policy.rate_limit.requests == 100


def test_path_and_query_parameters():
    estate = load_spec_file(EXAMPLE)
    by_op = {ep.operation_id: ep for ep in estate.endpoints}
    get_pet = by_op["getPet"]
    assert get_pet.method == "GET"
    assert get_pet.path == "/pets/{petId}"
    pet_id = [p for p in get_pet.parameters if p.name == "petId"][0]
    assert pet_id.location == "path"
    assert pet_id.required is True

    list_pets = by_op["listPets"]
    limit = [p for p in list_pets.parameters if p.name == "limit"][0]
    assert limit.location == "query"
    assert limit.schema_type == "integer"
    assert limit.required is False


def test_body_properties_are_flattened():
    estate = load_spec_file(EXAMPLE)
    by_op = {ep.operation_id: ep for ep in estate.endpoints}
    props = {b.name: b for b in by_op["createPet"].body_properties}
    assert props["name"].required is True
    assert props["tag"].required is False
    assert props["name"].schema_type == "string"


def test_non_openapi_3_spec_is_rejected():
    with pytest.raises(ValueError, match="OpenAPI 3"):
        parse_spec('openapi: "2.0"\ninfo:\n  title: old\npaths: {}')


def test_empty_spec_is_rejected():
    with pytest.raises(ValueError, match="no operations"):
        parse_spec('openapi: "3.0.0"\ninfo:\n  title: empty\npaths: {}')
