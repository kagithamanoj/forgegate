"""End to end: compile the example spec, import the server, call tools.

The generated server's HTTP layer is stubbed by monkeypatching
requests.request, so this test exercises parsing, code generation,
module import, auth injection, path substitution, and the client-side
rate limiter without any network access.
"""

import importlib.util
import os

import pytest

from oxvara.codegen import write_server
from oxvara.parser import load_spec_file

EXAMPLE = os.path.join(
    os.path.dirname(__file__), "..", "examples", "petstore.yaml"
)


class FakeResponse:
    def __init__(self, text="[]"):
        self.text = text

    def raise_for_status(self):
        return None


@pytest.fixture()
def server_module(tmp_path, monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        return FakeResponse()

    import requests

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setenv("OXVARA_API_KEY", "test-key-123")

    estate = load_spec_file(EXAMPLE)
    out = str(tmp_path / "petserver.py")
    write_server(estate, out)

    spec = importlib.util.spec_from_file_location("petserver", out)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._calls = calls
    return module


def test_list_pets_builds_correct_request(server_module):
    server_module.petstore_list_pets(limit=5)
    call = server_module._calls[-1]
    assert call["method"] == "GET"
    assert call["url"] == "https://petstore.example.com/api/v1/pets"
    assert call["params"] == {"limit": 5}
    assert call["headers"]["X-API-Key"] == "test-key-123"


def test_optional_params_are_omitted_when_not_given(server_module):
    server_module.petstore_list_pets()
    call = server_module._calls[-1]
    assert call["params"] == {}


def test_path_parameter_is_substituted(server_module):
    server_module.petstore_get_pet(petId="abc-123")
    call = server_module._calls[-1]
    assert call["url"] == "https://petstore.example.com/api/v1/pets/abc-123"


def test_body_is_sent_as_json(server_module):
    server_module.petstore_create_pet(name="Fido", tag="dog")
    call = server_module._calls[-1]
    assert call["method"] == "POST"
    assert call["json"] == {"name": "Fido", "tag": "dog"}


def test_rate_limiter_blocks_after_budget_exhausted(server_module):
    # createPet inherits a 10/minute budget; hammer it until it trips.
    for _ in range(10):
        server_module.petstore_create_pet(name="Fido")
    with pytest.raises(server_module.RateLimitExceeded):
        server_module.petstore_create_pet(name="Fido")


def test_all_three_tools_are_registered(server_module):
    tools = server_module.mcp._tool_manager.list_tools()
    assert {t.name for t in tools} == {
        "petstore_list_pets",
        "petstore_create_pet",
        "petstore_get_pet",
    }
