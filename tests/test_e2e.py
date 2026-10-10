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
        self.status_code = 200

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


def test_path_value_cannot_traverse(server_module):
    server_module.petstore_get_pet(petId="../admin?x=1")
    url = server_module._calls[-1]["url"]
    assert url.endswith("/pets/..%2Fadmin%3Fx%3D1")


def test_response_is_labeled_untrusted_and_capped(server_module, monkeypatch):
    import requests

    big = "x" * 50000
    monkeypatch.setattr(requests, "request", lambda *a, **k: FakeResponse(big))
    out = server_module.petstore_list_pets()
    assert out.startswith("[oxvara: untrusted API response")
    assert "response truncated" in out
    assert len(out) < 21000


def test_audit_log_redacts_secrets(server_module, tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("OXVARA_AUDIT_LOG", str(log))
    server_module._audit("call", "t", args=server_module._redact({"api_key": "s3", "q": "ok"}))
    text = log.read_text()
    assert "s3" not in text and '"q": "ok"' in text


def test_oauth2_client_credentials_cached(server_module, monkeypatch):
    import requests

    posts = []

    class Tok:
        def raise_for_status(self):
            pass

        def json(self):
            return {"access_token": "tok-1", "expires_in": 3600}

    def fake_post(url, **kw):
        posts.append((url, kw))
        return Tok()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.delenv("OXVARA_OAUTH_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("OXVARA_OAUTH_SUBJECT_TOKEN", raising=False)
    monkeypatch.setenv("OXVARA_OAUTH_TOKEN_URL", "https://idp.test/token")
    monkeypatch.setenv("OXVARA_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("OXVARA_OAUTH_CLIENT_SECRET", "sec")
    assert server_module._auth_headers("oauth2", "", "") == {"Authorization": "Bearer tok-1"}
    server_module._auth_headers("oauth2", "", "")
    assert len(posts) == 1
    assert posts[0][1]["data"]["grant_type"] == "client_credentials"


def test_oauth2_pre_issued_token_wins(server_module, monkeypatch):
    monkeypatch.setenv("OXVARA_OAUTH_ACCESS_TOKEN", "upstream-tok")
    assert server_module._auth_headers("oauth2", "", "") == {
        "Authorization": "Bearer upstream-tok"
    }


def test_oauth2_token_exchange_carries_user_identity(server_module, monkeypatch):
    import requests

    posts = []

    class Tok:
        def raise_for_status(self):
            pass

        def json(self):
            return {"access_token": "exchanged", "expires_in": 600}

    monkeypatch.setattr(requests, "post", lambda url, **kw: posts.append(kw) or Tok())
    monkeypatch.delenv("OXVARA_OAUTH_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("OXVARA_OAUTH_TOKEN_URL", "https://idp.test/token")
    monkeypatch.setenv("OXVARA_OAUTH_CLIENT_ID", "oxvara")
    monkeypatch.setenv("OXVARA_OAUTH_CLIENT_SECRET", "sec")
    monkeypatch.setenv("OXVARA_OAUTH_SUBJECT_TOKEN", "alice-token")
    monkeypatch.setenv("OXVARA_OAUTH_AUDIENCE", "https://orders.example.com")
    assert server_module._auth_headers("oauth2", "", "") == {
        "Authorization": "Bearer exchanged"
    }
    data = posts[0]["data"]
    assert data["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert data["subject_token"] == "alice-token"
    assert data["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert data["audience"] == "https://orders.example.com"
    # cached per subject: a second call does not hit the IdP again
    server_module._auth_headers("oauth2", "", "")
    assert len(posts) == 1


def test_audit_records_subject(server_module, tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("OXVARA_AUDIT_LOG", str(log))
    monkeypatch.setenv("OXVARA_AUDIT_SUBJECT", "alice@example.com")
    server_module.petstore_list_pets()
    records = [__import__("json").loads(line) for line in log.read_text().splitlines()]
    assert [r["event"] for r in records] == ["call", "response"]
    assert all(r["subject"] == "alice@example.com" for r in records)


def test_oauth2_unconfigured_fails_loudly(server_module, monkeypatch):
    for v in ("ACCESS_TOKEN", "SUBJECT_TOKEN", "TOKEN_URL", "CLIENT_ID", "CLIENT_SECRET"):
        monkeypatch.delenv("OXVARA_OAUTH_" + v, raising=False)
    server_module._oauth_cache.clear()
    with pytest.raises(server_module.OxvaraError):
        server_module._auth_headers("oauth2", "", "")
