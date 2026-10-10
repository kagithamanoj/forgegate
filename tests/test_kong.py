"""Tests for the Kong decK exporter."""

import os

import pytest

from oxvara.exporters.kong import _route_path, load_deck
from oxvara.inputs import detect_source, load_input

DECK = os.path.join(os.path.dirname(__file__), "..", "examples", "kong", "kong.yaml")
GW = "https://kong.example.com"


def _by_id(estate):
    return {ep.operation_id: ep for ep in estate.endpoints}


def test_detects_deck_file():
    assert detect_source(DECK) == "kong"
    assert detect_source(DECK + "@" + GW) == "kong"


def test_routes_become_operations_and_terminated_route_is_skipped():
    estate = load_deck(DECK, GW)
    ops = _by_id(estate)
    assert set(ops) == {
        "list_orders_get", "create_order_post", "get_order_get",
        "refund_payment_post",
    }
    assert any("legacy-export" in n and "request-termination" in n for n in estate.notes)


def test_tools_call_the_kong_proxy_not_the_upstream():
    estate = load_deck(DECK, GW)
    assert estate.base_url == GW
    assert estate.upstream_url == "http://orders.internal:8080"
    assert estate.kind == "kong"


def test_missing_gateway_url_is_reported():
    estate = load_deck(DECK)
    assert estate.base_url == ""
    assert any("no gateway URL" in n for n in estate.notes)


def test_named_regex_capture_becomes_path_parameter():
    ops = _by_id(load_deck(DECK, GW))
    ep = ops["get_order_get"]
    assert ep.path == "/orders/{orderId}"
    assert [p.name for p in ep.parameters] == ["orderId"]


def test_service_key_auth_and_route_rate_limit_override():
    ops = _by_id(load_deck(DECK, GW))
    for op in ("list_orders_get", "create_order_post", "get_order_get"):
        auth = ops[op].policy.auth
        assert (auth.kind, auth.name, auth.location) == ("apiKey", "x-api-key", "header")
    # route-level rate-limiting replaces the service-level one, as in Kong
    rl = ops["list_orders_get"].policy.rate_limit
    assert (rl.requests, rl.per) == (120, "minute")
    rl = ops["create_order_post"].policy.rate_limit
    assert (rl.requests, rl.per) == (5, "second")


def test_top_level_service_scoped_plugins_apply():
    ep = _by_id(load_deck(DECK, GW))["refund_payment_post"]
    assert ep.policy.auth.kind == "oauth2"
    # of 100/60s and 2000/3600s, the lower sustained rate wins: 2000/hour
    rl = ep.policy.rate_limit
    assert (rl.requests, rl.per) == (2000, "hour")
    assert ep.path == "/payments/{paymentId}/refund"


def test_route_without_methods_exposes_get_only(tmp_path):
    deck = tmp_path / "k.yaml"
    deck.write_text(
        '_format_version: "3.0"\n'
        "services:\n"
        "  - name: s\n"
        "    url: http://s.internal\n"
        "    routes:\n"
        "      - name: any\n"
        "        paths: [/things]\n",
        encoding="utf-8",
    )
    estate = load_deck(str(deck), GW)
    assert [ep.method for ep in estate.endpoints] == ["GET"]
    assert any("every method" in n for n in estate.notes)


def test_disabled_and_consumer_plugins_are_ignored(tmp_path):
    deck = tmp_path / "k.yaml"
    deck.write_text(
        '_format_version: "3.0"\n'
        "services:\n"
        "  - name: s\n"
        "    url: http://s.internal\n"
        "    routes: [{name: r, paths: [/x], methods: [GET]}]\n"
        "plugins:\n"
        "  - {name: key-auth, enabled: false}\n"
        "  - {name: rate-limiting, consumer: bob, config: {minute: 5}}\n",
        encoding="utf-8",
    )
    estate = load_deck(str(deck), GW)
    ep = estate.endpoints[0]
    assert ep.policy.auth.kind == "none"
    assert ep.policy.rate_limit is None
    assert any("disabled" in n for n in estate.notes)
    assert any("consumer-scoped" in n for n in estate.notes)


def test_unmodelable_regex_route_is_skipped():
    assert _route_path("~/files/.*$") is None
    assert _route_path("/plain") == "/plain"


def test_not_a_deck_file_raises(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text("services: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a decK state file"):
        load_deck(str(f))


def test_load_input_tags_endpoint_source():
    estate = load_input(DECK + "@" + GW)
    assert {ep.source for ep in estate.endpoints} == {"kong:kong"}
    assert all(ep.base_url == GW for ep in estate.endpoints)
