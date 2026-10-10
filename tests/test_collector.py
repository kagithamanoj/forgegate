"""Tests for oxvara.collector (live AWS collection), all with mocked boto3."""

import io
import json
from unittest import mock

import pytest

from oxvara import collector


def _streaming_body(text: str):
    return io.BytesIO(text.encode("utf-8"))


def _make_clients(apis=None, stages=None, export_text=None, plans=None,
                  fail_export=False, throttle_export=0):
    """Build mock sts + apigateway clients with canned responses."""
    apis = apis if apis is not None else [{"id": "abc123", "name": "orders"}]
    stages = stages if stages is not None else [{"stageName": "prod"}]
    plans = plans if plans is not None else {"items": []}
    export_text = export_text if export_text is not None else json.dumps(
        {"openapi": "3.0.1", "info": {"title": "t", "version": "1"},
         "paths": {}}
    )

    sts = mock.Mock()
    sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST",
    }}

    gw = mock.Mock()
    gw.get_rest_apis.return_value = {"items": apis}
    gw.get_stages.return_value = {"items": stages}
    gw.get_stage.return_value = {"stageName": "prod", "methodSettings": {}}
    gw.get_usage_plans.return_value = plans

    calls = {"export": 0}

    def fake_export(**kwargs):
        calls["export"] += 1
        if fail_export:
            raise Exception("AccessDenied")  # noqa: TRY002 - simulating AWS error
        if calls["export"] <= throttle_export:
            err = mock.Mock()
            err.response = {"Error": {"Code": "TooManyRequestsException"}}
            # botocore ClientError needs the real class; emulate via type
            raise _client_error()
        return {"body": _streaming_body(export_text)}

    gw.get_export.side_effect = fake_export
    return sts, gw, calls


def _client_error():
    # Minimal stand-in shaped like botocore.exceptions.ClientError
    class FakeClientError(Exception):
        def __init__(self):
            self.response = {"Error": {"Code": "TooManyRequestsException"}}
    return FakeClientError()


def _boto3_module(sts, gw):
    mod = mock.Mock()
    def client(service, **kwargs):
        return sts if service == "sts" else gw
    mod.client.side_effect = client
    return mod


def test_assume_role_called_with_account_and_role(tmp_path):
    sts, gw, _ = _make_clients()
    mod = _boto3_module(sts, gw)
    notes = []
    collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    sts.assume_role.assert_called_once()
    kwargs = sts.assume_role.call_args.kwargs
    assert kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/OxvaraCollector"
    assert kwargs["RoleSessionName"] == "oxvara-collector"


def test_writes_aws_importer_layout(tmp_path):
    sts, gw, _ = _make_clients()
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 1
    dest = tmp_path / "123456789012" / "us-east-1" / "abc123" / "prod"
    assert (dest / "openapi.json").is_file()
    assert (dest / "stage.json").is_file()
    assert (dest / "usage-plans.json").is_file()
    # the existing AWS importer must accept what the collector wrote
    from oxvara.exporters.aws import is_aws_export
    assert is_aws_export(str(dest))


def test_iterates_accounts_and_regions(tmp_path, monkeypatch):
    sts, gw, _ = _make_clients()
    mod = _boto3_module(sts, gw)
    monkeypatch.setattr(collector, "boto3", mod)
    result = collector.collect_aws(
        ["111111111111", "222222222222"], ["us-east-1", "eu-west-1"],
        "OxvaraCollector", str(tmp_path),
    )
    assert result["stages"] == 4
    assert sts.assume_role.call_count == 4


def test_export_failure_becomes_note_not_silent(tmp_path):
    sts, gw, _ = _make_clients(fail_export=True)
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 0
    assert any("get_export" in note and "AccessDenied" in note for note in notes)


def test_throttling_retries_then_succeeds(tmp_path):
    sts, gw, calls = _make_clients(throttle_export=2)
    mod = _boto3_module(sts, gw)
    notes = []
    with mock.patch.object(collector.time, "sleep", return_value=None):
        n = collector.collect_account_region(
            mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
            str(tmp_path), notes,
        )
    assert n == 1
    assert calls["export"] == 3  # 2 throttled + 1 success


def test_throttling_gives_up_after_max_attempts(tmp_path):
    sts, gw, calls = _make_clients(throttle_export=99)
    mod = _boto3_module(sts, gw)
    notes = []
    with mock.patch.object(collector.time, "sleep", return_value=None):
        n = collector.collect_account_region(
            mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
            str(tmp_path), notes,
        )
    assert n == 0
    assert calls["export"] == collector._MAX_ATTEMPTS
    assert any("throttled after" in note for note in notes)


def test_empty_account_is_noted(tmp_path):
    sts, gw, _ = _make_clients(apis=[])
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 0
    # no APIs means nothing written and no crash; no failure note needed


def test_api_without_stages_is_noted(tmp_path):
    sts, gw, _ = _make_clients(stages=[])
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 0
    assert any("no stages found" in note for note in notes)


def test_invalid_export_json_becomes_note(tmp_path):
    sts, gw, _ = _make_clients(export_text="not json at all")
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 0
    assert any("not valid JSON" in note for note in notes)


def test_assume_role_failure_is_noted(tmp_path):
    sts, gw, _ = _make_clients()
    sts.assume_role.side_effect = Exception("AccessDenied: not authorized")
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "999999999999", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 0
    assert any("assume_role" in note for note in notes)


def test_empty_accounts_and_regions(tmp_path, monkeypatch):
    mod = mock.Mock()
    monkeypatch.setattr(collector, "boto3", mod)
    result = collector.collect_aws([], ["us-east-1"], "R", str(tmp_path))
    assert result["stages"] == 0
    assert any("no accounts" in note for note in result["notes"])
    result = collector.collect_aws(["123456789012"], [], "R", str(tmp_path))
    assert result["stages"] == 0
    assert any("no regions" in note for note in result["notes"])


def test_missing_boto3_raises_helpful_error(monkeypatch):
    monkeypatch.setattr(collector, "boto3", None)
    with pytest.raises(ImportError, match='pip install "oxvara\\[aws\\]"'):
        collector.collect_aws(["123456789012"], ["us-east-1"], "R", "/tmp/x")


def test_usage_plans_written(tmp_path):
    plans = {"items": [{"id": "p1", "name": "gold",
                        "throttle": {"rateLimit": 10.0},
                        "apiStages": [{"apiId": "abc123", "stage": "prod"}]}]}
    sts, gw, _ = _make_clients(plans=plans)
    mod = _boto3_module(sts, gw)
    notes = []
    collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    dest = tmp_path / "123456789012" / "us-east-1" / "abc123" / "prod"
    written = json.loads((dest / "usage-plans.json").read_text())
    assert written["items"][0]["name"] == "gold"


def test_pagination_collects_all_pages(tmp_path):
    sts, gw, _ = _make_clients()
    gw.get_rest_apis.side_effect = [
        {"items": [{"id": "a1"}], "position": "tok"},
        {"items": [{"id": "a2"}]},
    ]
    mod = _boto3_module(sts, gw)
    notes = []
    n = collector.collect_account_region(
        mod, sts, "123456789012", "us-east-1", "OxvaraCollector",
        str(tmp_path), notes,
    )
    assert n == 2
    assert (tmp_path / "123456789012" / "us-east-1" / "a1" / "prod").is_dir()
    assert (tmp_path / "123456789012" / "us-east-1" / "a2" / "prod").is_dir()
