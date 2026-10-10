"""Collect API Gateway estates across AWS accounts and regions.

Uses boto3 to assume an IAM role in each target account, then reads the
API Gateway REST APIs through the live AWS APIs and writes them to disk
in the exact directory layout that ``oxvara/exporters/aws.py`` reads::

    <output>/<account_id>/<region>/<api_id>/<stage_name>/
        openapi.json      # get_export with extensions=apigateway
        stage.json        # get_stage (method settings / throttling)
        usage-plans.json  # get_usage_plans (filtered to this API stage)

Point the normal commands at the collected tree afterwards, for example::

    oxvara inventory collected/*/*/*/

boto3 is an optional dependency (``pip install "oxvara[aws]"``). Importing
this module without boto3 installed raises an ImportError that says so.

Live-AWS verification is pending: this module was built and tested with
mocked boto3 clients only. It has not been run against real AWS APIs.
"""

from __future__ import annotations

import json
import os
import time

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover - exercised via the import guard test
    boto3 = None
    ClientError = Exception

_ROLE_SESSION = "oxvara-collector"
_EXPORT_TYPE = "oas30"
_MAX_ATTEMPTS = 5
_BASE_DELAY = 1.0


def _require_boto3():
    if boto3 is None:
        raise ImportError(
            'collect-aws needs boto3: pip install "oxvara[aws]"'
        )
    return boto3


def _throttled(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    code = str((response.get("Error") or {}).get("Code", ""))
    return code in (
        "ThrottlingException",
        "ThrottledException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "ProvisionedThroughputExceededException",
    )


def _call_with_retry(client, operation: str, note: str, notes: list[str], **kwargs):
    """Call a boto3 client method, retrying throttling with backoff.

    Returns None (and records a note) when the call fails for any other
    reason, so one bad API never aborts the whole collection.
    """
    delay = _BASE_DELAY
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            return getattr(client, operation)(**kwargs)
        except Exception as exc:  # noqa: BLE001 - boto3 raises ClientError
            if _throttled(exc):
                if attempt < _MAX_ATTEMPTS:
                    time.sleep(delay)
                    delay *= 2
                    continue
                notes.append(f"{note}: throttled after {_MAX_ATTEMPTS} attempts")
                return None
            notes.append(f"{note}: {exc}")
            return None
    return None  # unreachable; the loop always returns


def _paginate(client, operation: str, note: str, notes: list[str], **kwargs) -> list[dict]:
    """Collect every page of a ``position``-paginated API Gateway call."""
    items: list[dict] = []
    position = None
    while True:
        page_kwargs = dict(kwargs)
        if position:
            page_kwargs["position"] = position
        page = _call_with_retry(client, operation, note, notes, **page_kwargs)
        if page is None:
            break
        items.extend(page.get("items") or [])
        position = page.get("position")
        if not position:
            break
    return items


def _assume_role(sts, account_id: str, role_name: str, notes: list[str]):
    """Assume the collector role in a target account. None on failure."""
    arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    resp = _call_with_retry(
        sts, "assume_role", f"account {account_id}: assume_role {arn}",
        notes, RoleArn=arn, RoleSessionName=_ROLE_SESSION,
    )
    if resp is None:
        return None
    return (resp.get("Credentials") or {})


def _client_for(boto3_mod, service: str, region: str, creds: dict):
    return boto3_mod.client(
        service,
        region_name=region,
        aws_access_key_id=creds.get("AccessKeyId"),
        aws_secret_access_key=creds.get("SecretAccessKey"),
        aws_session_token=creds.get("SessionToken"),
    )


def _export_api(client, api_id: str, stage_name: str, notes: list[str]) -> str | None:
    """Export one API stage as an OpenAPI document. None on failure."""
    resp = _call_with_retry(
        client, "get_export",
        f"api {api_id} stage {stage_name}: get_export",
        notes,
        restApiId=api_id, stageName=stage_name,
        exportType=_EXPORT_TYPE, parameters={"extensions": "apigateway"},
    )
    if resp is None:
        return None
    body = resp.get("body")
    try:
        text = body.read().decode("utf-8") if hasattr(body, "read") else str(body)
        json.loads(text)  # sanity: the export must be JSON
        return text
    except (ValueError, UnicodeDecodeError, AttributeError) as exc:
        notes.append(f"api {api_id} stage {stage_name}: export is not valid JSON: {exc}")
        return None


def _write_json(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def collect_account_region(
    boto3_mod,
    sts,
    account_id: str,
    region: str,
    role_name: str,
    output_dir: str,
    notes: list[str],
) -> int:
    """Collect every REST API stage in one account and region.

    Returns the number of API stages written. Failures are appended to
    ``notes``; nothing raises except filesystem errors.
    """
    creds = _assume_role(sts, account_id, role_name, notes)
    if not creds:
        return 0
    client = _client_for(boto3_mod, "apigateway", region, creds)

    apis = _paginate(
        client, "get_rest_apis",
        f"account {account_id} region {region}: get_rest_apis", notes,
    )
    written = 0
    for api in apis:
        api_id = str(api.get("id", ""))
        if not api_id:
            notes.append(
                f"account {account_id} region {region}: "
                "API entry without an id, skipped"
            )
            continue
        stages = _paginate(
            client, "get_stages",
            f"api {api_id}: get_stages", notes, restApiId=api_id,
        )
        if not stages:
            notes.append(
                f"account {account_id} region {region} api {api_id}: "
                "no stages found, nothing to export"
            )
            continue
        for stage in stages:
            stage_name = str(stage.get("stageName", ""))
            if not stage_name:
                continue
            dest = os.path.join(output_dir, account_id, region, api_id, stage_name)
            export_text = _export_api(client, api_id, stage_name, notes)
            if export_text is None:
                continue
            _write_json(os.path.join(dest, "openapi.json"), json.loads(export_text))
            detail = _call_with_retry(
                client, "get_stage",
                f"api {api_id} stage {stage_name}: get_stage",
                notes, restApiId=api_id, stageName=stage_name,
            )
            if detail is not None:
                _write_json(os.path.join(dest, "stage.json"), detail)
            else:
                notes.append(
                    f"api {api_id} stage {stage_name}: stage.json missing, "
                    "stage throttling will be reported as unknown by the importer"
                )
            plans = _paginate(
                client, "get_usage_plans",
                f"api {api_id}: get_usage_plans", notes,
            )
            _write_json(os.path.join(dest, "usage-plans.json"), {"items": plans})
            written += 1
    return written


def collect_aws(
    accounts: list[str],
    regions: list[str],
    role_name: str,
    output_dir: str,
) -> dict:
    """Collect API Gateway estates across accounts and regions.

    Returns ``{"stages": int, "notes": [str]}``. ``stages`` is the number
    of API stages written to ``output_dir``; ``notes`` describes every
    API, stage, or account that could not be collected and why.
    """
    boto3_mod = _require_boto3()
    notes: list[str] = []
    if not accounts:
        notes.append("no accounts given: nothing to collect")
        return {"stages": 0, "notes": notes}
    if not regions:
        notes.append("no regions given: nothing to collect")
        return {"stages": 0, "notes": notes}
    sts = boto3_mod.client("sts")
    total = 0
    for account_id in accounts:
        for region in regions:
            total += collect_account_region(
                boto3_mod, sts, account_id.strip(), region.strip(),
                role_name, output_dir, notes,
            )
    return {"stages": total, "notes": notes}
