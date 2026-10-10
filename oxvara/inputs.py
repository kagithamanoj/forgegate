"""Detect and load any supported estate input, alone or several at once.

Oxvara accepts four kinds of input:

- an OpenAPI 3.x YAML or JSON file (governance from x-oxvara blocks),
- an Apigee bundle directory (apiproxy/ layout),
- an Azure APIM export directory (openapi.yaml + policy.xml layout),
- a Kong decK state file (a YAML/JSON file with _format_version),
- an Amazon API Gateway export directory (openapi.json from get-export,
  plus optional stage.json and usage-plans.json).

Each input may carry the gateway URL it is served on, written as
``PATH@https://gateway.example.com``. Gateway exports (Apigee, Kong)
describe policy but not the public host, and tools must call the
gateway, not the backend, or every imported policy is bypassed.

Several inputs merge into one estate: one inventory, one policy check,
one MCP server whose tools keep their own gateway URL.
"""

from __future__ import annotations

import os

from .exporters.apigee import load_bundle
from .exporters.apim import load_apim
from .exporters.aws import is_aws_export, load_aws
from .exporters.kong import is_deck_file, load_deck
from .models import ApiEstate
from .parser import load_spec_file


def split_input(spec: str) -> tuple[str, str]:
    """Split ``PATH@https://host`` into (path, gateway_url)."""
    for marker in ("@https://", "@http://"):
        idx = spec.rfind(marker)
        if idx > 0:
            return spec[:idx], spec[idx + 1:]
    return spec, ""


def detect_source(path: str) -> str:
    """Return 'apigee', 'aws', 'apim', 'kong', or 'openapi' for a path."""
    path, _ = split_input(path)
    if os.path.isdir(path):
        if os.path.isdir(os.path.join(path, "apiproxy")) or os.path.isdir(
            os.path.join(path, "proxies")
        ):
            return "apigee"
        if is_aws_export(path):
            return "aws"
        return "apim"
    if is_deck_file(path):
        return "kong"
    return "openapi"


def load_input(spec: str, gateway_url: str = "") -> ApiEstate:
    """Load an estate from one input (``PATH`` or ``PATH@URL``)."""
    path, own_gateway = split_input(spec)
    gateway = own_gateway or gateway_url
    source = detect_source(path)
    if source == "apigee":
        estate = load_bundle(path, gateway)
    elif source == "aws":
        estate = load_aws(path, gateway)
    elif source == "apim":
        estate = load_apim(path, gateway)
    elif source == "kong":
        estate = load_deck(path, gateway)
    else:
        estate = load_spec_file(path)
        if gateway:
            estate.base_url = gateway.rstrip("/")
    for ep in estate.endpoints:
        ep.source = f"{estate.kind}:{estate.slug}"
        ep.base_url = ep.base_url or estate.base_url
    return estate


def merge_estates(estates: list[ApiEstate]) -> ApiEstate:
    """Fold several estates into one; endpoints keep their own base URL."""
    if len(estates) == 1:
        return estates[0]
    merged = ApiEstate(
        title="Oxvara estate",
        slug="oxvara",
        version="+".join(f"{e.slug}@{e.version}" for e in estates),
        base_url=next((e.base_url for e in estates if e.base_url), ""),
        kind="merged",
    )
    for estate in estates:
        merged.endpoints.extend(estate.endpoints)
        merged.notes.extend(f"{estate.kind}:{estate.slug}: {n}" for n in estate.notes)
    return merged


def load_inputs(specs: list[str], gateway_url: str = "") -> tuple[ApiEstate, list[ApiEstate]]:
    """Load every input; return the merged estate and the per-input estates."""
    estates = [load_input(spec, gateway_url) for spec in specs]
    return merge_estates(estates), estates
