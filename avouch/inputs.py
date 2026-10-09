"""Detect and load any supported estate input.

Avouch accepts three kinds of input:

- an OpenAPI 3.x YAML or JSON file (governance from x-avouch blocks),
- an Apigee bundle directory (apiproxy/ layout),
- an Azure APIM export directory (openapi.yaml + policy.xml layout).

Directories are detected by layout; anything else is treated as an
OpenAPI file and parsed accordingly.
"""

from __future__ import annotations

import os

from .exporters.apigee import load_bundle
from .exporters.apim import load_apim
from .models import ApiEstate
from .parser import load_spec_file


def detect_source(path: str) -> str:
    """Return 'apigee', 'apim', or 'openapi' for a filesystem path."""
    if os.path.isdir(path):
        if os.path.isdir(os.path.join(path, "apiproxy")) or os.path.isdir(
            os.path.join(path, "proxies")
        ):
            return "apigee"
        return "apim"
    return "openapi"


def load_input(path: str) -> ApiEstate:
    """Load an estate from any supported input path."""
    source = detect_source(path)
    if source == "apigee":
        return load_bundle(path)
    if source == "apim":
        return load_apim(path)
    return load_spec_file(path)
