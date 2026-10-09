"""Small shared helpers for the Oxvara compiler."""

from __future__ import annotations

import re


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "api"


def camel_to_snake(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    name = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower().strip("_") or "operation"


def path_params(path: str) -> list[str]:
    """Return the {template} parameter names found in a URL path."""
    return re.findall(r"\{([^{}]+)\}", path)
