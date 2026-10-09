"""Small shared helpers for the Oxvara compiler."""

from __future__ import annotations

import re

from .models import RateLimit


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


def normalize_rate(requests: int, window_seconds: int) -> RateLimit | None:
    """Fit an arbitrary (requests, window) pair into the policy model."""
    if requests <= 0 or window_seconds <= 0:
        return None
    if window_seconds <= 1:
        return RateLimit(requests=requests, per="second")
    if window_seconds <= 60:
        return RateLimit(
            requests=max(1, round(requests * 60 / window_seconds)),
            per="minute",
        )
    return RateLimit(
        requests=max(1, round(requests * 3600 / window_seconds)),
        per="hour",
    )
