"""Import a Kong decK declarative configuration into a normalized ApiEstate.

Input is a decK state file (``_format_version: "3.0"``), the format
produced by ``deck gateway dump`` and consumed by ``deck gateway sync``::

    services:
      - name: orders
        url: http://orders.internal:8080
        plugins: [...]
        routes:
          - name: list-orders
            paths: [/orders]
            methods: [GET]
            plugins: [...]
    plugins: [...]   # global, or scoped with service:/route: keys

Operations come from routes: one operation per (route path, method).
Kong 3.x regex paths (``~/orders/(?<orderId>[^/]+)$``) are supported when
they use named captures, which become path parameters. Other regex paths
are skipped and reported, not guessed at.

Governance comes from plugins. Kong applies the most specific instance
of each plugin (route over service over global), and so does Oxvara:

- ``key-auth``: apiKey, sent in the first ``config.key_names`` header
  (Kong's default name is ``apikey``).
- ``basic-auth``: basic.
- ``jwt``: bearer. The client presents a JWT Kong verifies.
- ``oauth2``, ``openid-connect``: oauth2.
- ``rate-limiting``: the tightest of ``config.second/minute/hour/day``.
- ``rate-limiting-advanced``: the tightest ``limit``/``window_size`` pair.
- ``request-termination``: the route answers without reaching an
  upstream, so it is not exposed as a tool.

Consumer-scoped plugins, disabled plugins and auth plugins Oxvara does
not model (``hmac-auth``, ``mtls-auth``, ...) are reported as notes.

Tools call the Kong proxy, never the service ``url``: a decK file names
the upstream but not the proxy address, so the caller supplies it as
the gateway URL.
"""

from __future__ import annotations

import os
import re

import yaml

from ..models import (
    AUTH_STRENGTH,
    ApiEstate,
    AuthPolicy,
    Endpoint,
    Parameter,
    Policy,
    RateLimit,
)
from ..util import camel_to_snake, normalize_rate, path_params, slugify

_AUTH_PLUGINS = {
    "key-auth", "key-auth-enc", "basic-auth", "jwt", "oauth2",
    "openid-connect", "oauth2-introspection",
}
_UNMODELED_AUTH = {"hmac-auth", "mtls-auth", "ldap-auth", "ldap-auth-advanced",
                   "jwt-signer", "saml"}
_RATE_PLUGINS = {"rate-limiting", "rate-limiting-advanced"}
_WINDOWS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400,
            "month": 2592000, "year": 31536000}
_NAMED_CAPTURE = re.compile(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>[^)]*\)")


def is_deck_file(path: str) -> bool:
    """True when a YAML/JSON file looks like a decK state file."""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return "_format_version" in head


def _ref_name(value) -> str:
    """decK references entities as a name string or a {name: ...} map."""
    if isinstance(value, dict):
        return str(value.get("name") or value.get("id") or "")
    return str(value or "")


def _enabled(plugin: dict) -> bool:
    return plugin.get("enabled", True) is not False


def _auth_from(plugin: dict) -> AuthPolicy | None:
    name = plugin.get("name")
    config = plugin.get("config") or {}
    if name in ("key-auth", "key-auth-enc"):
        key_names = config.get("key_names") or ["apikey"]
        in_header = config.get("key_in_header", True) is not False
        return AuthPolicy(
            kind="apiKey",
            name=str(key_names[0]),
            location="header" if in_header else "query",
        )
    if name == "basic-auth":
        return AuthPolicy(kind="basic")
    if name == "jwt":
        return AuthPolicy(kind="bearer")
    if name in ("oauth2", "openid-connect", "oauth2-introspection"):
        return AuthPolicy(kind="oauth2")
    return None


def _tightest(limits: list[RateLimit | None]) -> RateLimit | None:
    real = [lim for lim in limits if lim is not None]
    return min(real, key=lambda lim: lim.per_second()) if real else None


def _rate_from(plugin: dict) -> RateLimit | None:
    config = plugin.get("config") or {}
    if plugin.get("name") == "rate-limiting":
        limits = []
        for unit, seconds in _WINDOWS.items():
            value = config.get(unit)
            if isinstance(value, (int, float)) and value > 0:
                limits.append(normalize_rate(int(value), seconds))
        return _tightest(limits)
    if plugin.get("name") == "rate-limiting-advanced":
        counts = config.get("limit") or []
        windows = config.get("window_size") or []
        limits = [
            normalize_rate(int(c), int(w))
            for c, w in zip(counts, windows)
            if isinstance(c, (int, float)) and isinstance(w, (int, float))
        ]
        return _tightest(limits)
    return None


class _Scope:
    """The plugins attached at one level (global, a service or a route)."""

    def __init__(self) -> None:
        self.auth: AuthPolicy | None = None
        self.rate: RateLimit | None = None
        self.terminated = False

    def add(self, plugin: dict, where: str, notes: list[str]) -> None:
        name = str(plugin.get("name", ""))
        if not _enabled(plugin):
            notes.append(f"{where}: plugin {name} is disabled; ignored")
            return
        if plugin.get("consumer") or plugin.get("consumer_group"):
            notes.append(
                f"{where}: plugin {name} is consumer-scoped; per-consumer "
                "policy is not modeled"
            )
            return
        if name in _AUTH_PLUGINS:
            auth = _auth_from(plugin)
            # When several auth plugins stack on one level, keep the
            # strongest: a weaker one cannot lower what Kong demands.
            if auth and (self.auth is None or _strength(auth) > _strength(self.auth)):
                self.auth = auth
        elif name in _UNMODELED_AUTH:
            notes.append(
                f"{where}: auth plugin {name} is not modeled; the operation "
                "will be reported as unauthenticated"
            )
        elif name in _RATE_PLUGINS:
            self.rate = _tightest([self.rate, _rate_from(plugin)])
        elif name == "request-termination":
            self.terminated = True

    def policy(self) -> Policy:
        return Policy(auth=self.auth or AuthPolicy(), rate_limit=self.rate)


def _strength(auth: AuthPolicy) -> int:
    return AUTH_STRENGTH.get(auth.kind, 0)


def _route_path(raw: str) -> str | None:
    """Turn a Kong route path into a templated path, or None if it can't be."""
    if not raw.startswith("~"):
        return raw
    pattern = raw[1:].lstrip("^").rstrip("$")
    templated = _NAMED_CAPTURE.sub(lambda m: "{" + m.group(1) + "}", pattern)
    # Anything regex-like left over means the route matches a family of
    # paths we cannot turn into one callable operation.
    if re.search(r"[()\[\]*+?|\\]", templated):
        return None
    return templated


def load_deck(path: str, gateway_url: str = "") -> ApiEstate:
    """Load a decK state file into an ApiEstate."""
    with open(path, "r", encoding="utf-8") as fh:
        try:
            doc = yaml.safe_load(fh.read())
        except yaml.YAMLError as exc:
            raise ValueError(f"could not parse {path}: {exc}") from exc
    if not isinstance(doc, dict) or "_format_version" not in doc:
        raise ValueError(f"{path!r} is not a decK state file (no _format_version)")

    title = os.path.splitext(os.path.basename(path))[0]
    info = doc.get("_info") or {}
    if isinstance(info, dict) and info.get("select_tags"):
        title = "-".join(str(t) for t in info["select_tags"])
    gateway_url = gateway_url.rstrip("/")
    estate = ApiEstate(
        title=title, slug=slugify(title), version=str(doc["_format_version"]),
        base_url=gateway_url, kind="kong",
    )
    notes = estate.notes
    if not gateway_url:
        notes.append(
            "no gateway URL given for this Kong config; pass --gateway-url "
            "(or PATH@https://host) so tools call the Kong proxy and its "
            "plugins are enforced"
        )

    services = [s for s in (doc.get("services") or []) if isinstance(s, dict)]
    global_scope = _Scope()
    service_scopes: dict[str, _Scope] = {}
    route_scopes: dict[str, _Scope] = {}  # top-level plugins with route:
    nested_scopes: dict[int, _Scope] = {}  # plugins nested in a route
    routes: list[tuple[dict, dict]] = []  # (route, service)

    for svc in services:
        sname = _ref_name(svc.get("name"))
        service_scopes.setdefault(sname, _Scope())
        for plugin in svc.get("plugins") or []:
            service_scopes[sname].add(plugin, f"service {sname}", notes)
        for route in svc.get("routes") or []:
            if isinstance(route, dict):
                routes.append((route, svc))
    by_name = {_ref_name(s.get("name")): s for s in services}
    for route in doc.get("routes") or []:
        if isinstance(route, dict):
            svc = by_name.get(_ref_name(route.get("service")), {})
            routes.append((route, svc))
    for route, _svc in routes:
        rname = _ref_name(route.get("name")) or "(unnamed)"
        scope = nested_scopes.setdefault(id(route), _Scope())
        for plugin in route.get("plugins") or []:
            scope.add(plugin, f"route {rname}", notes)

    for plugin in doc.get("plugins") or []:
        if not isinstance(plugin, dict):
            continue
        if plugin.get("route"):
            rname = _ref_name(plugin["route"])
            route_scopes.setdefault(rname, _Scope()).add(plugin, f"route {rname}", notes)
        elif plugin.get("service"):
            sname = _ref_name(plugin["service"])
            service_scopes.setdefault(sname, _Scope()).add(
                plugin, f"service {sname}", notes
            )
        else:
            global_scope.add(plugin, "global", notes)

    upstreams = [str(s.get("url", "")) for s in services if s.get("url")]
    estate.upstream_url = upstreams[0].rstrip("/") if upstreams else ""

    for route, svc in routes:
        sname = _ref_name(svc.get("name")) or "service"
        named = _ref_name(route.get("name"))
        rname = named or sname
        nested = nested_scopes.get(id(route), _Scope())
        rscope = route_scopes.get(named, _Scope()) if named else _Scope()
        sscope = service_scopes.get(sname, _Scope())
        scopes = (global_scope, sscope, rscope, nested)
        if any(s.terminated for s in scopes):
            notes.append(f"route {rname}: request-termination applies; not exposed")
            continue
        policy = Policy()
        for s in scopes:
            policy = policy.merge(s.policy())

        methods = [str(m).upper() for m in (route.get("methods") or [])]
        if not methods:
            notes.append(
                f"route {rname}: matches every method; exposing GET only. "
                "Add methods: to the route to expose writes deliberately"
            )
            methods = ["GET"]
        for raw_path in route.get("paths") or []:
            path = _route_path(str(raw_path))
            if path is None:
                notes.append(
                    f"route {rname}: regex path {raw_path!r} has no named "
                    "captures Oxvara can template; skipped"
                )
                continue
            for method in methods:
                if method in ("CONNECT", "TRACE"):
                    continue
                op = camel_to_snake(f"{rname}_{method.lower()}")
                if len(route.get("paths") or []) > 1:
                    op = camel_to_snake(f"{op}_{path}")
                estate.endpoints.append(
                    Endpoint(
                        operation_id=op,
                        tool_name=f"{slugify(sname)}_{op}",
                        method=method,
                        path=path,
                        summary=f"{method} {path} via Kong route {rname}",
                        description="",
                        parameters=[
                            Parameter(name=p, location="path", required=True,
                                      schema_type="string")
                            for p in path_params(path)
                        ],
                        body_raw=method in ("POST", "PUT", "PATCH"),
                        policy=policy,
                    )
                )

    if not estate.endpoints:
        raise ValueError(f"no exposable routes found in {path!r}")
    return estate
