"""Oxvara command line interface."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys

from . import __version__
from .codegen import tool_names, write_server
from .inputs import detect_source, load_inputs, split_input
from .lock import SEVERITY_ORDER, detect_drift, exceeds, read_lock, write_lock
from .models import ApiEstate
from .packs import PACKS, run_packs
from .report import as_json, sarif

INPUT_HELP = (
    "OpenAPI file, Apigee bundle dir, APIM export dir, AWS API Gateway export dir, "
    "or Kong decK file; "
    "append @https://gateway.host to set the gateway it is served on"
)


def _auth_desc(ep) -> str:
    auth = ep.policy.auth
    if auth.kind == "apiKey":
        return f"apiKey ({auth.name} in {auth.location})"
    return auth.kind


def _rate_desc(ep) -> str:
    rl = ep.policy.rate_limit
    return f"{rl.requests}/{rl.per}" if rl else "none"


def _load(args: argparse.Namespace) -> tuple[ApiEstate, list[ApiEstate]]:
    return load_inputs(args.inputs, getattr(args, "gateway_url", "") or "")


def _print_notes(estate: ApiEstate) -> None:
    if estate.notes:
        print()
        print("Import notes:")
        for note in estate.notes:
            print(f"  - {note}")


def cmd_compile(args: argparse.Namespace) -> int:
    estate, _ = _load(args)
    write_server(estate, args.output)
    print(f"compiled {len(estate.endpoints)} operations -> {args.output}")
    for ep, name in zip(estate.endpoints, tool_names(estate)):
        print(f"  {ep.method:6} {ep.path:28} tool={name} "
              f"auth={ep.policy.auth.kind} rate={_rate_desc(ep)}")
    if args.lock:
        write_lock(estate, args.lock)
        print(f"lockfile -> {args.lock}")
    _print_notes(estate)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    _, estates = _load(args)
    for spec, estate in zip(args.inputs, estates):
        print(f"{estate.title} {estate.version} ({estate.slug})")
        print(f"source: {detect_source(split_input(spec)[0])}")
        print(f"base URL: {estate.base_url or '(not set)'}")
        if estate.upstream_url:
            print(f"upstream (not called directly): {estate.upstream_url}")
        print(f"operations: {len(estate.endpoints)}")
        for ep in estate.endpoints:
            print(f"  {ep.method:6} {ep.path:28} auth={_auth_desc(ep):28} "
                  f"rate={_rate_desc(ep)}")
        _print_notes(estate)
        print()
    return 0


def _warnings(estate: ApiEstate) -> list[str]:
    warnings = []
    if not estate.base_url and not any(ep.base_url for ep in estate.endpoints):
        warnings.append(
            "base URL is not set; generated tools will call relative paths"
        )
    for ep in estate.endpoints:
        label = f"{ep.method} {ep.path}"
        if ep.policy.auth.kind == "none":
            warnings.append(f"{label} has no auth configured")
        if ep.policy.auth.kind == "oauth2":
            warnings.append(
                f"{label} uses oauth2; set OXVARA_OAUTH_TOKEN_URL, "
                "OXVARA_OAUTH_CLIENT_ID and OXVARA_OAUTH_CLIENT_SECRET (plus "
                "OXVARA_OAUTH_SUBJECT_TOKEN for per-user token exchange) "
                "before running the generated server"
            )
        if ep.policy.rate_limit is None:
            warnings.append(f"{label} has no rate limit configured")
    return warnings


def cmd_diff(args: argparse.Namespace) -> int:
    estate, _ = _load(args)
    print(f"Plan for {estate.title} {estate.version} "
          f"({len(estate.endpoints)} operations). Nothing will be written.")
    print()
    for ep, name in zip(estate.endpoints, tool_names(estate)):
        print(f"  {ep.method:6} {ep.path:28} -> {name}")
        print(f"      calls: {estate.base_for(ep) or '(no base URL)'}")
        print(f"      auth: {_auth_desc(ep)}")
        print(f"      rate: {_rate_desc(ep)}")
        print(f"      timeout: {ep.policy.timeout}s")
        print(f"      read-only: {'yes' if ep.read_only else 'no'}")
    warnings = _warnings(estate)
    if warnings:
        print()
        print("Warnings:")
        for warning in warnings:
            print(f"  ! {warning}")
    _print_notes(estate)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    packs = args.pack or ["strict"]
    _, estates = _load(args)
    findings = []
    total_ops = 0
    for spec, estate in zip(args.inputs, estates):
        total_ops += len(estate.endpoints)
        for v in run_packs(estate, packs):
            findings.append({
                "rule": v.rule, "level": "error", "message": v.message,
                "tool": v.operation_id, "uri": split_input(spec)[0],
                "source": v.source or f"{estate.kind}:{estate.slug}",
            })
    if args.format == "sarif":
        print(sarif(findings))
    elif args.format == "json":
        print(as_json(findings))
    elif not findings:
        print(f"{'+'.join(packs)}: {total_ops} operations, no violations")
    else:
        print(f"{'+'.join(packs)}: {len(findings)} violation(s)")
        for f in findings:
            where = f" [{f['tool']}]" if f["tool"] else ""
            print(f"  ! {f['rule']}{where}: {f['message']}")
    return 1 if findings else 0


def cmd_inventory(args: argparse.Namespace) -> int:
    estate, estates = _load(args)
    rows = []
    for ep, name in zip(estate.endpoints, tool_names(estate)):
        rows.append({
            "source": ep.source,
            "tool": name,
            "method": ep.method,
            "path": ep.path,
            "calls": estate.base_for(ep),
            "auth": ep.policy.auth.kind,
            "rate_limit": _rate_desc(ep),
            "read_only": ep.read_only,
        })
    if args.format == "json":
        print(json.dumps({"tools": rows, "notes": estate.notes}, indent=2))
        return 0
    if args.format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0]) if rows else ["tool"])
        writer.writeheader()
        writer.writerows(rows)
        print(buf.getvalue(), end="")
        return 0

    print(f"Agent-facing inventory: {len(rows)} tools across "
          f"{len(estates)} source(s)")
    print()
    print(f"  {'SOURCE':24} {'TOOL':32} {'METHOD':6} {'AUTH':7} {'RATE':12} WRITES")
    for r in rows:
        print(f"  {r['source'][:24]:24} {r['tool'][:32]:32} {r['method']:6} "
              f"{r['auth']:7} {r['rate_limit']:12} {'no' if r['read_only'] else 'yes'}")
    print()
    for e in estates:
        n = len(e.endpoints)
        no_auth = sum(1 for ep in e.endpoints if ep.policy.auth.kind == "none")
        no_rate = sum(1 for ep in e.endpoints if ep.policy.rate_limit is None)
        writes = sum(1 for ep in e.endpoints if not ep.read_only)
        print(f"  {e.kind}:{e.slug}: {n} tools, {writes} write, "
              f"{no_auth} without auth, {no_rate} without rate limit")
    _print_notes(estate)
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    estate, _ = _load(args)
    lock = write_lock(estate, args.output)
    print(f"locked {len(lock['tools'])} tools -> {args.output}")
    _print_notes(estate)
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    lock = read_lock(args.lock)
    estate, _ = _load(args)
    changes = detect_drift(lock, estate)
    failed = exceeds(changes, args.fail_on)
    if args.format in ("json", "sarif"):
        findings = [{"rule": c.rule, "level": c.severity, "message": c.message,
                     "tool": c.tool, "uri": args.lock} for c in changes]
        print(sarif(findings) if args.format == "sarif" else as_json(findings))
        return 1 if failed else 0
    if not changes:
        print(f"no drift: {len(lock.get('tools', {}))} tools match {args.lock}")
        return 0
    counts = {s: sum(1 for c in changes if c.severity == s) for s in SEVERITY_ORDER}
    print(f"drift against {args.lock}: {counts['error']} error(s), "
          f"{counts['warning']} warning(s), {counts['note']} note(s)")
    for c in sorted(changes, key=lambda c: -SEVERITY_ORDER[c.severity]):
        print(f"  {c}")
    if failed:
        print()
        print(f"failing: changes at or above '{args.fail_on}'. Review them, "
              "then refresh the lock with `oxvara lock`.")
    return 1 if failed else 0


def _inputs(p: argparse.ArgumentParser) -> None:
    p.add_argument("inputs", nargs="+", metavar="input", help=INPUT_HELP)
    p.add_argument(
        "--gateway-url", default="",
        help="gateway URL for inputs that do not carry their own @URL",
    )


def _format(p: argparse.ArgumentParser, choices: tuple[str, ...]) -> None:
    p.add_argument("--format", choices=choices, default="text",
                   help="output format (default: text)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oxvara",
        description=(
            "Vendor-neutral governance for agent access to your API "
            "estate (Apigee, Azure APIM, AWS API Gateway, Kong): inventory, "
            "validate, lock, detect drift, compile."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("compile", help="generate an MCP server module from an estate")
    _inputs(p)
    p.add_argument("-o", "--output", default="oxvara_server.py",
                   help="where to write the generated server (default: oxvara_server.py)")
    p.add_argument("--lock", default="",
                   help="also write a lockfile of the compiled tool surface")
    p.set_defaults(func=cmd_compile)

    p = sub.add_parser("inspect", help="show the operations and inherited policies per input")
    _inputs(p)
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("diff", help="dry run: show the tools and policies compile would produce")
    _inputs(p)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("validate", help="check estates against one or more policy packs")
    _inputs(p)
    p.add_argument("--pack", action="append",
                   help=f"policy pack, repeatable (available: {', '.join(sorted(PACKS))}; "
                        "default: strict)")
    _format(p, ("text", "json", "sarif"))
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("inventory", help="one table of every agent-facing tool across gateways")
    _inputs(p)
    _format(p, ("text", "json", "csv"))
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("lock", help="record the reviewed tool surface in a lockfile")
    _inputs(p)
    p.add_argument("-o", "--output", default="oxvara.lock.json",
                   help="lockfile path (default: oxvara.lock.json)")
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("drift", help="compare the estate with a lockfile; fail on drift")
    _inputs(p)
    p.add_argument("--lock", default="oxvara.lock.json",
                   help="lockfile to compare against (default: oxvara.lock.json)")
    p.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="warning",
                   help="lowest severity that fails the run (default: warning)")
    _format(p, ("text", "json", "sarif"))
    p.set_defaults(func=cmd_drift)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, TypeError, OSError) as exc:
        print(f"oxvara: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
