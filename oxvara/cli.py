"""Oxvara command line interface."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .codegen import write_server
from .inputs import detect_source, load_input
from .models import ApiEstate


def _auth_desc(ep) -> str:
    auth = ep.policy.auth
    if auth.kind == "apiKey":
        return f"apiKey ({auth.name} in {auth.location})"
    return auth.kind


def _rate_desc(ep) -> str:
    rl = ep.policy.rate_limit
    return f"{rl.requests}/{rl.per}" if rl else "none"


def cmd_compile(args: argparse.Namespace) -> int:
    estate = load_input(args.input)
    write_server(estate, args.output)
    print(f"compiled {len(estate.endpoints)} operations -> {args.output}")
    for ep in estate.endpoints:
        print(f"  {ep.method:6} {ep.path:28} tool={ep.tool_name} "
              f"auth={ep.policy.auth.kind} rate={_rate_desc(ep)}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    estate = load_input(args.input)
    print(f"{estate.title} {estate.version} ({estate.slug})")
    print(f"source: {detect_source(args.input)}")
    print(f"base URL: {estate.base_url or '(not set)'}")
    print(f"operations: {len(estate.endpoints)}")
    for ep in estate.endpoints:
        print(f"  {ep.method:6} {ep.path:28} auth={_auth_desc(ep):28} "
              f"rate={_rate_desc(ep)}")
    return 0


def _warnings(estate: ApiEstate) -> list[str]:
    warnings = []
    if not estate.base_url:
        warnings.append(
            "base URL is not set; generated tools will call relative paths"
        )
    for ep in estate.endpoints:
        label = f"{ep.method} {ep.path}"
        if ep.policy.auth.kind == "none":
            warnings.append(f"{label} has no auth configured")
        if ep.policy.auth.kind == "oauth2":
            warnings.append(
                f"{label} uses oauth2, which the generated server does not "
                "implement yet (it will raise NotImplementedError)"
            )
        if ep.policy.rate_limit is None:
            warnings.append(f"{label} has no rate limit configured")
    return warnings


def cmd_diff(args: argparse.Namespace) -> int:
    estate = load_input(args.input)
    print(f"Plan for {estate.title} {estate.version} "
          f"({len(estate.endpoints)} operations). Nothing will be written.")
    print()
    for ep in estate.endpoints:
        print(f"  {ep.method:6} {ep.path:28} -> {ep.tool_name}")
        print(f"      auth: {_auth_desc(ep)}")
        print(f"      rate: {_rate_desc(ep)}")
        print(f"      timeout: {ep.policy.timeout}s")
    warnings = _warnings(estate)
    if warnings:
        print()
        print("Warnings:")
        for warning in warnings:
            print(f"  ! {warning}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oxvara",
        description="Compile governed MCP servers from a managed API estate.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    compile_p = sub.add_parser(
        "compile", help="generate an MCP server module from an estate"
    )
    compile_p.add_argument(
        "input",
        help="OpenAPI file, Apigee bundle dir, or APIM export dir",
    )
    compile_p.add_argument(
        "-o", "--output", default="oxvara_server.py",
        help="where to write the generated server (default: oxvara_server.py)",
    )
    compile_p.set_defaults(func=cmd_compile)

    inspect_p = sub.add_parser(
        "inspect", help="show the operations and inherited policies in an estate"
    )
    inspect_p.add_argument(
        "input",
        help="OpenAPI file, Apigee bundle dir, or APIM export dir",
    )
    inspect_p.set_defaults(func=cmd_inspect)

    diff_p = sub.add_parser(
        "diff",
        help="dry run: show the tools and policies compile would produce",
    )
    diff_p.add_argument(
        "input",
        help="OpenAPI file, Apigee bundle dir, or APIM export dir",
    )
    diff_p.set_defaults(func=cmd_diff)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print(f"oxvara: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
