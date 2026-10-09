"""Oxvara command line interface."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .codegen import write_server
from .parser import load_spec_file


def cmd_compile(args: argparse.Namespace) -> int:
    estate = load_spec_file(args.spec)
    write_server(estate, args.output)
    print(f"compiled {len(estate.endpoints)} operations -> {args.output}")
    for ep in estate.endpoints:
        rl = ep.policy.rate_limit
        budget = f"{rl.requests}/{rl.per}" if rl else "none"
        print(f"  {ep.method:6} {ep.path:28} tool={ep.tool_name} "
              f"auth={ep.policy.auth.kind} rate={budget}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    estate = load_spec_file(args.spec)
    print(f"{estate.title} {estate.version} ({estate.slug})")
    print(f"base URL: {estate.base_url or '(not set)'}")
    print(f"operations: {len(estate.endpoints)}")
    for ep in estate.endpoints:
        rl = ep.policy.rate_limit
        budget = f"{rl.requests}/{rl.per}" if rl else "none"
        auth = ep.policy.auth
        auth_desc = auth.kind
        if auth.kind == "apiKey":
            auth_desc = f"apiKey({auth.name} in {auth.location})"
        print(f"  {ep.method:6} {ep.path:28} auth={auth_desc:28} rate={budget}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oxvara",
        description="Compile governed MCP servers from a managed API estate.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    compile_p = sub.add_parser(
        "compile", help="generate an MCP server module from an OpenAPI spec"
    )
    compile_p.add_argument("spec", help="path to an OpenAPI 3.x YAML/JSON file")
    compile_p.add_argument(
        "-o", "--output", default="oxvara_server.py",
        help="where to write the generated server (default: oxvara_server.py)",
    )
    compile_p.set_defaults(func=cmd_compile)

    inspect_p = sub.add_parser(
        "inspect", help="show the operations and inherited policies in a spec"
    )
    inspect_p.add_argument("spec", help="path to an OpenAPI 3.x YAML/JSON file")
    inspect_p.set_defaults(func=cmd_inspect)
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
