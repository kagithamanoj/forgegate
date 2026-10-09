# Avouch

**Your APIs are agent-ready. Your agents just don't know it.**

Every enterprise already has thousands of REST APIs behind a gateway,
with specs, keys, and rate limits. Agents speak MCP, not REST. Converting
even one critical API into a governed MCP server takes an engineer days.
Doing it for a whole estate takes quarters.

Avouch reads the API estate you already have and compiles governed
MCP servers from it. Auth schemes, rate limits, and timeouts are
inherited from the estate's own policies instead of being re-configured
for the agent world. It is the onboarding plane for MCP, not another
gateway.

## Quickstart

```bash
pip install "avouch @ git+https://github.com/kagithamanoj/avouch.git"

# point it at an OpenAPI file, an Apigee bundle, or an APIM export
avouch inspect examples/petstore.yaml
avouch inspect examples/apigee
avouch inspect examples/apim

# dry run: see the planned tools and inherited policies first
avouch diff examples/apigee

# check the estate against the strict policy pack
avouch validate examples/apigee

# compile it into a runnable MCP server
avouch compile examples/apigee -o petserver.py

# give the generated server its credentials, then run it
export AVOUCH_API_KEY=your-key
python petserver.py
```

The generated server speaks MCP over stdio, so point any MCP client at
it (for example Claude Code or any host that accepts an MCP command).

## How it works

```mermaid
flowchart LR
    A[OpenAPI 3.x\n+ x-avouch policies] --> D[Policy merge]
    B[Apigee bundle\nproxies + policies] --> D
    C[APIM export\nopenapi + policy.xml] --> D
    D[Policy merge\nestate defaults +\nper-operation overrides] --> E[Code generator]
    E --> F[FastMCP server\none tool per operation]
    F --> G[Agents call tools;\nauth + rate limits\nalready enforced]
```

1. Avouch imports your estate from one of three sources (below) and
   normalizes it into one internal model: operations plus the policy
   each one inherits.
2. `avouch compile` turns every operation into an MCP tool. The
   generated code injects credentials from the environment, substitutes
   path parameters, and enforces rate limits client-side before a
   request ever leaves the process.
3. The tool docstrings carry the inherited policy, so agents see the
   governance in plain language.

## Input sources

**OpenAPI 3.x.** Governance comes from `x-avouch` blocks. A block at
the document root sets the estate defaults; a block on an operation
overrides them. See `examples/petstore.yaml`.

**Apigee.** Point Avouch at an exported bundle directory
(`apiproxy/` with `proxies/`, `targets/`, `policies/`). Operations come
from proxy flow conditions (`proxy.pathsuffix MatchesPath ... and
request.verb = ...`). PreFlow policies apply to every operation;
per-flow steps override them. VerifyAPIKey and OAuthV2 map to auth;
Quota and SpikeArrest map to rate limits. A Quota that only carries a
`countRef` (a per-product quota the bundle cannot resolve) contributes
no limit rather than a wrong one. See `examples/apigee/`.

**Azure APIM.** Point Avouch at an export directory with
`openapi.yaml`, `policy.xml`, and optional
`operations/<operationId>/policy.xml` overrides. Only `<inbound>`
policies are read: `rate-limit` and `quota` (tightest wins),
`check-header` for subscription keys, `authentication-basic`, and
`validate-jwt`. See `examples/apim/`.

## Annotation reference (`x-avouch`)

| Key | Where | Meaning |
| --- | --- | --- |
| `baseUrl` | root only | Base URL for every generated tool |
| `auth.kind` | root, operation | `apiKey`, `bearer`, `basic`, `oauth2`, `none` |
| `auth.name` | root, operation | Header or query name for `apiKey` |
| `auth.in` | root, operation | `header` or `query` |
| `rateLimit.requests` | root, operation | Request budget |
| `rateLimit.per` | root, operation | `second`, `minute`, or `hour` |
| `timeout` | root, operation | HTTP timeout in seconds (default 30) |

Auth kinds and their credential sources in generated servers:

| Kind | Env var | Sent as |
| ---- | ------- | ------- |
| `apiKey` | `AVOUCH_API_KEY` | Header (or query param) named by `auth.name` |
| `bearer` | `AVOUCH_BEARER_TOKEN` | `Authorization: Bearer <token>` |
| `basic` | `AVOUCH_BASIC_CREDENTIALS` | `Authorization: Basic <base64(user:password)>` |
| `oauth2` | `AVOUCH_OAUTH_ACCESS_TOKEN` (delegated token), or `AVOUCH_OAUTH_TOKEN_URL` + `_CLIENT_ID` + `_CLIENT_SECRET` [+ `_SCOPE`] | `Authorization: Bearer <token>`; client-credentials tokens are cached until expiry |
| `none` | n/a | No credentials |

## Commands

| Command | What it does |
| ------- | ------------ |
| `avouch inspect <input>` | List operations and their inherited policies |
| `avouch diff <input>` | Dry run: planned tools, policies, and governance warnings. Writes nothing |
| `avouch validate [--pack strict] <input>` | Check the estate against a policy pack; exits non-zero on violations |
| `avouch compile <input> -o server.py` | Generate the MCP server module |

`<input>` is an OpenAPI file, an Apigee bundle directory, or an APIM
export directory; Avouch detects which by layout.

## Policy packs

Packs encode the bar an estate must clear before it is exposed to
agents. The `strict` pack requires a base URL, auth on every operation,
a rate limit on every operation, and caps every budget at 1000
requests/minute. Run it in CI to keep new APIs from shipping
ungoverned:

```bash
avouch validate --pack strict ./my-apim-export
```

## Project status

Working prototype, and labeled as one. The compiler pipeline works end
to end for all three input sources: import, merge policies, generate,
run. What is next: a Kong exporter, policy packs beyond `strict`
(per-team budgets, data-classification rules), a shared rate-budget
store so limits hold across server replicas, and response validation
against the OpenAPI schemas. The roadmap in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the details.

What is deliberately not faked: OAuth2 supports delegated token
passthrough and the client-credentials grant only. Authorization-code /
token-exchange (RFC 8693) flows for per-user delegation are not built.
Anything else marked "not implemented" in the docs is exactly that.

## Security model of generated servers

- **Audit log**: every call and response status is written as JSON lines
  to `AVOUCH_AUDIT_LOG` (default stderr). Argument values under
  secret-looking keys are redacted; credentials are never logged.
- **Argument injection**: path parameters are percent-encoded, so a value
  like `../admin` cannot add path segments.
- **Untrusted output**: upstream responses are size-capped
  (`AVOUCH_MAX_RESPONSE_CHARS`) and labeled as untrusted data. This
  reduces, but does not eliminate, prompt-injection risk from hostile
  API responses.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest        # full suite
ruff check avouch tests   # lint, also runs in CI
```

## Contributing

Issues and pull requests are welcome. Keep the no-fake-it rule: if a
feature is not implemented, the code should say so loudly instead of
pretending.

## License

MIT. See [LICENSE](LICENSE).
