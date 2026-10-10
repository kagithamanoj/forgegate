# Oxvara

**Every gateway secures its own MCP. Nobody governs all of them.**

Apigee, Azure APIM and Kong each turn their own APIs into MCP tools now.
But about a third of organizations already run more than one API
gateway ([Postman, 2025](https://www.postman.com/state-of-api/2025/)),
and no vendor will govern the others.

Oxvara is a vendor-neutral governance layer for agent access to your
API estate. It reads the gateway configuration you already have, from
any of them, and gives you:

- **One inventory** of every agent-facing tool across Apigee, APIM and Kong.
- **One policy check**, including rules mapped to the OWASP MCP Top 10,
  with SARIF output for GitHub code scanning.
- **A lockfile and a drift gate**: CI fails when someone weakens auth,
  loosens a rate limit, retargets a route, or changes a tool description
  agents will read.
- **An optional compiled MCP server** that calls through your gateways,
  inherits their policies, exchanges the end user's token (RFC 8693)
  and audits every call.

It does not replace your gateways or re-implement what they do. It reads them.

> Status: early, working prototype. Everything listed under "Working
> now" is implemented and tested; everything else says so.

## Quickstart

```bash
pip install "oxvara @ git+https://github.com/kagithamanoj/oxvara.git"

# Each input is an OpenAPI file, an Apigee bundle, an APIM export or a
# Kong decK file. Append @https://host for the gateway it is served on.
APIGEE="examples/apigee@https://apigee.example.com"
APIM="examples/apim"
KONG="examples/kong/kong.yaml@https://kong.example.com"

# one table across all three gateways
oxvara inventory $APIGEE $APIM $KONG

# policy check: strict + OWASP MCP rules (add --format sarif for code scanning)
oxvara validate --pack strict --pack owasp-mcp $APIGEE $APIM $KONG

# record the reviewed tool surface, then gate changes against it
oxvara lock $APIGEE $APIM $KONG -o oxvara.lock.json
oxvara drift --lock oxvara.lock.json $APIGEE $APIM $KONG

# optional: compile one MCP server that fronts all three
oxvara compile $APIGEE $APIM $KONG -o server.py
```

A ready-to-copy GitHub Actions gate is in
[examples/ci/oxvara-gate.yml](examples/ci/oxvara-gate.yml).

## Why not just use your vendor's MCP export?

If your whole estate lives behind one gateway, use it. Oxvara is for
the estates that don't, and for the questions vendor features don't
answer:

| | Vendor-native MCP (Apigee, APIM, Kong, MuleSoft) | Oxvara |
| --- | --- | --- |
| Scope | That vendor's estate | All of them, one policy model |
| Inventory of agent-facing tools | Per vendor console | One table, JSON or CSV |
| Per-tool policy view | Varies; APIM applies policy per server | Per operation |
| CI gate on policy gaps | Not a built-in concept | `validate`, SARIF |
| Drift and tool-description pinning | No | `lock` + `drift` |
| Maturity | Shipping, supported products | Early prototype |

Sources and the wider landscape (including MCP gateways, a different
layer) are in [docs/LANDSCAPE.md](docs/LANDSCAPE.md).

## The gateway URL rule

Tools always call the gateway, never the backend. Apigee bundles and
Kong decK files name the backend but not the public host, so you supply
it as `PATH@https://host` (or `--gateway-url` for every input). Without
it the strict pack fails, and the `owasp-mcp` pack flags any tool that
would call the recorded backend directly, because that skips every
policy on the gateway.

## Input sources

**OpenAPI 3.x.** Governance comes from `x-oxvara` blocks: one at the
root for estate defaults, one per operation to override. See
`examples/petstore.yaml` and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Apigee.** An exported bundle (`apiproxy/` with `proxies/`, `targets/`,
`policies/`). Operations come from flow conditions; PreFlow policies
apply to every operation and flow steps override them. VerifyAPIKey and
OAuthV2 map to auth; Quota and SpikeArrest to rate limits. Disabled
policies are ignored. A Quota with only a `countRef` contributes no
limit rather than a wrong one.

**Azure APIM.** An export directory with `openapi.yaml`, `policy.xml`
and optional `operations/<operationId>/policy.xml`. `<inbound>`
`rate-limit`/`quota` (tightest wins), `check-header`,
`authentication-basic` and `validate-jwt` are read.

**Kong.** A decK state file (`_format_version: "3.0"`). Routes become
operations; regex paths with named captures become path parameters.
`key-auth`, `basic-auth`, `jwt`, `oauth2`, `openid-connect`,
`rate-limiting`, `rate-limiting-advanced` and `request-termination` are
read with Kong's precedence (route over service over global).

Whatever an importer cannot model faithfully (consumer-scoped plugins,
`hmac-auth`, routes without methods) is reported as an import note, not
guessed at.

## Commands

| Command | What it does |
| ------- | ------------ |
| `oxvara inventory <inputs...>` | One table of every agent-facing tool: source, method, auth, rate limit, writes. `--format json\|csv` |
| `oxvara validate [--pack P]... <inputs...>` | Run policy packs; exits non-zero on violations. `--format json\|sarif` |
| `oxvara lock <inputs...> -o oxvara.lock.json` | Record the reviewed tool surface |
| `oxvara drift --lock oxvara.lock.json <inputs...>` | Compare with the lock; `--fail-on error\|warning\|note`; `--format json\|sarif` |
| `oxvara inspect <inputs...>` | Operations and inherited policy, per input |
| `oxvara diff <inputs...>` | Dry run of the tools `compile` would produce |
| `oxvara compile <inputs...> -o server.py [--lock FILE]` | Generate the MCP server |

## Policy packs

- **`strict`**: a gateway URL, auth and a rate limit on every operation,
  no budget above 1000 requests/minute.
- **`owasp-mcp`**: rules mapped to the OWASP MCP Top 10 that configuration
  alone can answer: no API keys in query strings and no plain HTTP
  (MCP01), scoped auth on destructive operations (MCP02), auth on every
  write and no gateway bypass (MCP07). Full mapping in
  [docs/SECURITY.md](docs/SECURITY.md).

## Drift detection

`oxvara.lock.json` records, per tool: source, route, gateway URL, auth,
rate limit, timeout, and SHA-256 hashes of the description and input
schema the agent is shown. `oxvara drift` re-imports and compares:

- **error**: auth weakened, rate limit loosened or removed, tool
  retargeted or route changed
- **warning**: description or schema changed (how tool poisoning and
  "rug pull" updates land, OWASP MCP03), new tool exposed
- **note**: auth or rate limit tightened, tool removed, timeout changed

## Generated servers

Credentials always come from the environment:

| Kind | Env vars | Sent as |
| ---- | -------- | ------- |
| `apiKey` | `OXVARA_API_KEY` | Header (or query param) named by the policy |
| `bearer` | `OXVARA_BEARER_TOKEN` | `Authorization: Bearer <token>` |
| `basic` | `OXVARA_BASIC_CREDENTIALS` | `Authorization: Basic <base64(user:password)>` |
| `oauth2` | `OXVARA_OAUTH_TOKEN_URL`, `_CLIENT_ID`, `_CLIENT_SECRET` [+ `_SCOPE`, `_AUDIENCE`, `_RESOURCE`] | Client-credentials token, cached until expiry |
| `oauth2`, per user | the above + `OXVARA_OAUTH_SUBJECT_TOKEN` [+ `_SUBJECT_TOKEN_TYPE`] | RFC 8693 token exchange of the user's token, cached per subject |
| `oauth2`, pre-issued | `OXVARA_OAUTH_ACCESS_TOKEN` | A token already issued for the upstream |

Per the MCP authorization spec, the token an MCP client presents to the
server is never forwarded upstream.

Each tool also:

- calls the gateway URL, with path parameters percent-encoded,
- enforces the inherited rate limit client-side (the gateway enforces it again),
- carries MCP tool annotations derived from the HTTP method (hints, not controls),
- writes a JSON-lines audit record per call and response to
  `OXVARA_AUDIT_LOG` (default stderr), with secrets redacted and the
  end user from `OXVARA_AUDIT_SUBJECT`,
- returns upstream output labeled as untrusted and capped at
  `OXVARA_MAX_RESPONSE_CHARS`.

Spec-derived names and strings reach the generated code only as
sanitized identifiers and escaped literals, so compiling a hostile spec
cannot inject code into the server.

## Project status

**Working now:** OpenAPI, Apigee, Azure APIM and Kong importers;
multi-gateway merge; inventory; `strict` and `owasp-mcp` packs with
SARIF; lockfile and drift gate; generated MCP servers with OAuth2
(client credentials, RFC 8693 exchange), audit log, tool annotations
and injection-safe codegen; CI on Python 3.10 to 3.13.

**Not built yet:** MuleSoft and AWS API Gateway importers; live import
from gateway management APIs; remote (HTTP) MCP transport with RFC 9728
metadata; per-consumer/per-product policy; a shared rate budget across
replicas. See the roadmap in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check oxvara tests
```

## Contributing

Issues and pull requests are welcome. Keep the no-fake-it rule: if a
feature is not implemented, the code and docs say so.

## License

MIT. See [LICENSE](LICENSE).
