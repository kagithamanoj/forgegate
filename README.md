# Oxvara

**Every gateway secures its own MCP. Nobody governs all of them.**

Apigee, Azure APIM, Kong, AWS (Bedrock AgentCore Gateway) and MuleSoft
each turn APIs into MCP tools now.
But about a third of organizations already run more than one API
gateway ([Postman, 2025](https://www.postman.com/state-of-api/2025/)),
and no vendor will govern the others.

Oxvara is a vendor-neutral governance layer for agent access to your
API estate. It reads the gateway configuration you already have, from
any of them, and gives you:

- **One inventory** of every agent-facing tool across Amazon API Gateway,
  Apigee, Azure APIM, Kong and MuleSoft, and across accounts and stages.
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

# Each input is an OpenAPI file, an AWS API Gateway export, an Apigee
# bundle, an APIM export, a Kong decK file or a MuleSoft Anypoint export.
# Append @https://host for the gateway it is served on.
APIGEE="examples/apigee@https://apigee.example.com"
APIM="examples/apim"
AWS="examples/aws/orders-api"
KONG="examples/kong/kong.yaml@https://kong.example.com"
MULESOFT="examples/mulesoft/orders-api@https://anypoint.example.com"

# one table across all five gateways
oxvara inventory $AWS $APIGEE $APIM $KONG $MULESOFT

# policy check: strict + OWASP MCP rules (add --format sarif for code scanning)
oxvara validate --pack strict --pack owasp-mcp $AWS $APIGEE $APIM $KONG $MULESOFT

# record the reviewed tool surface, then gate changes against it
oxvara lock $AWS $APIGEE $APIM $KONG $MULESOFT -o oxvara.lock.json
oxvara drift --lock oxvara.lock.json $AWS $APIGEE $APIM $KONG $MULESOFT

# optional: compile one MCP server that fronts all of them
oxvara compile $AWS $APIGEE $APIM $KONG $MULESOFT -o server.py
```

A ready-to-copy GitHub Actions gate is in
[examples/ci/oxvara-gate.yml](examples/ci/oxvara-gate.yml).

## On AWS: Oxvara and AgentCore Gateway

Amazon Bedrock AgentCore Gateway turns OpenAPI specs, Lambda functions
and API Gateway REST APIs into MCP tools. Oxvara works alongside it, on
the API Gateway configuration those tools depend on:

- **Inventory** every agent-reachable API Gateway method across APIs,
  stages and accounts, in one table.
- **Validate** that each one has an API key, Cognito or Lambda
  authorizer, and a throttle or usage plan before agents can reach it.
- **Lock and drift-gate** it, so "API key required" switched off or a
  usage plan loosened fails CI instead of reaching production quietly.

AgentCore makes your APIs callable by agents; Oxvara proves the policy
behind them is right and stays right.

## Why not just use your vendor's MCP export?

If your whole estate lives behind one gateway, use it. Oxvara is for
the estates that don't, and for the questions vendor features don't
answer:

| | Vendor-native MCP (AgentCore Gateway, Apigee, APIM, Kong, MuleSoft) | Oxvara |
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

**Amazon API Gateway (REST).** A directory with the stage export
(`aws apigateway get-export --export-type oas30 --parameters
extensions=apigateway`), plus `stage.json` (`get-stage`) and
`usage-plans.json` (`get-usage-plans`), since throttling does not travel
with the export. API-key requirements, Cognito user pool and Lambda
authorizers map to auth, with OpenAPI semantics (alternatives: weakest
wins; schemes in one requirement: strongest wins). Rate limits are the
tightest of stage default, stage method settings, usage plan throttle
and quota, and usage plan method throttles. IAM methods are modeled as
SigV4 and signed in generated servers. Tools call the stage invoke URL;
integration URIs are kept as the upstream so a gateway bypass is caught.
See `examples/aws/`.

**Amazon API Gateway (HTTP API, v2).** A directory with the export
(`aws apigatewayv2 export-api --specification OAS30`), plus `stage.json`
(`get-stage`) for throttling. JWT authorizers map to oauth2, Lambda
authorizers to bearer, IAM to SigV4. Throttling comes from
`DefaultRouteSettings` and per-route `RouteSettings`. See
`examples/aws/http-api/`.

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

**MuleSoft.** An Anypoint export directory: the API spec
(`openapi.json`/`openapi.yaml` from Exchange) plus `policies.json`
listing the applied API Manager policies as `{"type", "config"}`.
`client-id-enforcement` maps to apiKey, `rate-limiting` to a rate
limit, `jwt-validation` to bearer, `basic-authentication` to basic and
`oauth2` to oauth2. Policies apply API-wide unless scoped with
`methods`/`paths`; where several apply, the strongest auth and the
tightest rate limit win. IP allowlists and anything unrecognized are
reported as import notes, not guessed at. See
`examples/mulesoft/orders-api/`.

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
| `oxvara collect-aws --accounts IDS --regions REGIONS --role NAME -o DIR` | Collect API Gateway estates across AWS accounts and regions via STS assume-role; writes the aws.py directory layout |
| `oxvara agentcore-targets <inputs...> -o targets.json [--gateway-id ID]` | Emit Bedrock AgentCore Gateway targets for operations that pass the strict pack |

## AgentCore Gateway targets

After `oxvara validate` passes, `oxvara agentcore-targets` turns the
governed operations into Bedrock AgentCore Gateway target definitions,
one per input estate. Each target carries an OpenAPI 3.x document for
exactly the operations that passed the strict pack, plus the outbound
auth mapping AgentCore needs:

```bash
oxvara agentcore-targets examples/aws/orders-api -o targets.json \
  --gateway-id gw-abc123
```

The output follows the `CreateGatewayTarget` shape: `targetConfiguration`
with the spec as `inlinePayload`, and `credentialProviderConfigurations`
mapping Oxvara auth kinds to AgentCore types (apiKey to `API_KEY`,
bearer/basic to `API_KEY` with the Authorization header and prefix,
oauth2 to `OAUTH`). Two values must come from your AWS account before
the target can be registered, and the output marks them: the
`gatewayIdentifier`, and each credential provider's `providerArn`
(create the providers in AgentCore Identity first). Operations that fail
validation are listed under `skipped`, never silently dropped.

## Collecting from live AWS

`oxvara collect-aws` reads REST APIs through the live API Gateway APIs
across an AWS Organization and writes them in the layout the AWS importer
reads, so one inventory and drift gate can cover the whole org:

```bash
pip install "oxvara[aws]"  # boto3, only needed for live collection

oxvara collect-aws \
  --accounts 123456789012,210987654321 \
  --regions us-east-1,us-west-2 \
  --role OxvaraCollector \
  -o collected/

oxvara inventory collected/*/*/*/
```

The command assumes the named IAM role in each account via STS, then for
each region lists REST APIs, exports each stage as OpenAPI, and reads the
stage and usage plans. APIs that fail to export are reported as notes,
never silently skipped. AWS API throttling is retried with exponential
backoff.

IAM permissions required. On your own credentials: `sts:AssumeRole` for
the role in each target account. On the assumed role in each account:

- `apigateway:GetRestApis`
- `apigateway:GetStages`
- `apigateway:GetStage`
- `apigateway:GetExport`
- `apigateway:GetUsagePlans`

> Note: live-AWS collection has not been tested against real AWS APIs yet.
> It was built and verified with mocked boto3 clients only. If you run it
> against a real org, please report what you find.

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
| `sigv4` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` [+ `AWS_SESSION_TOKEN`, `AWS_REGION`] | AWS SigV4-signed request to API Gateway (region parsed from the invoke URL when unset) |

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

**Working now:** OpenAPI, Amazon API Gateway, Apigee, Azure APIM, Kong and
MuleSoft importers; multi-gateway merge; inventory; `strict` and
`owasp-mcp` packs with SARIF; lockfile and drift gate; generated MCP
servers with OAuth2 (client credentials, RFC 8693 exchange), audit log,
tool annotations and injection-safe codegen; CI on Python 3.10 to 3.13.

**Not built yet:** live import from gateway management APIs; remote (HTTP) MCP transport with RFC 9728
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
