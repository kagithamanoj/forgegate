# Oxvara architecture

Oxvara is a vendor-neutral governance layer for agent access to an API
estate. Apigee, Azure APIM and Kong each expose their own APIs as MCP
tools now, and each governs only its own estate. Oxvara reads all of
them, normalizes their policies into one model, and works from that
model: one inventory, one set of policy checks, one lockfile of the
reviewed agent-facing surface, drift detection against it, and an
optional compiled MCP server.

## The pipeline

```
 OpenAPI + x-oxvara   Apigee bundle   APIM export   Kong decK file
          \                 |              |              /
           +----------------+--------------+-------------+
                                  |
                       Ingest (parser, exporters/)
                                  |
                       Normalize (models.py): ApiEstate
                       per-endpoint policy, gateway URL, source
                                  |
        +-------------+-----------+------------+--------------+--------------+
        |             |                        |              |              |
    inventory      validate                lock / drift     compile    agentcore
   (cli.py)      (packs.py)                 (lock.py)     (codegen.py) (agentcore.py)
   one table     strict, owasp-mcp       reviewed surface  FastMCP server  Bedrock
                 text/json/SARIF         + change gate      (stdio)      targets
```

### 1. Ingest

| Source | Module | Reads |
| --- | --- | --- |
| OpenAPI 3.x | `oxvara/parser.py` | operations + `x-oxvara` policy blocks |
| Apigee | `oxvara/exporters/apigee.py` | proxy flows, PreFlow/flow steps, VerifyAPIKey, OAuthV2, Quota, SpikeArrest; skips `enabled="false"` policies |
| Amazon API Gateway (REST) | `oxvara/exporters/aws.py` | stage export (oas30 + apigateway extensions), `get-stage` method settings, usage plan throttle/quota/method throttles; API key, Cognito, Lambda and IAM (SigV4) authorizers |
| Amazon API Gateway (HTTP API, v2) | `oxvara/exporters/aws_v2.py` | `export-api` OAS30 export, `get-stage` DefaultRouteSettings and per-route RouteSettings; JWT, Lambda and IAM (SigV4) authorizers |
| Azure APIM | `oxvara/exporters/apim.py` | exported OpenAPI + `<inbound>` policy XML (rate-limit, quota, check-header, authentication-basic, validate-jwt) |
| Kong | `oxvara/exporters/kong.py` | decK services, routes, global/service/route plugins (key-auth, basic-auth, jwt, oauth2, openid-connect, rate-limiting, rate-limiting-advanced, request-termination) |

Anything an importer cannot model faithfully (consumer-scoped plugins,
`hmac-auth`, regex routes without named captures, routes with no
methods) is recorded as an import note and shown by every command,
instead of being guessed at.

### 2. The gateway URL rule

Gateway exports describe policy but often not the public host the API
is served on. Apigee bundles name the target backend; Kong services
name the upstream. Calling either directly would skip every policy the
importer just read. So tools always call the gateway:

- Apigee: `gateway URL + proxy BasePath`
- Kong: `gateway URL` (route paths are proxy paths)
- APIM: the gateway URL APIM writes into the exported `servers` entry
- AWS: the stage invoke URL from the export's `servers` entry (or a
  custom domain passed as the gateway URL)

The gateway URL is given per input as `PATH@https://host`, or for all
inputs with `--gateway-url`. Without it, the estate has no base URL,
the strict pack fails, and the `owasp-mcp` pack's
`MCP07-gateway-bypass` rule catches a base URL that points at the
recorded upstream.

### 3. Normalize and merge

Every importer produces an `ApiEstate` of `Endpoint`s, each with one
resolved `Policy` (auth, rate limit, timeout). Precedence follows each
gateway's own semantics: Apigee flow steps over PreFlow, APIM operation
policy over API policy, Kong route plugins over service over global.

Several inputs merge into one estate. Endpoints keep their own base URL
and a `source` label (`kong:orders`), and tool names are de-duplicated,
so one MCP server can front Apigee, APIM and Kong at once.

### 4. Policy packs (`oxvara/packs.py`)

- `strict`: gateway URL present; auth and a rate limit on every
  operation; no budget above 1000 requests/minute.
- `owasp-mcp`: checks from the OWASP MCP Top 10 (2025, v0.1) that
  configuration alone can answer. See [SECURITY.md](SECURITY.md).

`oxvara validate` runs one or more packs per input and prints text,
JSON or SARIF (for GitHub code scanning).

### 5. Lockfile and drift (`oxvara/lock.py`)

`oxvara lock` writes `oxvara.lock.json`: for every tool, its source,
route, gateway URL, auth, rate limit, timeout, and SHA-256 hashes of
the description and input schema the agent sees. It is deterministic so
it reviews cleanly in a pull request.

`oxvara drift` re-imports the estate and compares:

| Change | Severity |
| --- | --- |
| auth weakened (oauth2 -> apiKey, anything -> none) | error |
| rate limit loosened or removed | error |
| tool now calls a different base URL, or route changed | error |
| tool description or schema changed (tool poisoning, OWASP MCP03) | warning |
| new tool exposed | warning |
| auth tightened, rate limit tightened, tool removed, timeout changed | note |

`--fail-on` sets the threshold (default `warning`).

### 6. Compile (`oxvara/codegen.py`)

Emits one FastMCP tool per endpoint:

- Inputs come from path, query and header parameters and flattened JSON
  body properties. Spec-derived names become sanitized, non-shadowing
  Python identifiers; wire names stay as string keys.
- Every spec-derived string reaches the generated source only as a
  `repr()` literal, so a hostile spec cannot inject code.
- Tool annotations follow HTTP semantics (GET read-only, DELETE/PUT/PATCH
  destructive). They are hints for clients, not controls.
- Credentials come from the environment. OAuth2 supports a pre-issued
  upstream token, RFC 8693 token exchange of the end user's token, or
  the client-credentials grant. The token an MCP client presents to the
  server is never forwarded upstream (MCP authorization spec,
  2025-11-25: token passthrough is forbidden).
- The inherited rate limit is enforced client-side before a request
  leaves the process; the gateway enforces it again.
- Every call and response status is audited as JSON lines, with the
  end-user subject when configured.

## Annotation reference (OpenAPI input)

```yaml
x-oxvara:
  baseUrl: https://api.example.com/v1   # fallback: servers[0].url
  auth:
    kind: apiKey      # apiKey | bearer | basic | oauth2 | none
    name: X-API-Key   # header or query name for apiKey
    in: header        # header | query
  rateLimit:
    requests: 100
    per: minute       # second | minute | hour
  timeout: 30         # seconds
```

## Known limits

- The policy model holds one rate limit per operation (the lowest
  sustained rate wins). Burst and sustained limits are not modeled
  separately.
- Per-consumer and per-product policy (Apigee products, Kong consumer
  plugins, APIM subscriptions) is not modeled; it is reported.
- The generated server's rate limiter is per-process and in-memory.
- Generated servers use stdio transport; a remote (streamable HTTP)
  server with its own OAuth protected-resource metadata is not built.
- Kong `jwt` maps to a client-presented bearer token; Oxvara does not
  mint JWTs.
- MuleSoft `ip-allowlist`/`ip-blacklist`, header and CORS policies are
  reported, not modeled; a `client-id-enforcement` with several required
  headers models the first and reports the rest.

## Roadmap

1. Live import from gateway management APIs.
2. Remote MCP transport with RFC 9728 protected-resource metadata.
3. Shared rate budget store for multi-replica deployments.
4. Per-consumer / per-product policy in the model.
6. Response validation against OpenAPI response schemas.
