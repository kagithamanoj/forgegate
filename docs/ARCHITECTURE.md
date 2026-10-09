# Oxvara architecture

Oxvara is a compiler. It takes the API estate you already govern and
emits MCP servers your agents can call, with the governance carried
over instead of re-entered.

## The pipeline

```
OpenAPI 3.x + x-oxvara annotations
        |
        v
   +---------+      +----------------+
   | Ingest  | ---> | Normalize      |
   | (parser)|      | (policy merge) |
   +---------+      +----------------+
                           |
                           v
                    +--------------+
                    | Generate     |
                    | (codegen)    |
                    +--------------+
                           |
                           v
              runnable MCP server module
              (FastMCP, stdio transport)
```

### 1. Ingest (`oxvara/parser.py`)

Reads an OpenAPI 3.x document (YAML or JSON) and walks every path and
operation. It records the HTTP method, path template, parameters,
request body shape, and the raw `x-oxvara` extension blocks. Anything
outside OpenAPI 3.x is rejected with a clear error.

### 2. Normalize (`oxvara/models.py`)

The parser output is converted into a small internal model: `ApiEstate`,
`Endpoint`, `Parameter`, `BodyProperty`, and `Policy`. The code generator
only sees this model, so adding a new input format (an Apigee export, an
Azure APIM export) means writing a new parser, not touching the
generator.

### 3. Policy inheritance

This is the core idea. A root-level `x-oxvara` block declares the
estate defaults: base URL, auth scheme, rate limit, timeout. An operation
may carry its own `x-oxvara` block that overrides individual fields.
Anything not overridden is inherited.

```
estate defaults (x-oxvara at root)
  auth: apiKey / X-API-Key
  rateLimit: 100/minute
  timeout: 30s
        |
        +-- GET /pets            (inherits everything)
        +-- POST /pets           (overrides rateLimit: 10/minute)
        +-- GET /pets/{petId}    (inherits everything)
```

The merge rule is simple and explicit: an operation-level value wins
when present, otherwise the estate default applies. `Policy.merge()`
implements this, and the parser tests pin the behavior.

### 4. Generate (`oxvara/codegen.py`)

For each endpoint the generator emits one MCP tool function:

- The function signature comes from path parameters (required), query
  parameters (optional), and flattened request body properties.
- The docstring carries the operation summary plus the inherited policy,
  so the agent sees the governance in the tool description.
- The body injects auth credentials from environment variables
  (`OXVARA_API_KEY`, `OXVARA_BEARER_TOKEN`), substitutes path
  parameters into the URL, and enforces the inherited rate limit with a
  client-side token bucket before any request leaves the process.

The emitted module header records the Oxvara version and the source
spec, so a generated server is always traceable back to what produced
it. Generated files are meant to be regenerated, not hand-edited.

## Annotation reference

```yaml
x-oxvara:
  baseUrl: https://api.example.com/v1   # fallback: servers[0].url
  auth:
    kind: apiKey      # apiKey | bearer | oauth2 | none
    name: X-API-Key   # header or query name for apiKey
    in: header        # header | query
  rateLimit:
    requests: 100
    per: minute       # second | minute | hour
  timeout: 30         # seconds
```

OAuth2 is recognized by the parser but the generated server raises
`NotImplementedError` for it: token acquisition against an enterprise
identity provider is real work and the prototype does not fake it.

## What this prototype does not do yet

- No Kong exporter yet. Apigee and Azure APIM exporters are built and
  tested (see `oxvara/exporters/`).
- No response schema validation and no retry logic in generated servers.
- The rate limiter is per-process and in-memory. A shared budget store
  is on the roadmap.
- Request bodies that are not flat JSON objects are passed through as a
  raw JSON string.

## Roadmap

1. ~~Apigee X and Azure APIM exporters~~ Done.
2. ~~Policy packs~~ Done (`strict` ships; more packs to come, for
   example per-team budgets and data-classification rules).
3. ~~Dry-run and diff mode~~ Done (`oxvara diff`, `oxvara validate`).
4. Kong exporter: the third major gateway.
5. Shared rate budget store (Redis) for multi-replica deployments.
6. Response validation against the OpenAPI response schemas.
