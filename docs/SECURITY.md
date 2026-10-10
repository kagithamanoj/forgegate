# Security model

Oxvara sits between agents and production APIs, so its own failure
modes matter as much as the ones it checks for. This page maps what
Oxvara does against the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
(2025 edition, v0.1 at the time of writing) and states what it does not
cover.

## Coverage against the OWASP MCP Top 10

| OWASP item | What Oxvara does | Where |
| --- | --- | --- |
| MCP01 Token mismanagement and secret exposure | Credentials only from environment, never from specs or generated code. Audit log redacts secret-looking keys. `owasp-mcp` pack flags API keys in query strings and plain-HTTP gateway URLs. | `codegen.py`, `packs.py` |
| MCP02 Privilege escalation via scope creep | Flags destructive operations (PUT/PATCH/DELETE) guarded only by a shared static secret. RFC 8693 token exchange lets a tool act with a token scoped to the end user and the upstream audience instead of a shared service identity. Drift flags any auth downgrade. | `packs.py`, `lock.py`, `codegen.py` |
| MCP03 Tool poisoning | Lockfile pins a SHA-256 of every tool description and schema; `oxvara drift` fails when one changes or a tool appears, so a "rug pull" update is reviewed before agents see it. Upstream responses are labeled as untrusted data and size-capped. | `lock.py`, `codegen.py` |
| MCP04 Supply chain | Generated servers have three runtime dependencies (`mcp`, `requests`, stdlib). Compiling an untrusted spec cannot inject code: spec strings are emitted only as `repr()` literals and names are sanitized identifiers (tested with hostile input). | `codegen.py`, `tests/test_codegen.py` |
| MCP05 Command injection | Path parameters are percent-encoded, so `../admin` or `?x=` cannot change the request. No shell or eval anywhere in generated code. | `codegen.py` |
| MCP06 Intent flow subversion | Partial: responses are labeled untrusted. Oxvara cannot stop a model from following text it reads. |  |
| MCP07 Insufficient authentication and authorization | `strict` requires auth on every operation; `owasp-mcp` requires it on every write and catches tools that would call the backend directly and bypass the gateway. Tools always call the gateway. | `packs.py`, `inputs.py` |
| MCP08 Lack of audit and telemetry | Every tool call and response status is written as one JSON line with tool, source gateway and optional end-user subject. | `codegen.py` |
| MCP09 Shadow MCP servers | `oxvara inventory` lists every agent-facing tool across all gateways in one table, so exposure is known rather than discovered. Oxvara does not scan networks for servers it did not produce. | `cli.py` |
| MCP10 Context injection and over-sharing | Partial: response size cap. No field-level filtering or data classification yet. |  |

## MCP authorization spec alignment

- **No token passthrough.** The token an MCP client presents is never
  forwarded upstream. Upstream tokens are pre-issued for the upstream,
  obtained by RFC 8693 token exchange, or obtained with client
  credentials.
- **Audience binding.** Token exchange sends `audience` and `resource`
  when configured (`OXVARA_OAUTH_AUDIENCE`, `OXVARA_OAUTH_RESOURCE`), so
  the upstream token is bound to the upstream API.
- **Not yet built:** generated servers use stdio transport, so they do
  not act as OAuth protected resources (RFC 9728 metadata, 401 with
  `WWW-Authenticate`). A remote transport is on the roadmap.

## Honest limits

- Tool annotations (`readOnlyHint`, `destructiveHint`) are derived from
  HTTP methods. They are hints for clients, not controls; a POST that
  deletes data will be labeled non-destructive.
- The client-side rate limiter is per-process. The gateway is the real
  enforcement point, which is why tools always call it.
- Oxvara reads exported configuration. If what is deployed differs from
  the export, Oxvara checks the export.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a
public issue.
