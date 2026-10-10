# Landscape

Research notes on where Oxvara fits, with sources. Checked October 2026;
vendor capabilities change quickly, so verify before quoting.

## Gateway vendors already expose APIs as MCP tools

| Vendor | What ships | Limits noted in their docs |
| --- | --- | --- |
| Google Apigee | MCP proxy from an OpenAPI 3.0.x spec; existing Apigee policies govern the tools | Not available for Apigee hybrid ([overview](https://docs.cloud.google.com/apigee/docs/api-platform/apigee-mcp/apigee-mcp-overview)) |
| Azure API Management | Any managed REST API can be exposed as an MCP server; each operation becomes a tool | Policies apply to all tools of an MCP server, not per tool; tools only (no resources or prompts); not in workspaces ([overview](https://learn.microsoft.com/azure/api-management/mcp-server-overview)) |
| Kong | Konnect autogenerates MCP servers from Kong-managed APIs; `deck file openapi2mcp` converts OpenAPI to an MCP route with `x-kong-mcp-acl` scopes | Autogeneration not available on-prem ([openapi2mcp](https://developer.konghq.com/deck/file/openapi2mcp/)) |
| AWS (Bedrock AgentCore Gateway) | Converts OpenAPI specs, Smithy models, Lambda functions and existing API Gateway REST APIs into MCP tools behind one gateway endpoint with an OAuth authorizer | Turns APIs into tools; does not check or pin the API Gateway policy (API keys, authorizers, usage plans) behind them ([docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html)) |
| MuleSoft | Anypoint converts an API or Mule app to an MCP server; MCP Connector | ([Salesforce announcement](https://developer.salesforce.com/blogs/2025/06/introducing-mcp-support-across-salesforce)) |

**Implication.** Turning one vendor's APIs into MCP tools is a feature
each vendor now ships. If your estate lives behind one gateway, use it.

## Most large estates run more than one gateway

- Postman's 2025 State of the API survey (5,700+ respondents): about 31%
  of organizations run more than one API gateway; 20% run two and 11%
  run three or more ([report](https://www.postman.com/state-of-api/2025/)).
- Gartner is cited as forecasting that more than 75% of organizations
  will use two or more API gateways by 2028, driven by hybrid estates,
  business-unit integrations and M&A. This figure was seen only through
  secondary coverage; confirm against Gartner before quoting.

No vendor governs the others' gateways. That gap is Oxvara's scope:
one inventory, one policy check, one drift gate across all of them.

## MCP gateways are a different layer

Runlayer, Lunar.dev MCPX, Obot, TrueFoundry and Microsoft's Agent 365
MCP gateway govern **MCP traffic**: which MCP servers agents may reach,
with identity, logging and policy at runtime
([Obot comparison](https://obot.ai/blog/the-13-best-mcp-gateways-for-enterprise-teams/),
[Lunar.dev](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026)).
Runlayer raised an $11M seed in November 2025
([TechCrunch](https://techcrunch.com/2025/11/17/mcp-ai-agent-security-startup-runlayer-launches-with-8-unicorns-11m-from-khoslas-keith-rabois-and-felicis)).

Oxvara works one layer down, on the **API gateway configuration** the
agent-facing tools are derived from: does the policy that will apply to
an agent's call meet the bar, and has it changed since it was reviewed?
The two are complementary; an MCP gateway can front servers Oxvara
compiles.

## Standards Oxvara tracks

- MCP authorization, 2025-11-25: no token passthrough, audience
  validation, RFC 8707 resource indicators, RFC 9728 protected-resource
  metadata ([spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)).
- OAuth 2.0 Token Exchange, RFC 8693: per-user delegation for upstream
  calls.
- OWASP MCP Top 10, 2025 v0.1 ([project](https://owasp.org/www-project-mcp-top-10/)).
- MCP tool annotations: `readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint` (hints, not guarantees).
- SARIF 2.1.0 for GitHub code scanning.
