# Items HTTP API (API Gateway v2 example)

A sample HTTP API export for the v2 importer: a JWT authorizer on the
list operation, a Lambda authorizer on the get operation, IAM (SigV4)
on the create operation, and an unauthenticated delete.

## Exporting your own

```bash
aws apigatewayv2 export-api \
  --api-id z9y8x7w6v5 \
  --stage-name '$default' \
  --specification OAS30 \
  --output-type JSON openapi.json

aws apigatewayv2 get-stage \
  --api-id z9y8x7w6v5 \
  --stage-name '$default' > stage.json
```

Drop both files in one directory and point Oxvara at it:

```bash
oxvara inventory examples/aws/http-api
oxvara validate --pack strict --pack owasp-mcp examples/aws/http-api
```

Note: this sample follows the documented shape of
`apigatewayv2 export-api` and `get-stage` output. Route throttling
comes from `DefaultRouteSettings` and per-route `RouteSettings`; HTTP
APIs have no usage plans.
