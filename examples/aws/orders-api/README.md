# Example: Amazon API Gateway export

Made-up IDs. A real export of one REST API stage looks like this:

```bash
aws apigateway get-export --rest-api-id <id> --stage-name prod \
  --export-type oas30 --parameters extensions=apigateway openapi.json
aws apigateway get-stage --rest-api-id <id> --stage-name prod > stage.json
aws apigateway get-usage-plans > usage-plans.json
```

```bash
oxvara inspect examples/aws/orders-api
```
