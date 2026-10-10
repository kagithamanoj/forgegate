# Example: MuleSoft Anypoint export

A managed API with its API Manager policies: client ID enforcement and
rate limiting on the whole API, JWT validation scoped to `POST /orders`,
an IP allowlist (reported, not modeled), and one made-up policy type to
show how unknown policies surface as import notes instead of guesses.

## Exporting from Anypoint

1. In Exchange, open the API version and download the spec as OAS 3.x.
   Save it here as `openapi.json` (or `openapi.yaml`).
2. In API Manager, open the API instance and list the applied policies
   with their configuration. Write them into `policies.json` as a list
   of `{"type", "config"}` objects. The `type` is the policy name,
   lowercased, with spaces and underscores as hyphens
   (`client-id-enforcement`, `rate-limiting`, `jwt-validation`,
   `ip-allowlist`, ...). A policy may carry optional `methods` and
   `paths` to scope it to some operations, as API Manager allows.
3. Point Oxvara at the directory and the gateway the API is served on:

```bash
oxvara inspect examples/mulesoft/orders-api@https://anypoint.example.com
```

Without the `@https://...` suffix Oxvara warns that it does not know
the gateway URL, and the spec's own `servers` URL is used instead.
