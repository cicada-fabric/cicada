# Information connectors

Control accepts provider-neutral Email and Calendar events through dedicated
HMAC-protected endpoints. The adapters run before persistence, enforce a 1 MiB
body limit, derive an idempotent external ID, and retain only triage fields;
provider envelopes, credentials, cookies, and arbitrary headers are dropped.

Configure independent runtime secrets in the Control secret file:

```dotenv
CICADA_CONNECTOR_SECRET_EMAIL=independent-email-webhook-secret
CICADA_CONNECTOR_SECRET_CALENDAR=independent-calendar-webhook-secret
```

Sign the exact bytes sent by the provider with HMAC-SHA256 and send the result
as `X-Cicada-Signature: sha256=<hex>` to `/v1/connectors/email` or
`/v1/connectors/calendar`. Email accepts `message_id` or `id` and keeps
sender, recipients, subject, plain text, thread, timestamp, and reply linkage.
Calendar accepts provider-neutral JSON (`id`/`uid`, `summary`, `start`, `end`)
or a bounded `VEVENT` with `UID`, `SUMMARY`, `DTSTART`, and `DTEND`.

Event statuses are `message.created|updated|deleted` and
`event.created|updated|cancelled`. The response is a durable
`ExternalEvent`; duplicate connector IDs return the original record. Use
`/v1/connectors/events/{id}/triage` to classify, link, ignore, or escalate an
event to an Approval-backed action.

These adapters are ingress boundaries, not OAuth clients. Provider polling,
OAuth refresh, and reply delivery should run in an operator-owned connector
process and submit only signed events or separately approved external actions.
