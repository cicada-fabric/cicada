# Information connectors

Control accepts provider-neutral Email, Calendar, Documents, X, WeChat, QQ, Slack, and Discord events
through dedicated HMAC-protected endpoints. The adapters run before
persistence, enforce a 1 MiB body limit, derive an idempotent external ID, and
retain only triage fields; provider envelopes, credentials, cookies, and
arbitrary headers are dropped.

Configure independent runtime secrets in the Control secret file:

```dotenv
CICADA_CONNECTOR_SECRET_EMAIL=independent-email-webhook-secret
CICADA_CONNECTOR_SECRET_CALENDAR=independent-calendar-webhook-secret
CICADA_CONNECTOR_SECRET_DOCUMENTS=independent-documents-webhook-secret
CICADA_CONNECTOR_SECRET_X=independent-x-webhook-secret
CICADA_CONNECTOR_SECRET_WECHAT=independent-wechat-webhook-secret
CICADA_CONNECTOR_SECRET_QQ=independent-qq-webhook-secret
CICADA_CONNECTOR_SECRET_SLACK=independent-slack-webhook-secret
CICADA_CONNECTOR_SECRET_DISCORD=independent-discord-webhook-secret
```

Sign the exact bytes sent by the provider with HMAC-SHA256 and send the result
as `X-Cicada-Signature: sha256=<hex>` to `/v1/connectors/email` or
`/v1/connectors/calendar` or `/v1/connectors/documents`. The Documents adapter
accepts a bounded JSON `data`/`document`/`file` wrapper, keeps the document ID,
title, text, URL, MIME type, owner, and update time, and normalizes
`document.created|updated|deleted` events. The social adapters use the same
signature header at
`/v1/connectors/x`, `/v1/connectors/wechat`, `/v1/connectors/qq`,
`/v1/connectors/slack`, and `/v1/connectors/discord`; they
accept direct provider events or a bounded `data`/`event` wrapper. Email accepts
`message_id` or `id` and keeps
sender, recipients, subject, plain text, thread, timestamp, and reply linkage.
Calendar accepts provider-neutral JSON (`id`/`uid`, `summary`, `start`, `end`)
or a bounded `VEVENT` with `UID`, `SUMMARY`, `DTSTART`, and `DTEND`.

Event statuses are `message.created|updated|deleted` and
`event.created|updated|cancelled`. The response is a durable
`ExternalEvent`; duplicate connector IDs return the original record. Use
`/v1/connectors/events/{id}/classify` for a bounded deterministic first pass,
or `/v1/connectors/events/{id}/triage` to explicitly classify, link, ignore,
or escalate an event to an Approval-backed action. Classification never links
an event to a Goal implicitly.

These adapters are ingress boundaries, not OAuth clients. Provider polling,
OAuth refresh, and reply delivery should run in an operator-owned connector
process and submit only signed events or separately approved external actions.

An authorized reply is requested through `/v1/connectors/replies`:

```json
{
  "goal_id": "GOAL_ID",
  "worker_id": "WORKER_ID",
  "connector": "x",
  "event_id": "EVENT_ID",
  "callback_url": "https://connector.example/reply",
  "text": "The benchmark result is ready."
}
```

The request creates an Approval-backed `ExternalAction` with `kind=reply`.
After approval, `POST /v1/actions/ACTION_ID/reply` sends the bounded normalized
JSON body to the callback with `X-Cicada-Signature` computed from the connector
secret and no provider credentials. The callback process owns OAuth or bot
tokens and is responsible for the provider API call.

Replies may use `email`, `calendar`, `telegram`, `x`, `wechat`, `qq`, `slack`,
or `discord` as the connector name. Slack and Discord callbacks remain
operator-owned adapters: Control signs the normalized body but never stores a
Slack bot token, Discord token, or provider cookie.
