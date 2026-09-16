# Telegram connector

The Telegram connector is a separate, restartable process. It long-polls the
Bot API, converts supported updates into a small provider-neutral payload, and
submits the exact JSON bytes to Control's signed connector ingress. Bot tokens
and HMAC secrets stay in the connector and Control environments; neither is
stored in an external event or passed to a Worker.

## Configure

Put these values in the mode-0600 runtime file at
`$CICADA_DATA_ROOT/secrets/cicada.env`:

```dotenv
CICADA_TELEGRAM_BOT_TOKEN=123456:replace-with-the-bot-token
CICADA_CONNECTOR_SECRET_TELEGRAM=replace-with-an-independent-random-secret
```

Control and the connector must receive the same
`CICADA_CONNECTOR_SECRET_TELEGRAM`. A connector-specific secret takes
precedence over `CICADA_WEBHOOK_SECRET`, so rotating Telegram access does not
affect another integration. Set `CICADA_API_TOKEN` in the same file when the
Control API requires bearer authentication.

Start the optional Compose role:

```bash
docker compose --profile telegram up -d telegram
docker compose logs -f telegram
```

For a process outside Compose:

```bash
cicada connector telegram \
  --control-url http://127.0.0.1:8787 \
  --offset-file /var/lib/cicada/telegram-offset
```

`CICADA_TELEGRAM_POLL_SECONDS` controls the long-poll timeout and
`CICADA_TELEGRAM_RETRY_SECONDS` controls the retry interval. An optional
`CICADA_TELEGRAM_GOAL_ID` links every received update to an existing Goal.

## Delivery and privacy behavior

- The Telegram `update_id` becomes the stable connector event key.
- The next update offset is written atomically with mode 0600 only after
  Control accepts a supported update. Restarts resume from that offset.
- Control also enforces uniqueness on `(connector, external_id)`, so a retry
  returns the existing event instead of creating duplicate work.
- Unsupported Telegram update kinds advance the offset but are not stored.
- The normalized payload contains message and chat identifiers, basic sender
  metadata, text or caption, and reply linkage. The raw provider envelope and
  bot token are not forwarded.
- Transport errors are redacted because Telegram places the bot token in the
  request URL.

The connector only receives information. Sending Telegram messages remains an
external action and must use the policy and Approval boundary before a future
reply executor receives credentials.

## Triage

New events start in `received`. A client or classifier can record
`classified`, `linked`, `ignored`, or `action_required` through the generic
triage endpoint:

```bash
curl -X POST http://127.0.0.1:8787/v1/connectors/events/EVENT_ID/triage \
  -H 'content-type: application/json' \
  -d '{"status":"linked","goal_id":"GOAL_ID"}'
```

`linked` requires an existing Goal. Linked triage creates a durable Goal audit
event. `action_required` also creates a P1 notification so the message appears
in the user's decision queue.
