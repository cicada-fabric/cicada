# Client notifications

Control emits durable notifications for the moments where a personal client
should interrupt the user: approval requests (`P1`), monitor stalls (`P1`),
blocked goals (`P0`), completed goals (`P2`), and incoming peer messages
(`P2`). The event log remains the detailed audit stream; notifications carry
the concise action or result a client should show first.

Clients that need live Goal progress can subscribe to the authenticated
Server-Sent Events endpoint. It replays durable events after an optional
numeric offset and emits keep-alive comments while waiting:

```bash
curl -N http://127.0.0.1:8787/v1/goals/GOAL_ID/events/stream?after=0
```

When `CICADA_API_TOKEN` is set, send the bearer token in the request header.
The embedded browser client uses EventSource for live local Goals and keeps its
polling fallback for authenticated remote sessions because the native
`EventSource` API cannot set an Authorization header; it never places a token
in the stream URL.

```bash
# The default is unread-only; pass unread=false for history.
curl http://127.0.0.1:8787/v1/notifications
curl 'http://127.0.0.1:8787/v1/notifications?unread=false'

# A client acknowledges one item after displaying it.
curl -X POST http://127.0.0.1:8787/v1/notifications/NOTIFICATION_ID/read
```

Notifications are stored in the same SQLite state as Goals and survive a
Control restart. They never contain peer plaintext or private E2EE key data.

## Browser push

The embedded Personal Client can register a browser Push subscription. Configure
VAPID credentials in the Control environment first:

```bash
go run ./cmd/cicada push-vapid-keys # prints a public/private pair
# set CICADA_PUSH_VAPID_PUBLIC_KEY, CICADA_PUSH_VAPID_PRIVATE_KEY, and
# CICADA_PUSH_VAPID_SUBJECT (for example, mailto:owner@example.com)
```

After the client has an authenticated session, open **Remote access** and
choose **Enable push notifications**. Control stores only the subscription
endpoint and its public encryption keys. P0, P1, and P2 notifications are
encrypted with Web Push and delivered to registered browsers; P3 timeline
events stay in the durable event stream. A push service response of 404 or 410
automatically removes the stale subscription.

The public VAPID key is available at `GET /v1/notifications/push/config`.
Subscriptions are registered with `POST /v1/notifications/push/subscriptions`
and removed with `DELETE /v1/notifications/push/subscriptions/SUBSCRIPTION_ID`.
