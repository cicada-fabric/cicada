# Client notifications

Control emits durable notifications for the moments where a personal client
should interrupt the user: approval requests (`P1`), monitor stalls (`P1`),
blocked goals (`P0`), completed goals (`P2`), and incoming peer messages
(`P2`). The event log remains the detailed audit stream; notifications carry
the concise action or result a client should show first.

```bash
# The default is unread-only; pass unread=false for history.
curl http://127.0.0.1:8787/v1/notifications
curl 'http://127.0.0.1:8787/v1/notifications?unread=false'

# A client acknowledges one item after displaying it.
curl -X POST http://127.0.0.1:8787/v1/notifications/NOTIFICATION_ID/read
```

Notifications are stored in the same SQLite state as Goals and survive a
Control restart. They never contain peer plaintext or private E2EE key data.
