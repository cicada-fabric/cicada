# External actions

Control treats browser and internet access as an audited capability. A Worker
can request an action, but the request never carries credentials, cookies, or
arbitrary authorization headers:

```bash
curl -X POST http://127.0.0.1:8787/v1/actions \
  -H 'content-type: application/json' \
  -d '{"goal_id":"GOAL_ID","worker_id":"WORKER_ID","kind":"fetch","method":"GET","url":"https://example.com"}'
```

The request is queued behind the Goal's `external.fetch` policy. With no
explicit allow rule, it becomes a P1 Approval. After the Approval is accepted,
an isolated executor can claim it:

```bash
curl -X POST http://127.0.0.1:8787/v1/actions/ACTION_ID/execute
```

The built-in executor is deliberately narrow. It supports read-only `GET` and
`HEAD` actions of kind `fetch`, `search`, or `download`. It uses a 20 second
timeout, a 512 KiB response limit, normal TLS verification, no environment
proxy, and an allowlisted `Accept` header. Results contain the status code,
content type, a base64 body, a SHA-256 digest of the captured bytes, and a
truncation flag. The action and its result remain attached to the Goal event
history.

Every request validates the URL and resolves the destination before dialing.
Loopback, link-local, private, multicast, unspecified, and credential-bearing
targets are rejected. The dialer repeats the address check to reduce DNS
rebinding risk, and redirects are revalidated and cannot downgrade HTTPS.

`authenticated_browser`, `form_fill`, mutating HTTP methods, and
`external_api` requests remain queued for a separately isolated executor. The
Control plane does not store or forward their credentials, and it does not
claim that a public fetch is a browser session.
