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

## Isolated browser agent

The repository includes a small external agent for browser actions. It claims
only `browser`, `authenticated_browser`, and `form_fill` actions, then starts
an operator-supplied runner as a separate process:

```bash
export CICADA_BROWSER_EXECUTOR_BIN=/opt/cicada/bin/browser-runner
export CICADA_BROWSER_PROFILE_DIR=/var/lib/cicada/browser-profile
cicada external agent --control-url http://127.0.0.1:8787
```

Use `--once` for a single poll, which is convenient for a supervised service
or a smoke test. The runner path must be absolute. A browser profile is
required for authenticated browser and form-fill actions and is never stored
in an action payload.

The runner receives one JSON object on stdin and must write exactly one JSON
value to stdout. The request contains `action_id`, `kind`, `method`, `url`,
`payload`, and (when configured) `profile_dir`; it has no cookie, token,
credential, or authorization-header field. The payload has already passed
Control's secret-field validation. The agent gives the child a temporary
`HOME` (or the explicitly configured profile), an allowlisted locale/display
environment, and no API, proxy, Control, or model secrets. It does not invoke
a shell and kills the whole process group on timeout. Runner output is capped
at 1 MiB and must be valid JSON before it is sent to `/complete`.

The agent does not install or select a browser implementation. Operators can
wrap Chromium, Playwright, or another audited runtime behind the stdin/stdout
contract and keep its cookies and login state in the isolated profile. Claim,
completion, failure, and approval transitions remain durable Control events.
