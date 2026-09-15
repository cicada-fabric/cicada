# Embedded personal client

The Control HTTP server serves a small client at `/`. It is embedded in the Go
binary, so the Docker image has no Node/npm build step and the page works
immediately after `docker compose up -d control`:

```text
http://127.0.0.1:8787/
```

The current 0.3.0 development page provides a responsive Today view with
running, approval, and completed counts. It displays the local post-quantum
identity, Goal status and workers, latest result summaries, unread prioritized
notifications, and pending approval requests. It can create a Goal, approve or
deny a request, and acknowledge a notification. The page polls the JSON API
every five seconds; the API remains the stable boundary for a future mobile or
desktop client.

When `CICADA_API_TOKEN` protects Control, the HTML, CSS, and JavaScript remain
readable so the client can start. Open **Remote access**, paste the bearer
token, and select **Use for this tab**. The client keeps the token in
`sessionStorage`: it is removed when the tab closes and is never embedded in
the generated HTML or written to Control storage.

The embedded client uses separate HTML, CSS, and JavaScript source files with a
strict Content Security Policy. It has no package manager or asset build step.
This page covers the browser-based Goal overview, Approval UX, and remote
status slice of Personal Client. Push, voice, native mobile delivery, file and
image input, and detailed Goal graph/log views remain future work.
