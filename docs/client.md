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

Select **View detail** on any Goal to inspect its current conclusion, success
criteria, Worker states, key events, Artifacts, Workspaces, and external
actions. Detail data is loaded on demand from the existing Goal APIs, so the
overview stays compact while a long-running execution remains inspectable.

The Ask Cicada form accepts text, up to five files or images (8 MiB each), and
one reference link. Uploads are stored under Control's private state with
generated IDs; links are retained as references and are not fetched during
upload.

The web client is installable as a small PWA. Its service worker caches only
the embedded HTML/CSS/JavaScript and manifest; it never caches `/v1` responses,
attachments, bearer tokens, or other private state. Polling resumes when the
app returns online.

When `CICADA_API_TOKEN` protects Control, the HTML, CSS, and JavaScript remain
readable so the client can start. Open **Remote access**, paste the bearer
token, and select **Use for this tab**. The client keeps the token in
`sessionStorage`: it is removed when the tab closes and is never embedded in
the generated HTML or written to Control storage.

The embedded client uses separate HTML, CSS, and JavaScript source files with a
strict Content Security Policy. It has no package manager or asset build step.
This page covers the browser-based Goal overview, Approval UX, remote status,
attachments, and on-demand Goal detail slice of Personal Client. Push, voice,
and native mobile delivery remain future work.
