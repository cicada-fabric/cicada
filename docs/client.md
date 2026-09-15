# Embedded personal client

The Control HTTP server serves a small client at `/`. It is embedded in the Go
binary, so the Docker image has no Node/npm build step and the page works
immediately after `docker compose up -d control`:

```text
http://127.0.0.1:8787/
```

The current 0.3.0 development page displays the local post-quantum identity,
unread notifications,
Goal status, worker count, and latest evidence summary. It can create a Goal
and acknowledge a notification. The page polls the JSON API every five
seconds; the API remains the stable boundary for a future TypeScript mobile or
desktop client.
