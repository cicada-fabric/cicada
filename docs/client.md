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

On browsers that expose `SpeechRecognition`, **Speak** adds a dictated intent
to the same text field. Audio is handled by the browser's speech implementation
and is never uploaded to Control as an attachment; browser vendors may apply
their own local or remote speech-processing policy. Notifications also offer a
user-triggered **Read aloud** action backed by the browser's `speechSynthesis`
API, so Cicada never starts audio without an explicit gesture. Browsers without
these APIs keep the text form and visual notification list fully usable.

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
attachments, on-demand Goal detail slice, browser speech input/output, and
encrypted VAPID browser Push delivery. A browser/PWA is the current mobile
client; a separately packaged native mobile client and fully model-local voice
pipeline remain future work.

Goal detail also provides **View raw output** for each Worker. This reads a
bounded response file through the authenticated `/v1/workers/{id}/log` route;
Control accepts only paths under its configured workspace or state roots and
marks output over 512 KiB as truncated.
