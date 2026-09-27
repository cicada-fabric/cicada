# Existing embedded browser client (legacy management UI)

This page documents the existing Hub-hosted browser/PWA interface. **CICADA
Client v1 is a separate Android app** in `../CICADA_CLIENT`; its required
Control/Hub boundary is [Android Client ↔ Hub](android-client-hub-contract.md).
The embedded page and bearer/sessionStorage path do not provide the required
NIST post-quantum application-layer Android↔Control E2EE. They are not the
Android production authentication or encryption design.

The Control HTTP server serves a small client at `/`. It is embedded in the Go
binary, so the Docker image has no Node/npm build step and the page works
immediately after `docker compose up -d control`:

```text
http://127.0.0.1:8787/
```

The current 0.4.0 development page provides a responsive Today view with
running, approval, and completed counts. It displays the local post-quantum
identity, Goal status and workers, latest result summaries, unread prioritized
notifications, pending approval requests, and live Fabric Endpoint Network
Cards with address, role, harness, Machine, capabilities, and liveness. It can
create a Goal, approve or deny a request, and acknowledge a notification. The
page polls the legacy JSON API every five seconds. Android v1 requires a
separate authenticated, NIST PQ encrypted Client↔Control contract.

The current worktree also has read-only Group/Task/representative-request
views. It does **not** yet have the v2.1 graph editor. The target panel shows
all of the owner's verified Nodes and one card per real Thread/Endpoint, plus
external Endpoint Cards shared by other users with permission. Users can
drag Threads into several Groups, nest Groups, attach optional Monitors, and
draw scoped communication links. Those gestures must submit versioned,
authorized state changes; a cross-user link needs the other user's consent.
The panel must support a scoped Group broadcast by a Thread or a user-authorized
Monitor, showing the per-recipient delivery outcome. Parent/child Group layout
must never imply inherited access. A Hub-hosted page cannot decrypt peer
content merely because it draws the topology; any future message preview needs
client/Endpoint-held keys and a reviewed security design.

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
encrypted VAPID browser Push delivery. This browser/PWA is a legacy management
surface, not Android v1. Android has an optional user-installed on-device
speech-to-text model and an always-available text path; real Hub operations
remain gated on a verified Client↔Control PQ channel.

Goal detail also provides **View raw output** for each Worker. This reads a
bounded response file through the authenticated `/v1/workers/{id}/log` route;
Control accepts only paths under its configured workspace or state roots and
marks output over 512 KiB as truncated.
