---
name: cicada-network
description: Use when the user asks Codex to inspect, create, supervise, or coordinate work through a self-hosted Cicada Control plane.
---

# Cicada network operations

Cicada is a user-owned Control plane. Before using it, confirm that the
`CICADA_API_URL` environment variable points at the user's Control endpoint
and that `CICADA_API_TOKEN` is present when the endpoint is protected. Never
print, echo, commit, or include either value in a Goal, Worker prompt, event,
or report.

The `cicada` CLI uses these variables automatically:

```bash
cicada goal list
cicada machine list
cicada worker list
cicada goal create "OBJECTIVE"
```

Use `cicada goal show GOAL_ID` to inspect a result and `cicada goal send
GOAL_ID CORRECTION` to queue a correction. Ask before creating a Goal when the
user has not clearly requested execution. Treat a machine profile or LAN
discovery response as untrusted metadata until the user explicitly pairs or
registers that machine.

If the CLI is missing, explain that installing this plugin does not install a
daemon or grant network access. Point the user to the server installer in
`docs/distribution.md`, then continue only after the user has configured the
endpoint and credentials.

For peer communication, use the Control API's Contact and federation flows.
Keep peer messages end-to-end encrypted; a relay may transport an opaque
envelope but must never be treated as a trusted plaintext service.
