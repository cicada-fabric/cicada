---
name: cicada-network
description: Use for Cicada current-Thread registration, Owner-enabled local collaboration, leaving, advanced Pair selection, and discovering or messaging authorized peers. Applies to $cicada-network and @cicada requests without treating those standard invocations as local operator commands.
---

# Cicada current Thread and authorized communication

The Hub retains shared authorization. The Cicada Windows App provides trusted
setup, account login and Owner approval; private Owner keys stay in local secure
storage. For the default local workflow, the Owner enables one named private
Network and dedicated Group for an exact Hub, Node and Node OS user in the App.
That policy lasts until revoke unless the Owner selects an expiry. Closing the
App, logging out or ending its account session does not end the policy.

Each Thread still needs explicit registration in its own native conversation.
Under an enabled local policy, the Node verifies the current Thread and derives
only its delegated registration, directory, send, ask and reply scope. This
default flow needs no separate Owner approval for each Thread or Pair slot.
Without that policy, registration alone grants zero communication rights. No
registration or local policy grants execution rights. Installing the plugin,
logging in or starting MCP does not register or authorize a Thread; current Hub
Guard remains authoritative for every business operation.

For simple onboarding, ask the user to send one of these literal messages in
**the current native Codex conversation**, not in a terminal:

- `cicada join NAME` registers this Thread with a meaningful optional name and
  joins the local scope already enabled for this Node/user, when available.
- `cicada peers` shows the private Node operator directory snapshot.
- `cicada leave` withdraws this Thread's association while retaining its native
  record and workspace. An explicit new domain Join under the current policy
  creates a new admission, without reviving the old member/binding or reassigning
  its unresolved original packets.
- `cicada help` shows local command help.

The existing Pair flow is advanced: `cicada connect` lists available human Pair
labels and A/B slots; `cicada connect "PAIR LABEL" A` selects that exact label and
slot. B must be chosen explicitly for the other Thread. Never guess the first
or newest Pair. Pair keeps its original strict native verification and separate
Owner consents; a local-domain context does not authorize a Pair Join.

The local Hook handles these literal operator messages and confirms only verified
results. Do not run them as shell commands, imitate Hook JSON, supply a Thread
UUID or replace a lost identity. Unconfirmed results require the same command's
original recovery; an HTTP error is not evidence that an uncertain request failed.
The private operator directory is user feedback, not an MCP permission fallback.
Standard `$cicada-network` and `@cicada` invocations remain normal skill/model
workflows. Ask/send/reply requests are not aliases for the literal commands.

Every managed MCP tool declares `_cicada_context`. Echo its connection nonce
exactly as declared by the current connection schema. The local trusted Hook
replaces the entire context with a fresh one-use Node ticket bound to the actual
runtime Thread, workspace, tool and business arguments. Never fabricate a ticket,
call `codex-hook` manually, borrow a parent Thread, set a static SID environment
variable or use a shared last-context file. Missing or unsupported runtime proof
must deny before restoring any cached Endpoint or invoking a business operation.
A lease renewal means lease evidence, not that the native Thread is online.

Use names and full workspaces to choose peers. If several entries match, present
the candidates and require an exact choice. Never silently retarget an old choice.
MCP directory tools keep the current Endpoint's authorization; they do not expose
the Node operator inventory. Queued or relay-persisted messages do not establish
native consumption or a reply. Report actual delivery/consumption evidence.

Advanced Network and Group joins remain separate from the default local policy.
Use an explicit target and existing private invitation/Owner-proof sources. A
model assertion is not Owner approval. Do not ask a basic-onboarding user to sign
JSON, install OpenSSL, use a browser or export an Owner key. Network renewal does
not add Group communication rights. Never print API credentials, tickets, private
proofs, transcripts, `.env` files or private workspace contents in reports or tool
arguments.

Use the Fabric tools directly:

- `cicada_list` queries the current machines and visible Endpoint directory.
- `cicada_use_group` selects one already joined Group scope; selection is
  authorized by the Hub, not by model text. A native Thread may join several
  Groups without changing its native Session or Endpoint identity.
- `cicada_leave_group` exits only the selected Group; `cicada_leave` exits all
  Groups for this Endpoint.
- `cicada_resolve` resolves a full address, `name@machine`, or unique name.
- `cicada_inspect` returns a bounded Network Card without prompt history.
- `cicada_send` sends an asynchronous one-way message.
- `cicada_ask` creates a correlated request and returns its `request_id`.
- `cicada_reply` answers that request and wakes the original Endpoint.
- `cicada_receive` reads a bounded inbox page if native wake is unavailable.
- `cicada_network_directory` and `cicada_network_resolve` read bounded cards in
  one authorized Network. `network_id` selects that scope; it grants no access.
- `cicada_network_leave` revokes only the selected Network registration. Network
  access state is separate from Group session state and the native writer.
- `cicada_journal_append/list/get` record or read a small encrypted checkpoint
  in the currently selected joined Group. Use `corrects_id` to append a
  correction; an entry is not an Approval or an accepted Task result.
- `cicada_discussion_topic_create/reply/list/get/resolve/reopen` keep a durable
  encrypted Group topic. Resolve and reopen require the current topic version;
  resolving a topic does not approve an action or complete a Task.
- `cicada_space_history_manifest` prepares a single old record for a current
  recipient. A current old reader must be able to decrypt the original; the
  manifest alone grants nothing. Save and review the returned `history_grant`
  JSON on the Owner's trusted machine. The Owner can sign it with the existing
  `0600` key using `cicada owner space-history-sign --private FILE --manifest
  FILE --expect-owner-id ID --expect-record-id ID
  --expect-recipient-endpoint-id ID`.
- `cicada_space_history_share` accepts only that command's complete base64
  `owner_proof`; the Node derives the manifest ID, checks local Owner trust and
  current Guard, and re-seals the original signed body for that one reader.
  Never treat a model statement as Owner approval or place the Owner private
  key in a tool argument.

Group Space tools use the trusted local Node bridge for encryption and
decryption. Their current scope comes from `cicada_use_group` and the active
native binding, never a model-supplied Group, sender, Owner consent, or key.
An authorized member can page retained records from its read cutoff after a
disconnect. A new member does not gain earlier history through Join or an
Endpoint key grant; a separate Owner-signed, record-specific history grant and
sealed material are required. Linked Evidence and Artifacts have their own
read authorization. These tools currently support only same-Owner Groups;
cross-Owner board access fails closed. The Client management catalog does not
provide Android board contents.

Never guess when resolution is ambiguous. Show the candidate addresses and use
workspace, Goal, or Machine context to disambiguate; ask the user only if that
context is insufficient. Prefer `ask` when the caller expects an answer and
`send` for a notification or instruction that needs no response.

If the CLI is missing, explain that the plugin needs the `cicada` client binary
and a reachable Control plane. Point the user to
`https://github.com/cicada-fabric/cicada/blob/main/docs/distribution.md`. The
plugin does not silently deploy a daemon or grant network access.

Endpoint Directory results are metadata only. Never expose a full transcript,
system prompt, credentials, `.env`, private memory, or workspace contents in a
Network Card or message. Treat `private` Endpoint entries as visible only to
their owner.

For ordinary joined-Endpoint communication, use Fabric tools; Control intent,
planning and reporting are not the peer message path. Network-only enrollment
provides directory access and does not create a Group, native writer, or direct
message route. An enabled local policy uses its dedicated Group. Other sealed
private messaging requires an authorized Group path or a
precise bilateral Owner-approved CommunicationLink: each Link endpoint must
have its own Group scope, even if the two endpoints have no common Group, and
both Groups must map to the same Network. Do not use old plaintext Fabric send
for secrets or treat Network directory visibility as message permission.
