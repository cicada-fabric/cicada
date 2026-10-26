---
name: cicada-network
description: Use for Cicada current-Thread registration, Owner-enabled local collaboration, selecting authorized Groups, leaving, advanced Pair selection, and discovering or messaging authorized peers. Applies to $cicada-network and @cicada requests without treating those standard invocations as local operator commands.
---

# Cicada current Thread and authorized communication

Follow Host-required skill announcements. Handle routine requests directly in
the user's language, omitting unnecessary repeated announcements, procedural
steps or cryptographic details unless the user asks or they explain a failure.

The Hub retains shared authorization. The Cicada Windows App provides trusted
setup, account login and Owner approval; private Owner keys stay in local secure
storage. For the default local workflow, the Owner enables one named private
Network and dedicated Group for an exact Hub, Node and Node OS user in the App.
That policy lasts until revoke unless the Owner selects an expiry. Closing the
App, logging out or ending its account session does not end the policy.

Each original Thread still needs explicit registration; the default Linux flow
uses the separate system terminal described below.
Under an enabled local policy, the Node verifies the current Thread and derives
only its delegated registration, directory, send, ask and reply scope. This
default flow needs no separate Owner approval for each Thread or Pair slot.
Without that policy, registration alone grants zero communication rights. No
registration or local policy grants execution rights. Installing the plugin,
logging in or starting MCP does not register or authorize a Thread; current Hub
Guard remains authoritative for every business operation.

For Linux native Codex onboarding, ask the user to register the intended
conversation from a separate **system terminal**:

- `cicada join --thread ID --name NAME` registers that existing native Thread
  with a meaningful name, or explicitly brings its same registration back
  online after Leave, subject to current authorization checks.
- Under `OWNER_ENDPOINT_GROUPS_V1`, `cicada leave --thread ID` persists only a
  local offline state. It retains the native Thread and workspace, original
  SID, keys and binding, and every Owner-managed Group relation. A later Join
  restores that same registration and rechecks current authorization; it does
  not create another identity, automatically restore default Group G1 or
  replace unresolved original packets.

Use the actual native Thread ID exposed by the Host and quote argument values
for the user's shell. Never invent an ID, borrow a parent Thread or replace a
lost identity. The CLI must validate the selected Thread's native record,
workspace and Node OS user; a supplied ID alone is not identity proof. Do not
run this registration inside the model's active conversation tool call or
imitate Hook JSON. Unconfirmed results require the same command's original
recovery; an HTTP error is not evidence that an uncertain request failed.

The default plugin retains only the Cicada MCP `PreToolUse` Hook. It does not
intercept ordinary prompts or run registration through `UserPromptSubmit`.
Standard `$cicada-network` and `@cicada` invocations remain normal skill/model
workflows; ask/send/reply requests do not become local operator commands.

Older installations may explicitly retain the literal-message operator Hook
for compatibility. Only there, `cicada peers` is a private Node operator
snapshot, and the advanced Pair commands `cicada connect` and
`cicada connect "PAIR LABEL" A` list or select exact human Pair labels and A/B
slots. B must be chosen explicitly for the other Thread. Do not translate
these compatibility messages into external CLI commands or recommend them for
default registration. Pair keeps its strict native verification and separate
Owner consents; a local-domain context does not authorize a Pair Join. The
private operator directory is user feedback, not an MCP permission fallback.
Under the retained legacy local-domain profile, a later Join creates a new
admission without reviving the old member/binding or reassigning unresolved
original packets. That legacy rule does not apply to `OWNER_ENDPOINT_GROUPS_V1`.

Every managed MCP tool declares `_cicada_context`. Echo its connection nonce
exactly as declared by the current connection schema. The local trusted Hook
replaces the entire context with a fresh one-use Node ticket bound to the actual
runtime Thread, workspace, tool and business arguments. Never fabricate a ticket,
call `codex-hook` manually, borrow a parent Thread, set a static SID environment
variable or use a shared last-context file. Missing or unsupported runtime proof
must deny before restoring any cached Endpoint or invoking a business operation.
A lease renewal means lease evidence, not that the native Thread is online.

When the user wants to choose a peer, use `cicada_select_peer` to open the Host's
standard selection form. Set `scope` to `group` for the current joined Group, or
to `network` with an explicit already joined `network_id`. An optional `query`
narrows that authorized directory. The form can include peers on other Nodes;
only show names, workspaces and snapshot status that the caller may read.
The retained legacy `cicada peers` snapshot supplies no Thread directory rights.

An accepted form returns an opaque `peer_selection_id`. Preserve it exactly for
the intended `cicada_send` or `cicada_ask` call, without `target`, `network_id` or
`link_id`. Selection sends nothing and grants no authority. The later call needs
its own fresh runtime proof and current Guard approval. If the selection expires,
the binding changes or access is revoked, open a new form; never resolve a label
again or substitute another peer. Decline or cancel ends that selection attempt;
do not send afterward.
If the Host cannot display forms, report the explicit refusal without claiming
that a peer was selected. Do not invent a local slash command or a colored
composer mention. Standard skill/plugin invocation still uses the normal Host.

For an ordinary request to a named peer in the current Group, use
`cicada_resolve`. If it returns one authorized target, call `cicada_ask` directly
when an answer is expected, or `cicada_send` for a notification that needs no
response. For an explicitly selected authorized Network, use
`cicada_network_resolve` and the existing Network message route; preserve that
scope. Do not routinely call `cicada_whoami` or list the directory first. Every
call still requires fresh identity proof from the existing trusted Hook; never
cache or fabricate context.
If resolution is ambiguous, show permitted candidate addresses and use workspace,
Goal or Machine context to distinguish them; ask the user only if that context is
insufficient. MCP directory tools retain the current Endpoint's authorization;
they do not expose the Node operator inventory.

Advanced Network and Group joins remain separate from the default local policy.
Use an explicit target and existing private invitation/Owner-proof sources. A
model assertion is not Owner approval. Do not ask a basic-onboarding user to sign
JSON, install OpenSSL, use a browser or export an Owner key. Network renewal does
not add Group communication rights. Never print API credentials, tickets, private
proofs, transcripts, `.env` files or private workspace contents in reports or tool
arguments.

Use only tools and permissions advertised by the current connection. Under
`OWNER_ENDPOINT_GROUPS_V1`, the profile permits only its five communication
rights and current-Thread self-Group tools. Group/all-Group/Network Leave,
journals, discussions and Tasks below belong to legacy or advanced profiles;
never use them in place of the Owner's exact relation removal or the CLI's
local offline operation.

Use the Fabric tools directly when that profile advertises and authorizes them:

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

When asked to switch Groups, use the connection's current-Thread Group listing
tool if advertised. Match an authorized entry by name and pass its returned ID
directly to `cicada_use_group`; do not ask the user to copy IDs or JSON. If names
are ambiguous, show the permitted Group/Network labels and require an exact
choice. Listing and selection create no membership or key grant, and an App
Owner's list is not the calling Thread's permission. A pending authorization is
not an active selectable Group. Do not automatically select a newly added Group,
revive a removed Group or re-Join to repair a selection. If the connection lacks
this self-listing tool or has no active Groups, explain that state and retain
the original native registration and identity.

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

After a confirmed ask with no reply yet, say only “已发给 X，等待回复” or its
equivalent in the user's language. For a confirmed one-way send, say “已发给 X”.
When a correlated reply arrives, give its result directly; explain the association
only if the request or peer is unclear. `SENT`, queued or relay-persisted messages
do not establish reading, native consumption, a reply or task completion. Report
failures and uncertain outcomes plainly; never present them as success.

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
