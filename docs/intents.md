# Control Intent routing

Current Clients submit user management input through encrypted `intent.submit`
and inspect durable progress through `intent.status`; manager-authorized result
reads use `goal.result` where supported. The current catalog marks Intent
operations as resident-manager boundaries, not permissions for every enrolled
Owner. Public availability never replaces encrypted session authority and Guard.
See the [catalog](../cicada-go/internal/clientcontract/catalog.json),
[wire contract](client-hub-wire-v1.md) and
[Client development boundary](client-hub-development.md) for exact fields,
operation identity and recovery semantics.

Control can distinguish goals, ideas, research, questions, commands and explicit
approval actions. Acceptance does not prove task completion. Model text cannot
create an approval; high-impact actions still require the exact policy and user
authorization. Ordinary peer messages do not invoke Control intent planning.

The older `/v1/intents` implementation is a legacy plaintext Manager API. It is
not a current Client integration recipe: the production HTTP boundary disables
legacy management when no `CICADA_API_TOKEN` is configured, and authenticates it
when deliberately configured. The lightweight Hub deployment does not enable
that bearer or bundle a Codex planner/provider key. Old anonymous curl examples
and a fixed gpt-5.5 deployment claim have been removed; their history remains in
Git. Optional planner configuration must be reviewed against actual source and
Runtime evidence rather than an old document's model pin.

Retain original encrypted requests/counters when recovering uncertain outcomes;
transport recovery does not authorize replaying an uncertain business action.
See [current acceptance limits](v01-current-closeout-20261009-validation.md).
