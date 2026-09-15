# Intent routing

The Control boundary accepts natural input without forcing every sentence to
become an executing Goal. `POST /v1/intents` records the input first, then
routes it to a typed Cicada object or returns a durable clarification request.

```bash
curl -X POST http://127.0.0.1:8787/v1/intents \
  -H 'content-type: application/json' \
  -d '{"text":"比较两种缓存策略","kind":"research"}'
```

The response is an `Intent` with `status` set to `resolved`, `needs_input`, or
`failed`. A resolved response contains a small `result` object with the created
`goal_id`, `idea_id`, `command_id`, or `approval_id`. Every input can be read
again with `GET /v1/intents/ID`; `GET /v1/intents?status=needs_input` lists
pending clarifications.

Supported kinds are:

- `goal`: create an executing Goal from `text` and optional nested `goal`
  metadata;
- `idea`: capture an Idea without creating a Worker;
- `research`: capture an Idea and start a research-only Goal;
- `question`: start a read-only Goal that answers the question and records
  evidence;
- `command`: enqueue `text` for the Goal named by `target_id`;
- `approval`: resolve the Approval named by `target_id` using an explicit
  `decision`.

`kind=auto` is the default. It recognizes explicit prefixes such as
`idea:`, `research:`, `question:`, and `command:` (including their Chinese
forms), recognizes a trailing question mark, and treats other input as a Goal.
It never infers an Approval from ordinary language. Commands without a
`target_id`, approvals without an explicit `kind`, and approvals without a
decision become `needs_input` rather than causing a side effect.

The first router is intentionally deterministic and auditable. It provides a
stable boundary for a future gpt-5.5 planner while keeping high-impact actions
behind explicit typed input and the existing Control policy checks.
