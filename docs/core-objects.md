# Core object APIs

The Go control plane now persists the objects that sit around a long-running
Goal. SQLite migrations are additive, so upgrading an existing pre-0.2 state
directory preserves its workers and event history.

Ideas are intentionally separate from Goals. Create one without starting a
worker, keep it `parked` with a `rationale` and `revisit_when` condition, or
promote it when it is ready:

```bash
curl -X POST http://127.0.0.1:8787/v1/ideas \
  -H 'content-type: application/json' \
  -d '{"title":"Benchmark idea","description":"Compare two kernel strategies","status":"parked","revisit_when":"after the current release"}'

curl -X POST http://127.0.0.1:8787/v1/ideas/IDEA_ID/promote \
  -H 'content-type: application/json' \
  -d '{"success_criteria":"Record a reproducible comparison"}'
```

Research is a separate action and carries an explicit no-execution constraint
into the temporary Goal:

```bash
curl -X POST http://127.0.0.1:8787/v1/ideas/IDEA_ID/research
```

Every Goal creates a registered Workspace. The workspace registry records its
path, source, revision, and lifecycle status; `GET /v1/workspaces?goal_id=...`
lists the workspaces associated with a Goal, and `PATCH /v1/workspaces/ID`
updates a snapshot or migration revision after an executor performs it.

The lifecycle actions are explicit and auditable. `snapshot` records the Git
revision when the path is a repository, `migrate` copies a workspace inside
the configured workspace root and updates its path, `archive` marks it
inactive without deleting files, and `resume` recreates the directory and
marks it active:

```bash
curl -X POST http://127.0.0.1:8787/v1/workspaces/WORKSPACE_ID/actions \
  -H 'content-type: application/json' \
  -d '{"action":"snapshot"}'
curl -X POST http://127.0.0.1:8787/v1/workspaces/WORKSPACE_ID/actions \
  -H 'content-type: application/json' \
  -d '{"action":"migrate","target_path":"/workspace/migrated"}'
```

Memory entries have one of the CICADA scopes (`personal`, `project`,
`execution`, or `idea`) and an optional namespace. They are durable context,
not hidden prompt text:

```bash
curl -X POST http://127.0.0.1:8787/v1/memories \
  -H 'content-type: application/json' \
  -d '{"scope":"project","namespace":"GOAL_ID","content":"Use the same benchmark input for every worker","importance":90}'
curl 'http://127.0.0.1:8787/v1/memories?scope=project&namespace=GOAL_ID'
```

Workers automatically register their final Codex message as an
`ArtifactProduced` artifact and attach its path and ID to the completed Goal's
evidence list. Other executors can register reports, patches, measurements,
or links through `POST /v1/artifacts`.

A Goal can also add another logical Worker. Each added Worker receives an
 isolated directory under the Goal workspace and can be scheduled with a
 different capability profile:

```bash
curl -X POST http://127.0.0.1:8787/v1/goals/GOAL_ID/workers \
  -H 'content-type: application/json' \
  -d '{"resources":{"accelerator":"H100","harness":"codex"},"prompt":"Run the independent validation path."}'
curl http://127.0.0.1:8787/v1/goals/GOAL_ID/workers
```

Goal metadata accepts an RFC3339 `deadline`, structured `budget`, and
structured `resources`. The monitor stops an unfinished Goal after its deadline
and emits a P0 notification. The MVP enforces `budget.max_runtime_seconds` for
running workers and `budget.max_workers` when adding workers; token and
executor-specific accounting can be added without changing the Goal shape.
