# Permission and trust

Cicada stores capability rules separately from a harness. A rule identifies a
`subject_type` (`contact`, `goal`, `workspace`, `machine`, or `global`), a
`subject_id`, an `action`, an optional `resource`, and an `effect`:

- `allow` permits the action;
- `approval` blocks the action until a human policy flow is added;
- `deny` blocks the action.

Rules are durable in the control SQLite database and are evaluated from the
most specific subject/resource to a wildcard subject (`"*"`). No matching rule
currently preserves the local MVP default of allowing the operation. This
makes policies opt-in while leaving a clear path to install a global default
deny and narrow exceptions.

Contacts must also have status `trusted` before Cicada sends or accepts an
encrypted peer message. Revoking a contact therefore takes effect even when a
previously valid public key is still stored.

Set a contact policy:

```sh
curl -X POST http://127.0.0.1:8787/v1/permissions \
  -H 'content-type: application/json' \
  -d '{"subject_type":"contact","subject_id":"contact_…","action":"peer.message","effect":"deny"}'
```

Inspect or remove policies:

```sh
curl 'http://127.0.0.1:8787/v1/permissions?subject_type=contact'
curl -X DELETE http://127.0.0.1:8787/v1/permissions/PERMISSION_ID
```

The policy layer is intentionally independent from Codex’s approval callback.
Codex requests still become first-class Approval objects; future harnesses can
use the same policy evaluator before invoking their own tools.
