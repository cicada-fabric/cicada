# Happy upstream reference

Cicada may reuse code and design patterns from
[slopus/happy](https://github.com/slopus/happy). A shallow sparse checkout is
kept outside the project repository at:

```text
/gpu1-share/data/cicada/vendor/happy
```

The reviewed revision is:

```text
3825130467cb6e8fd49205f2aadbc3d5d83e9019
```

The checkout contains `packages/happy-cli`, `packages/happy-agent`, and
`packages/happy-server`. Happy is MIT licensed. Any copied or substantially
derived code must retain Happy's copyright and permission notice.

For the Codex-first MVP, the most relevant references are:

- `packages/happy-cli/src/codex/codexAppServerClient.ts` and related app-server
  types for the Codex event and request boundary;
- `packages/happy-cli/src/codex/runCodex.ts`, thread resume/fork helpers, and
  execution-policy handling for session lifecycle;
- `packages/happy-cli/src/daemon/` for process supervision and liveness;
- `packages/happy-agent/src/machineRpc.ts` for later remote machine/session RPC;
- `packages/happy-agent/src/encryption.ts` and `packages/happy-server` for the
  later encrypted relay and multi-client phases.

The initial Cicada implementation should keep its own small control/worker
boundary and reuse focused modules only when their behavior matches
`CICADA.md`. Pulling in Happy's complete UI, account system, or server is not
required for the MVP.

To refresh the reference deliberately:

```bash
git -C /gpu1-share/data/cicada/vendor/happy fetch --depth 1 origin
git -C /gpu1-share/data/cicada/vendor/happy checkout <reviewed-commit>
```

Record the new commit here and review its license before copying code.

