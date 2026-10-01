"""Validate the Node-Control child marker against its structured result."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


SCHEMA = "cicada.node-control-v1-http-flow.v1"
STATUSES = {"PASS", "NOT_RUN", "FAIL", "BLOCKED"}
MARKER = re.compile(r"^(PASS|NOT_RUN|FAIL|BLOCKED):\s+(.+?)\s*$")


def classify(stdout: str, exit_code: int) -> dict[str, str | None]:
    marker_status: str | None = None
    result_path: str | None = None
    for line in stdout.splitlines():
        match = MARKER.fullmatch(line)
        if match:
            marker_status, result_path = match.groups()

    outcome = "FAIL"
    reason = "child stdout has no valid status marker"
    if marker_status is not None and result_path is not None:
        try:
            result = json.loads(Path(result_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            reason = "child marker result.json is missing or invalid"
        else:
            result_status = result.get("status") if result.get("schema_version") == SCHEMA else None
            if result_status not in STATUSES:
                reason = "child result.json schema or status is invalid"
            elif result_status != marker_status:
                reason = "child stdout marker and result.json status disagree"
            elif exit_code != 0 and result_status in {"PASS", "NOT_RUN"}:
                reason = f"child reported {result_status} but exited {exit_code}"
            elif exit_code == 0 and result_status == "BLOCKED":
                reason = "child reported BLOCKED but exited 0"
            else:
                outcome = result_status
                reason = f"child result.json reports {result_status}"

    return {
        "status": outcome,
        "marker_status": marker_status,
        "result_path": result_path,
        "reason": reason,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: completion_driver_status.py LOG EXIT_CODE", file=sys.stderr)
        return 2
    try:
        exit_code = int(argv[2], 10)
        stdout = Path(argv[1]).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}))
        return 0
    print(json.dumps(classify(stdout, exit_code), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
