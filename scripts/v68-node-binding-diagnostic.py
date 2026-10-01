#!/usr/bin/env python3
"""Print a secret-free Node credential/Owner binding health summary."""

import argparse
import base64
import hashlib
import json
import sqlite3
from pathlib import Path


def sqlite_error_class(error: sqlite3.OperationalError) -> str:
    message = str(error).lower()
    if "locked" in message or "busy" in message:
        return "database_busy"
    if "no such table" in message or "no such column" in message:
        return "schema_missing"
    if "unable to open" in message or "cannot open" in message:
        return "database_unavailable"
    return "query_error"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--node-state", required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--hub-id", required=True)
    args = parser.parse_args()

    identity_path = Path(args.node_state) / "nodes" / ("node-" + args.node_id) / "identity.json"
    token_path = identity_path.parent / "relay.token"
    result = {
        "node_id_matches_state_path": False,
        "local_token_present": False,
        "node_token_digest_matches_active_owner_binding": False,
        "credential_active": False,
        "binding_active": False,
        "credential_version_matches_binding": False,
        "hub_matches_fixture": False,
        "owner_principal_active": False,
        "owner_key_active": False,
        "client_device_active": False,
        "owner_bound_authorization_join_complete": False,
        "sqlite_error_class": "",
    }
    try:
        identity_info = identity_path.stat(follow_symlinks=False)
        token_info = token_path.stat(follow_symlinks=False)
        if not identity_path.is_file() or identity_path.is_symlink() or not token_path.is_file() or token_path.is_symlink():
            raise OSError("unsafe_node_state")
        if token_info.st_mode & 0o777 != 0o600:
            raise OSError("unsafe_node_token_mode")
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        result["node_id_matches_state_path"] = identity.get("version") == 1 and identity.get("node_id") == args.node_id
        token = token_path.read_text(encoding="utf-8").strip()
        result["local_token_present"] = bool(token)
        if not token:
            print(json.dumps(result, sort_keys=True))
            return 0
    except (OSError, ValueError, json.JSONDecodeError):
        result["sqlite_error_class"] = "node_state_unavailable_or_unsafe"
        print(json.dumps(result, sort_keys=True))
        return 0

    digest = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode("ascii").rstrip("=")
    connection = None
    try:
        database_uri = Path(args.db).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(database_uri, uri=True, timeout=5)
        connection.execute("PRAGMA busy_timeout=5000")
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
SELECT hub.hub_id AS configured_hub_id,
       credential.node_id AS credential_node_id,
       credential.credential_hash AS credential_hash,
       credential.version AS credential_version,
       credential.status AS credential_status,
       binding.node_id AS binding_node_id,
       binding.hub_id AS binding_hub_id,
       binding.node_credential_digest AS binding_digest,
       binding.node_credential_version AS binding_credential_version,
       binding.state AS binding_state,
       principal.kind AS principal_kind,
       principal.status AS principal_status,
       owner_key.state AS owner_key_state,
       device.state AS device_state,
       device.owner_id AS device_owner_id,
       binding.owner_id AS binding_owner_id,
       binding.owner_key_id AS binding_owner_key_id,
       binding.client_device_id AS binding_device_id
FROM client_device_hub_config_v2 hub
LEFT JOIN fabric_node_credentials credential
  ON credential.node_id=? AND credential.credential_hash=?
LEFT JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
LEFT JOIN principals principal ON principal.id=binding.owner_id
LEFT JOIN owner_approval_keys_v2 owner_key
  ON owner_key.owner_id=binding.owner_id AND owner_key.key_id=binding.owner_key_id
LEFT JOIN client_devices_v2 device
  ON device.owner_id=binding.owner_id AND device.device_id=binding.client_device_id
WHERE hub.id=1
""",
            (args.node_id, digest),
        ).fetchone()
        if row is not None:
            result.update(
                {
                    "hub_matches_fixture": row["configured_hub_id"] == args.hub_id and row["binding_hub_id"] == args.hub_id,
                    "node_token_digest_matches_active_owner_binding": row["credential_hash"] == digest and row["binding_digest"] == digest,
                    "credential_active": row["credential_node_id"] == args.node_id and row["credential_status"] == "active",
                    "binding_active": row["binding_node_id"] == args.node_id and row["binding_state"] == "ACTIVE",
                    "credential_version_matches_binding": row["credential_version"] is not None and row["credential_version"] == row["binding_credential_version"],
                    "owner_principal_active": row["principal_kind"] == "human" and row["principal_status"] == "active" and row["binding_owner_id"] is not None,
                    "owner_key_active": row["owner_key_state"] == "ACTIVE" and row["binding_owner_key_id"] is not None,
                    "client_device_active": row["device_state"] == "ACTIVE" and row["device_owner_id"] == row["binding_owner_id"] and row["binding_device_id"] is not None,
                }
            )
            result["owner_bound_authorization_join_complete"] = all(
                result[key]
                for key in (
                    "node_id_matches_state_path",
                    "node_token_digest_matches_active_owner_binding",
                    "credential_active",
                    "binding_active",
                    "credential_version_matches_binding",
                    "hub_matches_fixture",
                    "owner_principal_active",
                    "owner_key_active",
                    "client_device_active",
                )
            )
        else:
            result["sqlite_error_class"] = "hub_identity_row_missing"
    except sqlite3.OperationalError as error:
        result["sqlite_error_class"] = sqlite_error_class(error)
    except OSError:
        result["sqlite_error_class"] = "database_unavailable"
    finally:
        if connection is not None:
            connection.close()

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
