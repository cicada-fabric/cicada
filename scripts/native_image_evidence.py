"""Shared data-only STD producer/image checks and owned binary extraction.

These checks do not call a model, authorize a task, or prove native consumption.
The immutable receipt digest is an explicit trusted Supervisor input.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import json

def read_clean_producer(path, expected_sha256):
    """The caller supplies the trusted producer receipt digest, never a mutable tag."""
    path = Path(path)
    if (not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") or
            path.resolve(strict=True) != path.absolute() or
            not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 32 << 20):
        raise RuntimeError("canonical_regular_pinned_producer_metadata_required")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise RuntimeError("producer_metadata_sha256_mismatch")
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise RuntimeError("invalid_producer_metadata_json") from None


def check_clean_producer(metadata, current_source):
    if not isinstance(metadata, dict):
        raise RuntimeError("clean_standard_producer_required")
    source, image = metadata.get("source"), metadata.get("image")
    if (metadata.get("schema_version") != "cicada.hub-build.v1" or
            metadata.get("transport_variant") != "standard" or metadata.get("pqtls_available") is not False or
            not isinstance(source, dict) or not isinstance(image, dict) or source.get("dirty") is not False or
            not re.fullmatch(r"[0-9a-f]{40}", source.get("revision", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", source.get("source_fingerprint", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", source.get("catalog_sha256", "")) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("id", "")) or
            image.get("dockerfile") != "docker/Dockerfile.hub"):
        raise RuntimeError("clean_standard_producer_required")
    for key in ("revision", "source_fingerprint", "catalog_sha256", "input_inventory"):
        if not source.get(key) or source[key] != current_source.get(key):
            raise RuntimeError("producer_current_code_inputs_mismatch_" + key)
    inventory = source["input_inventory"]
    if (not isinstance(inventory, dict) or inventory.get("schema_version") != "cicada.hub-build-input-inventory.v1" or
            inventory.get("source_fingerprint_v4", {}).get("sha256") != source["source_fingerprint"]):
        raise RuntimeError("producer_inventory_fingerprint_mismatch")
    return image["id"]


def check_clean_image(metadata, inspected, kind="hub"):
    if kind not in ("hub", "interop"):
        raise RuntimeError("unknown_standard_image_kind")
    source = metadata["source"]
    image = metadata["image"] if kind == "hub" else metadata.get("test_image", {})
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("id", "")):
        raise RuntimeError("immutable_delivered_image_id_required")
    labels = inspected.get("Config", {}).get("Labels") or {}
    expected = {"org.opencontainers.image.revision": source["revision"], "org.cicada.build.dirty": "false",
                "org.cicada.build.source-fingerprint": source["source_fingerprint"],
                "org.cicada.client-catalog.sha256": source["catalog_sha256"]}
    if kind == "hub":
        expected["org.cicada.role"] = "hub"
    else:
        expected["org.opencontainers.image.title"] = "CICADA Hub interop test runner"
    if inspected.get("Id") != image["id"] or any(labels.get(k) != v for k, v in expected.items()):
        raise RuntimeError("immutable_delivered_image_or_labels_mismatch")


def check_hub_provenance(health, result):
    source = result["build"]["source"]
    exact = result["acceptance_mode"] in ("exact-clean-image", "exact-clean-image-pair")
    if (health.get("source_fingerprint") != source["source_fingerprint"] or health.get("dirty") is not (not exact) or
            exact and (health.get("revision") != source["revision"] or health.get("catalog_sha256") != source["catalog_sha256"])):
        raise RuntimeError("hub_actual_build_provenance_mismatch")


def check_clean_pair(metadata, current_source):
    hub_id = check_clean_producer(metadata, current_source)
    interop_id = metadata.get("test_image", {}).get("id", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", interop_id) or interop_id == hub_id:
        raise RuntimeError("distinct_immutable_delivered_interop_required")
    return hub_id, interop_id


def extract_image_binary(gate, image_id):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise RuntimeError("immutable_binary_source_image_required")
    binary = gate.root / "cicada"
    if binary.exists() or binary.is_symlink():
        raise RuntimeError("extracted_binary_destination_not_new")
    extract = gate.run_id + "-extract"
    gate.docker("create", "--name", extract, "--label", "org.cicada.test.run=" + gate.run_id,
                "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", image_id)
    gate.containers[extract] = image_id  # Container is owned; shared source image is never cleanup-owned.
    gate.docker("cp", extract + ":/usr/local/bin/cicada", binary)
    info = binary.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
            not 0 < info.st_size <= 128 << 20 or not info.st_mode & 0o111):
        raise RuntimeError("extracted_image_binary_not_regular_executable")
    binary.chmod(0o700)
    return hashlib.sha256(binary.read_bytes()).hexdigest(), {
        "origin": "immutable-delivered-image", "image_id": image_id,
        "path": "/usr/local/bin/cicada", "rebuilt": False, "hub_overlay": False}


def check_preparation(prior, result):
    if (prior.get("status") != "PREPARATION_PASS_NATIVE_NOT_RUN" or prior.get("terminal_exit_code") != 0 or
            prior.get("models_invoked") != 0 or prior.get("native_model_turn_attempts") != 0 or
            prior.get("cleanup_owned_resources") is not True or prior.get("source_unchanged_during_gate") is not True or
            prior.get("build", {}).get("source") != result["build"]["source"]):
        raise RuntimeError("successful_matching_zero_model_preparation_required")
    keys = ("acceptance_mode", "script_sha256", "image_evidence_helper_sha256", "cicada_binary_sha256",
            "fixture_binary_sha256", "runtime_image_id", "hub_image_id", "interop_image_id", "producer_metadata_sha256")
    if any(not result.get(key) or prior.get(key) != result[key] for key in keys):
        raise RuntimeError("preparation_driver_fixture_binary_runtime_image_mismatch")
