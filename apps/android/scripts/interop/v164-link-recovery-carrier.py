#!/usr/bin/env python3
"""Narrow opaque frame adapter for one Core-owned Client Link recovery case.

The Android app keeps its Root-pinned base URL. Its existing network-none
stdio carrier emits ``req`` frames and consumes ``resp``/``drop`` frames; this
module gates those frames and forwards only to the exact numeric loopback
``serve-link`` origin supplied by Root. It has no listener, ADB/Docker helpers,
database access, key material, lifecycle controls, or generic proxy behavior.

The selected ``POST /v2/client/rpc`` response is always represented as a
``drop`` frame, including when upstream unexpectedly writes an HTTP response.
This closes the Android request without fabricating an HTTP response and
leaves the original encrypted packet pending. One byte-identical
``POST /v2/client/rpc/recover`` may follow, after an independently Root-pinned
READY envelope is installed through the separate control FD.

CLI network use requires ``--go``. The module itself is importable for offline
validation and its ``FrameAdapter`` can be embedded in a Root-owned bridge.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import sys
from typing import Any, Mapping
from urllib.parse import urlsplit


# Import only Client definitions. The opaque carrier and Android staging must
# reject historical tuples against the same independently verified delivery.
sys.dont_write_bytecode = True
_delivery_spec = importlib.util.spec_from_file_location(
    'v164_recovery_carrier_delivery', Path(__file__).with_name('v164-clean-delivery.py'))
if _delivery_spec is None or _delivery_spec.loader is None:
    raise ValueError('Client delivery definitions are unavailable')
_delivery = importlib.util.module_from_spec(_delivery_spec)
_delivery_spec.loader.exec_module(_delivery)
CORE_REVISION = _delivery.PINS['source_revision']
HUB_IMAGE_ID = _delivery.PINS['hub_image_id']
SOURCE_FINGERPRINT = _delivery.PINS['source_fingerprint']
CATALOG_SHA256 = _delivery.PINS['catalog_sha256']
CONTRACT_REVISION = _delivery.PINS['contract_revision']
WIRE_VERSION = _delivery.PINS['wire_version']

MANIFEST_SCHEMA = 'cicada.client-v164-link-recovery-carrier.v1'
ROOT_READY_SCHEMA = 'cicada.client-v164-link-recovery-ready.v1'
SCENARIO_SCHEMA = 'cicada.client-v164-link-consent-recovery-scenario.v2'
MAX_MANIFEST_BYTES = 32 * 1024
MAX_SCENARIO_BYTES = 8 * 1024
MAX_ROOT_READY_BYTES = 24 * 1024
MAX_EVENT_BYTES = 4096
MAX_PACKET_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FRAME_BYTES = 6 * 1024 * 1024
MAX_CONTROL_FRAME_BYTES = 64 * 1024
# Native Android counters use signed Long even though the wire uses uint64.
MAX_CLIENT_LONG = (1 << 63) - 1
HEX64 = re.compile(r'[0-9a-f]{64}')
RUN_ID = re.compile(r'v164-[A-Za-z0-9_-]{1,72}')

CONSENT_OPERATIONS = frozenset({'link.key_grant', 'link.review_policy_grant'})
FAULT_MODES = frozenset({'response-loss', 'processing', 'uncertain', 'legacy'})
READ_OPERATIONS = frozenset({
    'session.capabilities', 'status.snapshot', 'link.list', 'link.key_manifest',
    'link.key_grants', 'link.review_policy_preview', 'link.review_policy_status',
})
IDENTITY_ROUTES = frozenset({
    ('GET', '/v2/client/identity'),
    ('GET', '/v2/client/capabilities'),
})
RPC_PATH = '/v2/client/rpc'
RECOVER_PATH = '/v2/client/rpc/recover'
ANDROID_EMULATOR_PORTS = frozenset({8787, 8788, 8789, 8790, 8792, 8794, 8795})

ROOT_MANIFEST_FIELDS = frozenset({
    'schema', 'run_id', 'run_scope', 'core_revision', 'hub_image_id',
    'source_fingerprint', 'catalog_sha256', 'contract_revision', 'wire_version',
    'fixture_pid', 'fixture_process_start', 'helper_sha256', 'ready_raw_sha256',
    'hub_id', 'upstream_origin', 'android_base_url', 'owner_id', 'device_id',
    'session_epoch', 'expected_operation', 'fault_mode',
})
ROUTE_FIELDS = frozenset({
    'version', 'direction', 'hub_id', 'owner_id', 'device_id', 'session_epoch',
    'sequence', 'operation_id', 'operation', 'sender_key_id', 'sender_key_version',
    'receiver_key_id', 'receiver_key_version',
})
SCENARIO_FIELDS = frozenset({'schema', 'run_id', 'expected_operation', 'fault_mode'})
ROOT_READY_FIELDS = frozenset({
    'schema', 'run_id', 'hub_source', 'fault_ready_raw_base64',
    'fault_ready_raw_sha256', 'restart',
})
HUB_SOURCE_FIELDS = frozenset({
    'core_revision', 'hub_image_id', 'source_fingerprint', 'catalog_sha256',
    'contract_revision', 'wire_version',
})


def _fail(message: str) -> None:
    raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail('duplicate JSON field')
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    _fail('non-finite JSON number')


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > 12:
        _fail('JSON nesting exceeds the fixed bound')
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def _parse_json(raw: bytes, *, maximum: int) -> Any:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        _fail('bounded JSON bytes are required')
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'),
            object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('JSON is malformed') from error
    _check_depth(value)
    return value


def _parse_jsonl_event(raw_line: bytes) -> dict[str, Any]:
    if not isinstance(raw_line, bytes) or not 2 <= len(raw_line) <= MAX_EVENT_BYTES or \
            not raw_line.endswith(b'\n') or raw_line.count(b'\n') != 1 or b'\r' in raw_line:
        _fail('one bounded Core JSONL event line is required')
    value = _parse_json(raw_line[:-1], maximum=MAX_EVENT_BYTES - 1)
    if not isinstance(value, dict):
        _fail('Core event must be a JSON object')
    return value


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != set(expected):
        _fail(label + ' fields differ from the pinned schema')


def _token(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and value.strip() == value and \
        all(char.isprintable() and not char.isspace() and char not in '/\\' for char in value)


def _uint(value: Any, *, positive: bool = False) -> bool:
    return type(value) is int and (value > 0 if positive else value >= 0) and value <= MAX_CLIENT_LONG


def _digest(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _loopback_origin(raw: Any) -> tuple[str, int]:
    if not isinstance(raw, str) or len(raw) > 128:
        _fail('fixed loopback origin is invalid')
    parsed = urlsplit(raw)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError('fixed loopback origin is invalid') from error
    if parsed.scheme != 'http' or parsed.username is not None or parsed.password is not None or \
            parsed.hostname != '127.0.0.1' or port is None or not 1024 <= port <= 65535 or \
            parsed.path != '' or parsed.query or parsed.fragment or \
            parsed.netloc != f'127.0.0.1:{port}':
        _fail('origin must be a fixed numeric IPv4 loopback HTTP origin')
    return '127.0.0.1', port


def _android_base_url(raw: Any) -> str:
    if not isinstance(raw, str) or len(raw) > 128:
        _fail('Root-pinned Android base URL is invalid')
    parsed = urlsplit(raw)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError('Root-pinned Android base URL is invalid') from error
    exact_loopback = parsed.hostname == '127.0.0.1' and port is not None and 1024 <= port <= 65535
    exact_emulator = parsed.hostname == '10.0.2.2' and port in ANDROID_EMULATOR_PORTS
    if parsed.scheme != 'http' or parsed.username is not None or parsed.password is not None or \
            not (exact_loopback or exact_emulator) or parsed.path or parsed.query or parsed.fragment or \
            parsed.netloc != f'{parsed.hostname}:{port}':
        _fail('Android base URL is outside the exact Root-approved loopback allowlist')
    return raw


@dataclass(frozen=True, slots=True)
class Scenario:
    run_id: str
    expected_operation: str
    fault_mode: str


def parse_scenario(raw_or_mapping: bytes | Mapping[str, Any], *, run_id: str | None = None) -> Scenario:
    """Validate the exact four-field Android recovery scenario v2 record."""
    value = _parse_json(raw_or_mapping, maximum=MAX_SCENARIO_BYTES) if isinstance(raw_or_mapping, bytes) \
        else raw_or_mapping
    _exact_keys(value, SCENARIO_FIELDS, 'Recovery scenario')
    if value.get('schema') != SCENARIO_SCHEMA or not isinstance(value.get('run_id'), str) or \
            RUN_ID.fullmatch(value['run_id']) is None or value.get('expected_operation') not in CONSENT_OPERATIONS or \
            value.get('fault_mode') not in FAULT_MODES or run_id is not None and value['run_id'] != run_id:
        _fail('recovery scenario does not match the exact v2 run scope')
    return Scenario(value['run_id'], value['expected_operation'], value['fault_mode'])


@dataclass(frozen=True, slots=True)
class RootManifest:
    run_id: str
    run_scope: str
    fixture_pid: int
    fixture_process_start: str
    helper_sha256: str
    ready_raw_sha256: str
    hub_id: str
    upstream_origin: str
    android_base_url: str
    owner_id: str
    device_id: str
    session_epoch: int
    expected_operation: str
    fault_mode: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> 'RootManifest':
        _exact_keys(value, ROOT_MANIFEST_FIELDS, 'Root manifest')
        fixed = {
            'schema': MANIFEST_SCHEMA,
            'core_revision': CORE_REVISION,
            'hub_image_id': HUB_IMAGE_ID,
            'source_fingerprint': SOURCE_FINGERPRINT,
            'catalog_sha256': CATALOG_SHA256,
            'contract_revision': CONTRACT_REVISION,
            'wire_version': WIRE_VERSION,
        }
        if any(value.get(key) != expected for key, expected in fixed.items()):
            _fail('Root manifest does not match the fixed current Core build pins')
        if not isinstance(value.get('run_id'), str) or RUN_ID.fullmatch(value['run_id']) is None or \
                not isinstance(value.get('run_scope'), str) or \
                re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value['run_scope']) is None:
            _fail('Root run identity is malformed')
        if type(value.get('fixture_pid')) is not int or not 2 <= value['fixture_pid'] <= (1 << 31) - 1 or \
                not isinstance(value.get('fixture_process_start'), str) or \
                re.fullmatch(r'[1-9][0-9]{0,19}', value['fixture_process_start']) is None:
            _fail('externally pinned Core process identity is malformed')
        for field in ('helper_sha256', 'ready_raw_sha256'):
            if not _digest(value.get(field)):
                _fail('Root manifest contains an invalid SHA-256 pin')
        if not all(_token(value.get(field)) for field in ('hub_id', 'owner_id', 'device_id')):
            _fail('Root manifest profile identity is malformed')
        if not _uint(value.get('session_epoch'), positive=True):
            _fail('Root manifest session epoch is invalid')
        if value.get('expected_operation') not in CONSENT_OPERATIONS or value.get('fault_mode') not in FAULT_MODES:
            _fail('Root manifest selects an unsupported consent operation or fault mode')
        upstream = value.get('upstream_origin')
        _loopback_origin(upstream)
        android_url = _android_base_url(value.get('android_base_url'))
        return cls(
            run_id=value['run_id'], run_scope=value['run_scope'], fixture_pid=value['fixture_pid'],
            fixture_process_start=value['fixture_process_start'], helper_sha256=value['helper_sha256'],
            ready_raw_sha256=value['ready_raw_sha256'], hub_id=value['hub_id'],
            upstream_origin=upstream, android_base_url=android_url,
            owner_id=value['owner_id'], device_id=value['device_id'], session_epoch=value['session_epoch'],
            expected_operation=value['expected_operation'], fault_mode=value['fault_mode'])

    def routing_scope(self) -> 'RawRoutingScope':
        return RawRoutingScope(self.run_id, self.hub_id, self.owner_id, self.device_id,
            self.session_epoch, self.expected_operation, self.fault_mode)

    def hub_source(self) -> dict[str, Any]:
        return {
            'core_revision': CORE_REVISION, 'hub_image_id': HUB_IMAGE_ID,
            'source_fingerprint': SOURCE_FINGERPRINT, 'catalog_sha256': CATALOG_SHA256,
            'contract_revision': CONTRACT_REVISION, 'wire_version': WIRE_VERSION,
        }


@dataclass(frozen=True, slots=True)
class RawRoutingScope:
    """Immutable allowlist for one exact enrolled Owner/device/session case."""
    run_id: str
    hub_id: str
    owner_id: str
    device_id: str
    session_epoch: int
    expected_operation: str
    fault_mode: str

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or RUN_ID.fullmatch(self.run_id) is None or \
                not all(_token(value) for value in (self.hub_id, self.owner_id, self.device_id)) or \
                not _uint(self.session_epoch, positive=True) or self.expected_operation not in CONSENT_OPERATIONS or \
                self.fault_mode not in FAULT_MODES:
            _fail('immutable routing scope is malformed')


@dataclass(frozen=True, slots=True)
class Ready:
    listen: str
    mode: str
    operation: str
    contract_revision: str
    catalog_sha256: str
    wire_version: int
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class ParsedRoute:
    hub_id: str
    owner_id: str
    device_id: str
    session_epoch: int
    sequence: int
    operation_id: str
    operation: str
    sender_key_id: str
    sender_key_version: int
    receiver_key_id: str
    receiver_key_version: int
    route_sha256: str


@dataclass(frozen=True, slots=True)
class FaultReady:
    mode: str
    operation: str
    request_sha256: str
    request_sequence: int
    request_status: str
    reserved_response_sequence: int
    response_sha256: str | None
    handler_executed: bool
    scope: str
    restart_required: bool | None
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class RootReadyEnvelope:
    run_id: str
    fault_ready: FaultReady
    restart_status: str
    restart_receipt_sha256: str | None
    raw_sha256: str


def parse_ready(raw_line: bytes, manifest: RootManifest | Mapping[str, Any]) -> Ready:
    """Validate Core's actual READY JSONL bytes against Root's fixed manifest."""
    if not isinstance(manifest, RootManifest):
        manifest = RootManifest.from_mapping(manifest)
    raw_sha = hashlib.sha256(raw_line).hexdigest()
    if raw_sha != manifest.ready_raw_sha256:
        _fail('Core READY bytes differ from Root’s externally pinned raw hash')
    event = _parse_jsonl_event(raw_line)
    _exact_keys(event, frozenset({
        'event', 'mode', 'operation', 'listen', 'contract_revision', 'catalog_sha256', 'wire_version',
    }), 'Core READY event')
    host, port = _loopback_origin(manifest.upstream_origin)
    if event.get('listen') != f'{host}:{port}' or event.get('event') != 'READY' or \
            event.get('mode') != manifest.fault_mode or event.get('operation') != manifest.expected_operation or \
            event.get('contract_revision') != CONTRACT_REVISION or event.get('catalog_sha256') != CATALOG_SHA256 or \
            type(event.get('wire_version')) is not int or event['wire_version'] != WIRE_VERSION:
        _fail('Core READY event does not match the fixed manifest and selected scope')
    return Ready(event['listen'], event['mode'], event['operation'], event['contract_revision'],
        event['catalog_sha256'], event['wire_version'], raw_sha)


def _parse_packet_route(raw_packet: bytes, scope: RawRoutingScope, *, direction: str) -> ParsedRoute:
    value = _parse_json(raw_packet, maximum=MAX_PACKET_BYTES)
    _exact_keys(value, frozenset({'route', 'envelope'}), 'Client packet')
    route = value.get('route')
    _exact_keys(route, ROUTE_FIELDS, 'Client route')
    if type(route.get('version')) is not int or route['version'] != WIRE_VERSION or \
            route.get('direction') != direction or route.get('hub_id') != scope.hub_id or \
            route.get('owner_id') != scope.owner_id or route.get('device_id') != scope.device_id or \
            route.get('session_epoch') != scope.session_epoch or not _uint(route.get('session_epoch'), positive=True) or \
            not _uint(route.get('sequence'), positive=True) or not _token(route.get('operation_id')) or \
            not _token(route.get('operation')) or not _token(route.get('sender_key_id')) or \
            not _token(route.get('receiver_key_id')) or not _uint(route.get('sender_key_version'), positive=True) or \
            not _uint(route.get('receiver_key_version'), positive=True):
        _fail('Client packet route is outside the fixed Owner/device/session scope')
    envelope = value.get('envelope')
    if not isinstance(envelope, str) or not envelope or len(envelope) > MAX_PACKET_BYTES * 2:
        _fail('Client packet envelope is malformed')
    try:
        envelope_bytes = base64.b64decode(envelope, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('Client packet envelope is malformed') from error
    if not envelope_bytes or len(envelope_bytes) > MAX_PACKET_BYTES or \
            base64.b64encode(envelope_bytes).decode('ascii') != envelope:
        _fail('Client packet envelope encoding is not canonical or bounded')
    route_bytes = json.dumps(route, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return ParsedRoute(route['hub_id'], route['owner_id'], route['device_id'], route['session_epoch'],
        route['sequence'], route['operation_id'], route['operation'], route['sender_key_id'],
        route['sender_key_version'], route['receiver_key_id'], route['receiver_key_version'],
        hashlib.sha256(route_bytes).hexdigest())


def parse_request_route(raw_packet: bytes, scope: RawRoutingScope) -> ParsedRoute:
    """Read only the bounded public route; encrypted envelope stays opaque."""
    return _parse_packet_route(raw_packet, scope, direction='REQUEST')


def parse_response_route(raw_packet: bytes, scope: RawRoutingScope, original: ParsedRoute,
        *, expected_sequence: int) -> ParsedRoute:
    route = _parse_packet_route(raw_packet, scope, direction='RESPONSE')
    if route.operation != original.operation or route.operation_id != original.operation_id or \
            route.sequence != expected_sequence or route.sender_key_id != original.receiver_key_id or \
            route.receiver_key_id != original.sender_key_id or \
            route.sender_key_version != original.receiver_key_version or \
            route.receiver_key_version != original.sender_key_version:
        _fail('recovered response route differs from the selected request reservation')
    return route


def parse_fault_ready(raw_line: bytes, scope: RawRoutingScope, original_packet: bytes,
        *, expected_request_sequence: int | None = None,
        expected_response_sequence: int | None = None) -> FaultReady:
    """Validate the exact raw Core FAULT_READY JSONL event against original bytes."""
    route = parse_request_route(original_packet, scope)
    if route.operation != scope.expected_operation or expected_request_sequence is not None and \
            route.sequence != expected_request_sequence:
        _fail('original packet is not the selected consent operation and sequence')
    event = _parse_jsonl_event(raw_line)
    common = {
        'event', 'mode', 'operation', 'request_sha256', 'request_sequence', 'business_outcome',
        'handler_executed', 'scope', 'request_status', 'reserved_response_sequence',
    }
    expected_fields = common | ({'response_sha256'} if scope.fault_mode == 'response-loss' else {'restart_required'})
    _exact_keys(event, frozenset(expected_fields), 'Core FAULT_READY event')
    request_sha = hashlib.sha256(original_packet).hexdigest()
    if event.get('event') != 'FAULT_READY' or event.get('mode') != scope.fault_mode or \
            event.get('operation') != scope.expected_operation or event.get('request_sha256') != request_sha or \
            event.get('request_sequence') != route.sequence or not _uint(event.get('request_sequence'), positive=True) or \
            event.get('business_outcome') != 'UNKNOWN':
        _fail('Core FAULT_READY does not bind the selected original packet')
    reserved = event.get('reserved_response_sequence')
    if not _uint(reserved):
        _fail('Core FAULT_READY response sequence is malformed')
    response_sha: str | None = None
    restart_required: bool | None = None
    if scope.fault_mode == 'response-loss':
        if event.get('handler_executed') is not True or event.get('scope') != 'REAL_HANDLER_COMPLETED_TRANSPORT' or \
                event.get('request_status') != 'COMPLETED' or not _digest(event.get('response_sha256')) or \
                not _uint(reserved, positive=True):
            _fail('response-loss FAULT_READY does not describe a cached completed response')
        response_sha = event['response_sha256']
    else:
        modes = {
            'processing': ('PROCESSING', 0, False),
            'uncertain': ('PROCESSING', None, True),
            'legacy': ('UNCERTAIN', 0, False),
        }
        status, expected_reserved, expected_restart = modes[scope.fault_mode]
        if event.get('handler_executed') is not False or event.get('scope') != 'OUTER_RPC_LEDGER_ONLY' or \
                event.get('request_status') != status or event.get('restart_required') is not expected_restart or \
                expected_reserved is not None and reserved != expected_reserved or \
                scope.fault_mode == 'uncertain' and not _uint(reserved, positive=True):
            _fail('outer-ledger FAULT_READY mode fields differ from the Core source contract')
        restart_required = expected_restart
    if expected_response_sequence is not None and reserved != expected_response_sequence:
        _fail('Core response reservation differs from the Client pending counter')
    return FaultReady(scope.fault_mode, scope.expected_operation, request_sha, route.sequence,
        event['request_status'], reserved, response_sha, event['handler_executed'], event['scope'],
        restart_required, hashlib.sha256(raw_line).hexdigest())


def parse_fault_failed(raw_line: bytes, scope: RawRoutingScope, original_packet: bytes) -> dict[str, str]:
    route = parse_request_route(original_packet, scope)
    event = _parse_jsonl_event(raw_line)
    _exact_keys(event, frozenset({'event', 'mode', 'operation', 'request_sha256', 'business_outcome'}),
        'Core FAULT_FAILED event')
    if event.get('event') != 'FAULT_FAILED' or event.get('mode') != scope.fault_mode or \
            event.get('operation') != scope.expected_operation or \
            event.get('request_sha256') != hashlib.sha256(original_packet).hexdigest() or \
            event.get('business_outcome') != 'UNKNOWN' or route.operation != scope.expected_operation:
        _fail('Core FAULT_FAILED does not bind the selected original packet')
    return {'event': 'FAULT_FAILED', 'request_sha256': event['request_sha256'],
        'raw_sha256': hashlib.sha256(raw_line).hexdigest()}


def parse_ready_envelope(raw_envelope: bytes, scope: RawRoutingScope, original_packet: bytes,
        manifest: RootManifest | Mapping[str, Any], *, expected_sha256: str) -> RootReadyEnvelope:
    """Validate Root provenance wrapper and its byte-exact Core event separately."""
    if not _digest(expected_sha256) or hashlib.sha256(raw_envelope).hexdigest() != expected_sha256:
        _fail('Root READY envelope differs from its out-of-band SHA-256')
    if not isinstance(manifest, RootManifest):
        manifest = RootManifest.from_mapping(manifest)
    if scope != manifest.routing_scope():
        _fail('routing scope differs from the Root manifest')
    wrapper = _parse_json(raw_envelope, maximum=MAX_ROOT_READY_BYTES)
    _exact_keys(wrapper, ROOT_READY_FIELDS, 'Root READY envelope')
    if wrapper.get('schema') != ROOT_READY_SCHEMA or wrapper.get('run_id') != manifest.run_id or \
            wrapper.get('hub_source') != manifest.hub_source():
        _fail('Root READY envelope provenance differs from the externally pinned manifest')
    encoded = wrapper.get('fault_ready_raw_base64')
    raw_sha = wrapper.get('fault_ready_raw_sha256')
    if not isinstance(encoded, str) or not _digest(raw_sha) or len(encoded) > MAX_EVENT_BYTES * 2:
        _fail('Root READY envelope does not contain a bounded raw Core event')
    try:
        raw_event = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('Root READY Core event encoding is invalid') from error
    if not raw_event or base64.b64encode(raw_event).decode('ascii') != encoded or \
            hashlib.sha256(raw_event).hexdigest() != raw_sha:
        _fail('Root READY Core event hash or encoding is invalid')
    fault_ready = parse_fault_ready(raw_event, scope, original_packet)
    restart = wrapper.get('restart')
    _exact_keys(restart, frozenset({'status', 'receipt_sha256'}), 'Root restart evidence')
    if scope.fault_mode == 'uncertain':
        if restart.get('status') != 'VERIFIED' or not _digest(restart.get('receipt_sha256')):
            _fail('uncertain recovery requires externally verified Root restart evidence')
    elif restart.get('status') != 'NOT_REQUIRED' or restart.get('receipt_sha256') is not None:
        _fail('this fault mode cannot carry restart evidence')
    return RootReadyEnvelope(manifest.run_id, fault_ready, restart['status'],
        restart.get('receipt_sha256'), expected_sha256)


@dataclass(frozen=True, slots=True)
class RouteDecision:
    kind: str
    path: str
    packet_sha256: str | None = None


class OpaqueLinkRecoveryRouter:
    """Single-session gate retaining one exact encrypted packet until recovery."""

    def __init__(self, scope: RawRoutingScope):
        self.scope = scope
        self._state = 'ARMED'
        self._original_packet: bytes | None = None
        self._original_route: ParsedRoute | None = None
        self._fault_ready: FaultReady | None = None
        self._root_envelope_sha256: str | None = None

    @property
    def state(self) -> str:
        return self._state

    @property
    def original_packet(self) -> bytes | None:
        return self._original_packet

    @property
    def original_request_sha256(self) -> str | None:
        return hashlib.sha256(self._original_packet).hexdigest() if self._original_packet is not None else None

    @property
    def original_route(self) -> ParsedRoute | None:
        return self._original_route

    @property
    def fault_ready(self) -> FaultReady | None:
        return self._fault_ready

    def authorize(self, method: str, path: str, body: bytes) -> RouteDecision:
        if method not in {'GET', 'POST'} or path not in {p for _, p in IDENTITY_ROUTES} | {RPC_PATH, RECOVER_PATH}:
            _fail('method or path is outside the fixed route set')
        if self._state == 'ARMED':
            if method == 'GET' and (method, path) in IDENTITY_ROUTES and body == b'':
                return RouteDecision('read', path)
            if method == 'POST' and path == RPC_PATH:
                route = parse_request_route(body, self.scope)
                if route.operation == self.scope.expected_operation:
                    self._original_packet = bytes(body)
                    self._original_route = route
                    self._state = 'SELECTED_IN_FLIGHT'
                    return RouteDecision('selected', path, hashlib.sha256(body).hexdigest())
                if route.operation in READ_OPERATIONS:
                    return RouteDecision('read', path, hashlib.sha256(body).hexdigest())
            _fail('pre-fault request is outside exact enrolled reads and selected Link operation')
        if self._state == 'FAULT_READY' and method == 'POST' and path == RECOVER_PATH and \
                self._original_packet is not None and body == self._original_packet:
            self._state = 'RECOVERY_IN_FLIGHT'
            return RouteDecision('recovery', path, hashlib.sha256(body).hexdigest())
        _fail('post-fault request is not the one byte-identical original recovery packet')

    def selected_response_lost(self) -> None:
        if self._state == 'SELECTED_IN_FLIGHT':
            self._state = 'AWAITING_FAULT_READY'
        else:
            self._state = 'FAILED'

    def observe_fault_ready(self, envelope: RootReadyEnvelope) -> None:
        if self._state not in {'AWAITING_FAULT_READY', 'FAULT_READY'} or self._original_packet is None:
            self._state = 'FAILED'
            _fail('Root FAULT_READY arrived without one selected pending request')
        if self._root_envelope_sha256 is not None and self._root_envelope_sha256 != envelope.raw_sha256:
            self._state = 'FAILED'
            _fail('Root attempted to replace the immutable FAULT_READY envelope')
        if self._fault_ready is not None and self._fault_ready != envelope.fault_ready:
            self._state = 'FAILED'
            _fail('Root attempted to replace the Core FAULT_READY event')
        self._root_envelope_sha256 = envelope.raw_sha256
        self._fault_ready = envelope.fault_ready
        self._state = 'FAULT_READY'

    def complete_recovery(self, responded: bool) -> None:
        if self._state != 'RECOVERY_IN_FLIGHT':
            self._state = 'FAILED'
            return
        self._state = 'RECOVERY_RESPONDED' if responded else 'RECOVERY_DROPPED'

    def reject_all(self) -> None:
        self._state = 'FAILED'


@dataclass(frozen=True, slots=True)
class UpstreamReply:
    status: int
    content_type: str | None
    body: bytes


def _decode_frame_body(frame: Mapping[str, Any]) -> bytes:
    if set(frame) != {'kind', 'method', 'path', 'headers', 'body_b64', 'body_bytes'} or \
            frame.get('kind') != 'request':
        _fail('stdio request frame differs from the v15 transport shape')
    method, path, headers = frame.get('method'), frame.get('path'), frame.get('headers')
    if method not in {'GET', 'POST'} or not isinstance(path, str) or \
            path not in {p for _, p in IDENTITY_ROUTES} | {RPC_PATH, RECOVER_PATH}:
        _fail('stdio request route is outside the fixed Client route set')
    if not isinstance(headers, dict) or any(key not in {'content-type', 'accept'} for key in headers):
        _fail('stdio request headers are outside the no-bearer allowlist')
    for value in headers.values():
        if not isinstance(value, str) or len(value) > 256 or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
            _fail('stdio request header value is malformed')
    if method == 'GET':
        if type(frame.get('body_bytes')) is not int or frame['body_bytes'] != 0 or \
                frame.get('body_b64') != '' or 'content-type' in headers:
            _fail('identity and capability reads must not carry a body')
        return b''
    if headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'application/json':
        _fail('encrypted RPC frames must use application/json transport framing')
    encoded = frame.get('body_b64')
    if not isinstance(encoded, str) or len(encoded) > MAX_PACKET_BYTES * 2:
        _fail('stdio request body encoding is malformed')
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('stdio request body encoding is malformed') from error
    if not body or len(body) > MAX_PACKET_BYTES or type(frame.get('body_bytes')) is not int or \
            len(body) != frame['body_bytes'] or base64.b64encode(body).decode('ascii') != encoded:
        _fail('stdio request body length or encoding is invalid')
    return body


def _response_frame(reply: UpstreamReply) -> dict[str, Any]:
    headers = {'content-type': reply.content_type} if reply.content_type else {}
    return {'kind': 'response', 'status': reply.status, 'headers': headers,
        'body_b64': base64.b64encode(reply.body).decode('ascii')}


class FrameAdapter:
    """Bounded ``req`` to ``resp``/``drop`` adapter for one Root-owned session."""

    def __init__(self, manifest: RootManifest, ready: Ready, *, timeout: float = 25.0):
        expected_host, expected_port = _loopback_origin(manifest.upstream_origin)
        if ready.listen != f'{expected_host}:{expected_port}' or ready.raw_sha256 != manifest.ready_raw_sha256:
            _fail('Core READY and fixed upstream origin differ')
        if not 1.0 <= timeout <= 60.0:
            _fail('upstream timeout is outside the bounded profile')
        self.manifest = manifest
        self.ready = ready
        self.router = OpaqueLinkRecoveryRouter(manifest.routing_scope())
        self._origin_host, self._origin_port = expected_host, expected_port
        self._timeout = timeout
        self._frame_count = 0
        self._forward_count = 0
        self._last_status: int | None = None
        self._last_response_sha256: str | None = None
        self._last_fault_raw_sha256: str | None = None
        self._root_ready_envelope: RootReadyEnvelope | None = None

    def install_root_ready_envelope(self, raw_envelope: bytes, *, expected_sha256: str) -> RootReadyEnvelope:
        if self.router.original_packet is None:
            self.router.reject_all()
            _fail('Root FAULT_READY cannot be installed before the selected original packet')
        try:
            envelope = parse_ready_envelope(raw_envelope, self.manifest.routing_scope(),
                self.router.original_packet, self.manifest, expected_sha256=expected_sha256)
            self.router.observe_fault_ready(envelope)
        except (ValueError, TypeError, KeyError):
            self.router.reject_all()
            raise
        self._root_ready_envelope = envelope
        self._last_fault_raw_sha256 = envelope.fault_ready.raw_sha256
        return envelope

    def _call_upstream(self, method: str, path: str, body: bytes) -> UpstreamReply:
        # http.client opens a direct TCP socket and ignores HTTP(S)_PROXY env vars.
        # It never follows redirects. Only numeric 127.0.0.1 from Root is used.
        connection = http.client.HTTPConnection(self._origin_host, self._origin_port, timeout=self._timeout)
        try:
            connection.putrequest(method, path, skip_accept_encoding=True, skip_host=True)
            connection.putheader('Host', f'{self._origin_host}:{self._origin_port}')
            connection.putheader('Accept', 'application/json')
            connection.putheader('Accept-Encoding', 'identity')
            connection.putheader('Connection', 'close')
            if method == 'POST':
                connection.putheader('Content-Type', 'application/json')
                connection.putheader('Content-Length', str(len(body)))
            connection.endheaders(body if method == 'POST' else None)
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                _fail('upstream response exceeded the fixed byte bound')
            encoding = response.getheader('Content-Encoding')
            if encoding not in (None, '', 'identity'):
                _fail('upstream response used an unexpected content encoding')
            content_type = response.getheader('Content-Type')
            if content_type is not None and (len(content_type) > 256 or any(
                    ord(ch) < 0x20 or ord(ch) == 0x7f for ch in content_type)):
                _fail('upstream response content type is malformed')
            return UpstreamReply(response.status, content_type, data)
        finally:
            connection.close()

    def preflight_origin(self) -> None:
        """Check only Root's fixed loopback identity/capabilities after explicit --go."""
        identity = self._call_upstream('GET', '/v2/client/identity', b'')
        capabilities = self._call_upstream('GET', '/v2/client/capabilities', b'')
        if identity.status != 200 or capabilities.status != 200:
            _fail('pinned Core identity/capability preflight did not return HTTP 200')
        identity_value = _parse_json(identity.body, maximum=64 * 1024)
        capabilities_value = _parse_json(capabilities.body, maximum=256 * 1024)
        if not isinstance(identity_value, dict) or identity_value.get('hub_id') != self.manifest.hub_id or \
                not isinstance(capabilities_value, dict) or \
                capabilities_value.get('contract_revision') != CONTRACT_REVISION or \
                capabilities_value.get('catalog_sha256') != CATALOG_SHA256 or \
                capabilities_value.get('external_thread_links') is not False:
            _fail('pinned Core identity or Client capability preflight did not match')

    def handle_frame(self, frame: Mapping[str, Any]) -> dict[str, Any]:
        """Handle one v15 request frame. Invalid input is always a no-body drop."""
        self._frame_count += 1
        try:
            body = _decode_frame_body(frame)
            method, path = frame['method'], frame['path']
            if method == 'GET' and (method, path) not in IDENTITY_ROUTES:
                _fail('GET is outside identity/capability routes')
            if path == RECOVER_PATH and self.router.state == 'AWAITING_FAULT_READY':
                _fail('Root FAULT_READY envelope has not arrived on the separate control FD')
            decision = self.router.authorize(method, path, body)
            self._forward_count += 1
            try:
                reply = self._call_upstream(method, decision.path, body)
            except (OSError, http.client.HTTPException, ValueError, TimeoutError):
                if decision.kind == 'selected':
                    self.router.selected_response_lost()
                elif decision.kind == 'recovery':
                    self.router.complete_recovery(False)
                return {'kind': 'drop'}
            self._last_status = reply.status
            self._last_response_sha256 = hashlib.sha256(reply.body).hexdigest()
            if decision.kind == 'selected':
                # Suppress any HTTP reply, including a fabricated 200. The
                # Android side receives only a connection close/drop frame.
                self.router.selected_response_lost()
                return {'kind': 'drop'}
            if 300 <= reply.status <= 399:
                # Never expose a redirect to a client that may follow it.
                if decision.kind == 'recovery':
                    self.router.complete_recovery(False)
                return {'kind': 'drop'}
            if decision.kind == 'recovery':
                if reply.status == 200:
                    original = self.router.original_route
                    fault = self.router.fault_ready
                    if original is None or fault is None or fault.reserved_response_sequence < 1:
                        self.router.complete_recovery(False)
                        return {'kind': 'drop'}
                    try:
                        parse_response_route(reply.body, self.manifest.routing_scope(), original,
                            expected_sequence=fault.reserved_response_sequence)
                    except ValueError:
                        self.router.complete_recovery(False)
                        return {'kind': 'drop'}
                    if self.manifest.fault_mode == 'response-loss' and \
                            hashlib.sha256(reply.body).hexdigest() != fault.response_sha256:
                        self.router.complete_recovery(False)
                        return {'kind': 'drop'}
                elif self.manifest.fault_mode == 'response-loss':
                    # A completed cached response must recover as the exact
                    # encrypted packet, not an HTTP error or synthetic result.
                    self.router.complete_recovery(False)
                    return {'kind': 'drop'}
                self.router.complete_recovery(True)
            return _response_frame(reply)
        except (ValueError, TypeError, KeyError, binascii.Error):
            # A malformed/unauthorized request consumes this isolated slot;
            # Root must prepare a fresh independent run before another try.
            self.router.reject_all()
            return {'kind': 'drop'}

    def evidence_snapshot(self) -> dict[str, Any]:
        """Return only redacted digests, public counters and state labels."""
        original = self.router.original_route
        fault = self.router.fault_ready
        return {
            'state': self.router.state,
            'request_sha256': self.router.original_request_sha256,
            'response_sha256': self._last_response_sha256,
            'expected_response_sha256': fault.response_sha256 if fault else None,
            'route_sha256': original.route_sha256 if original else None,
            'fault_ready_raw_sha256': self._last_fault_raw_sha256,
            'fault_ready_mode': fault.mode if fault else None,
            'request_status': fault.request_status if fault else None,
            'root_ready_envelope_sha256': self._root_ready_envelope.raw_sha256 \
                if self._root_ready_envelope else None,
            'restart_status': self._root_ready_envelope.restart_status \
                if self._root_ready_envelope else None,
            'restart_receipt_sha256': self._root_ready_envelope.restart_receipt_sha256 \
                if self._root_ready_envelope else None,
            'request_sequence': original.sequence if original else None,
            'reserved_response_sequence': fault.reserved_response_sequence if fault else None,
            'frame_count': self._frame_count,
            'forward_count': self._forward_count,
            'last_http_status': self._last_status,
            'payload_persisted': False,
        }


def _read_private_file(path_value: str, *, expected_sha256: str | None, maximum: int) -> bytes:
    path = Path(path_value)
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or \
                info.st_uid != os.getuid() or info.st_nlink != 1 or not 1 <= info.st_size <= maximum:
            _fail('Root-pinned input must be an owned bounded mode-0600 regular file')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size) != (info.st_dev, info.st_ino, info.st_size):
                _fail('Root-pinned input changed while opening')
            data = bytearray()
            while len(data) <= maximum:
                part = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            after = os.fstat(fd)
            if len(data) != info.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                _fail('Root-pinned input changed while reading')
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError('Root-pinned input is unavailable') from error
    raw = bytes(data)
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        _fail('Root-pinned input differs from its out-of-band SHA-256')
    return raw


def read_root_manifest(path: str, expected_sha256: str) -> RootManifest:
    if not _digest(expected_sha256):
        _fail('out-of-band Root manifest SHA-256 is required')
    raw = _read_private_file(path, expected_sha256=expected_sha256, maximum=MAX_MANIFEST_BYTES)
    value = _parse_json(raw, maximum=MAX_MANIFEST_BYTES)
    if not isinstance(value, dict):
        _fail('Root manifest must be a JSON object')
    return RootManifest.from_mapping(value)


def _read_ready_event(path: str, manifest: RootManifest) -> Ready:
    raw = _read_private_file(path, expected_sha256=manifest.ready_raw_sha256, maximum=MAX_EVENT_BYTES)
    return parse_ready(raw, manifest)


def _write_frame(value: Mapping[str, Any]) -> None:
    raw = (json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError('outbound frame exceeds its fixed byte bound')
    view = memoryview(raw)
    while view:
        count = sys.stdout.buffer.write(view)
        if count is None or count <= 0:
            raise OSError('stdio response channel closed')
        view = view[count:]
    sys.stdout.buffer.flush()


def _handle_control_frame(adapter: FrameAdapter, raw: bytes) -> None:
    if len(raw) > MAX_CONTROL_FRAME_BYTES or not raw.endswith(b'\n'):
        adapter.router.reject_all()
        _fail('Root control frame exceeds its fixed bound')
    value = _parse_json(raw[:-1], maximum=MAX_CONTROL_FRAME_BYTES - 1)
    _exact_keys(value, frozenset({'kind', 'envelope_b64', 'envelope_sha256'}), 'Root control frame')
    encoded = value.get('envelope_b64')
    digest = value.get('envelope_sha256')
    if value.get('kind') != 'fault-ready' or not isinstance(encoded, str) or \
            len(encoded) > MAX_ROOT_READY_BYTES * 2 or not _digest(digest):
        adapter.router.reject_all()
        _fail('Root control frame is malformed')
    try:
        raw_envelope = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        adapter.router.reject_all()
        raise ValueError('Root control envelope encoding is malformed') from error
    if not raw_envelope or base64.b64encode(raw_envelope).decode('ascii') != encoded:
        adapter.router.reject_all()
        _fail('Root control envelope encoding is not canonical')
    adapter.install_root_ready_envelope(raw_envelope, expected_sha256=digest)


def run_stdio(adapter: FrameAdapter, control_fd: int) -> None:
    """Run the existing req/resp/drop protocol with a separate Root control FD."""
    if control_fd < 3 or control_fd in (sys.stdin.fileno(), sys.stdout.fileno()):
        _fail('Root control FD must be a separate inherited descriptor')
    mode = os.fstat(control_fd).st_mode
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        _fail('Root control FD must be a private pipe or socket')
    selector = selectors.DefaultSelector()
    selector.register(sys.stdin.fileno(), selectors.EVENT_READ, 'android')
    selector.register(control_fd, selectors.EVENT_READ, 'root')
    buffers = {'android': bytearray(), 'root': bytearray()}
    seen_root_envelope = False
    try:
        while True:
            events = selector.select()
            # Process Root readiness before Android recovery frames if both
            # channels become readable together.
            events.sort(key=lambda event: 0 if event[0].data == 'root' else 1)
            for key, _mask in events:
                channel = key.data
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    if channel == 'android':
                        return
                    selector.unregister(key.fd)
                    continue
                buf = buffers[channel]
                buf.extend(chunk)
                bound = MAX_FRAME_BYTES if channel == 'android' else MAX_CONTROL_FRAME_BYTES
                if len(buf) > bound and b'\n' not in buf:
                    if channel == 'android':
                        _write_frame({'kind': 'drop'})
                    adapter.router.reject_all()
                    return
                while b'\n' in buf:
                    line, _, tail = buf.partition(b'\n')
                    buf[:] = tail
                    raw = bytes(line) + b'\n'
                    if channel == 'root':
                        if seen_root_envelope:
                            adapter.router.reject_all()
                            _fail('Root may install only one immutable FAULT_READY envelope')
                        _handle_control_frame(adapter, raw)
                        seen_root_envelope = True
                    else:
                        try:
                            if len(raw) > MAX_FRAME_BYTES:
                                _fail('Android frame exceeds its fixed bound')
                            frame = _parse_json(raw[:-1], maximum=MAX_FRAME_BYTES - 1)
                            if not isinstance(frame, dict):
                                _fail('Android frame must be a JSON object')
                            response = adapter.handle_frame(frame)
                        except (ValueError, TypeError, KeyError, binascii.Error):
                            adapter.router.reject_all()
                            response = {'kind': 'drop'}
                        _write_frame(response)
    finally:
        selector.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root-manifest', required=True)
    parser.add_argument('--manifest-sha256', required=True,
        help='out-of-band SHA-256 for exact Root manifest bytes')
    parser.add_argument('--scenario', required=True,
        help='exact v2 per-slot recovery scenario, mode-0600 and Root-owned')
    parser.add_argument('--scenario-sha256', required=True,
        help='out-of-band SHA-256 for exact four-field scenario bytes')
    parser.add_argument('--ready-event', required=True,
        help='raw Core READY JSONL event, mode-0600 and hash-pinned by manifest')
    parser.add_argument('--control-fd', type=int, required=True,
        help='separate Root-owned pipe/socket for one late FAULT_READY envelope and its external SHA')
    parser.add_argument('--go', action='store_true',
        help='independent explicit GO after Root attests current image and process identity')
    args = parser.parse_args()
    os.umask(0o077)
    if args.go is not True:
        parser.error('an independent --go opt-in is required; no network request was made')
    try:
        manifest = read_root_manifest(args.root_manifest, args.manifest_sha256)
        scenario_raw = _read_private_file(args.scenario, expected_sha256=args.scenario_sha256,
            maximum=MAX_SCENARIO_BYTES)
        scenario = parse_scenario(scenario_raw, run_id=manifest.run_id)
        if scenario.expected_operation != manifest.expected_operation or scenario.fault_mode != manifest.fault_mode:
            _fail('scenario differs from the fixed Root carrier manifest')
        ready = _read_ready_event(args.ready_event, manifest)
        adapter = FrameAdapter(manifest, ready)
        # The only startup network calls are direct, fixed-loopback identity
        # and capability reads. They happen after --go and before Android frames.
        adapter.preflight_origin()
        run_stdio(adapter, args.control_fd)
    except (ValueError, OSError, TypeError, KeyError, http.client.HTTPException, TimeoutError):
        # Protocol channels carry only bounded frames. Never echo an exception
        # that could contain a URL, request detail, or private configuration.
        raise SystemExit(1)


if __name__ == '__main__':
    main()
