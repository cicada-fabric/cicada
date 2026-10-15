#!/usr/bin/env python3
"""Offline tests for the v1.6.4 opaque Link recovery frame adapter."""

from __future__ import annotations

import base64
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import socket
import sys
import threading
import unittest


MODULE_PATH = Path(__file__).with_name('v164-link-recovery-carrier.py')
SPEC = importlib.util.spec_from_file_location('v164_link_recovery_carrier', MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
carrier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = carrier
SPEC.loader.exec_module(carrier)


RUN_ID = 'v164-offline-test'
HUB_ID = 'hub-offline-01'
OWNER_ID = 'owner-offline-01'
DEVICE_ID = 'device-offline-01'
OPERATION_ID = 'offline-operation-01'
REQUEST_SEQUENCE = 11
RESPONSE_SEQUENCE = 6


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def make_request_packet() -> bytes:
    return compact({
        'route': {
            'version': 1, 'direction': 'REQUEST', 'hub_id': HUB_ID, 'owner_id': OWNER_ID,
            'device_id': DEVICE_ID, 'session_epoch': 7, 'sequence': REQUEST_SEQUENCE,
            'operation_id': OPERATION_ID, 'operation': 'link.key_grant',
            'sender_key_id': 'device-key-1', 'sender_key_version': 3,
            'receiver_key_id': 'hub-key-1', 'receiver_key_version': 4,
        },
        'envelope': base64.b64encode(b'opaque request ciphertext fixture').decode(),
    })


def make_response_packet(sequence: int = RESPONSE_SEQUENCE) -> bytes:
    return compact({
        'route': {
            'version': 1, 'direction': 'RESPONSE', 'hub_id': HUB_ID, 'owner_id': OWNER_ID,
            'device_id': DEVICE_ID, 'session_epoch': 7, 'sequence': sequence,
            'operation_id': OPERATION_ID, 'operation': 'link.key_grant',
            'sender_key_id': 'hub-key-1', 'sender_key_version': 4,
            'receiver_key_id': 'device-key-1', 'receiver_key_version': 3,
        },
        'envelope': base64.b64encode(b'opaque response ciphertext fixture').decode(),
    })


def make_fault_line(mode: str, packet: bytes, response: bytes | None = None) -> bytes:
    fields = {
        'event': 'FAULT_READY', 'mode': mode, 'operation': 'link.key_grant',
        'request_sha256': hashlib.sha256(packet).hexdigest(), 'request_sequence': REQUEST_SEQUENCE,
        'business_outcome': 'UNKNOWN',
    }
    if mode == 'response-loss':
        assert response is not None
        fields.update({
            'handler_executed': True, 'scope': 'REAL_HANDLER_COMPLETED_TRANSPORT',
            'request_status': 'COMPLETED', 'reserved_response_sequence': RESPONSE_SEQUENCE,
            'response_sha256': hashlib.sha256(response).hexdigest(),
        })
    else:
        status, reserved = {
            'processing': ('PROCESSING', 0),
            'uncertain': ('PROCESSING', RESPONSE_SEQUENCE),
            'legacy': ('UNCERTAIN', 0),
        }[mode]
        fields.update({
            'handler_executed': False, 'scope': 'OUTER_RPC_LEDGER_ONLY',
            'request_status': status, 'reserved_response_sequence': reserved,
            'restart_required': mode == 'uncertain',
        })
    return compact(fields) + b'\n'


class SyntheticCoreHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = ''
    sys_version = ''

    def log_message(self, *_args: object) -> None:
        pass

    def _send(self, status: int, body: bytes, content_type: str = 'application/json') -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self) -> None:
        self.server.calls.append((self.command, self.path, b''))  # type: ignore[attr-defined]
        if self.path == '/v2/client/identity':
            self._send(200, compact({'hub_id': HUB_ID}))
        elif self.path == '/v2/client/capabilities':
            self._send(200, compact({
                'contract_revision': carrier.CONTRACT_REVISION,
                'catalog_sha256': carrier.CATALOG_SHA256,
                'external_thread_links': False,
            }))
        elif self.path == '/v2/client/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://example.invalid/outside')
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self._send(404, b'{}')

    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        self.server.calls.append((self.command, self.path, body))  # type: ignore[attr-defined]
        if self.path == carrier.RPC_PATH and getattr(self.server, 'drop_selected', False):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            self.close_connection = True
            return
        if self.path == carrier.RPC_PATH:
            # An HTTP response from the selected request must be suppressed.
            self._send(200, make_response_packet())
        elif self.path == carrier.RECOVER_PATH:
            self._send(200, self.server.recovery_packet)  # type: ignore[attr-defined]
        else:
            self._send(404, b'{}')


class CarrierTests(unittest.TestCase):
    def test_route_counters_reject_values_outside_native_long_before_forwarding(self) -> None:
        scope = self.manifest.routing_scope()
        for field in ('sequence', 'session_epoch', 'sender_key_version', 'receiver_key_version'):
            for invalid in (1 << 63, (1 << 64) - 1, True, 41.0, '41', -1):
                with self.subTest(field=field, value=invalid):
                    packet = json.loads(self.request_packet)
                    packet['route'][field] = invalid
                    with self.assertRaises(ValueError):
                        carrier.parse_request_route(compact(packet), scope)
        adapter = carrier.FrameAdapter(self.manifest, carrier.parse_ready(self.ready_line, self.manifest))
        frame = {'kind': 'request', 'method': 'GET', 'path': '/v2/client/identity',
            'headers': {}, 'body_b64': '', 'body_bytes': False}
        self.assertEqual(adapter.handle_frame(frame), {'kind': 'drop'})
        self.assertEqual(adapter.evidence_snapshot()['forward_count'], 0)

    def setUp(self) -> None:
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), SyntheticCoreHandler)
        self.server.daemon_threads = True
        self.server.calls = []  # type: ignore[attr-defined]
        self.server.drop_selected = False  # type: ignore[attr-defined]
        self.response_packet = make_response_packet()
        self.server.recovery_packet = self.response_packet  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.request_packet = make_request_packet()
        ready_line = compact({
            'event': 'READY', 'mode': 'response-loss', 'operation': 'link.key_grant',
            'listen': f'127.0.0.1:{self.server.server_port}',
            'contract_revision': carrier.CONTRACT_REVISION,
            'catalog_sha256': carrier.CATALOG_SHA256, 'wire_version': carrier.WIRE_VERSION,
        }) + b'\n'
        self.manifest_value = {
            'schema': carrier.MANIFEST_SCHEMA, 'run_id': RUN_ID, 'run_scope': 'offline-test-slot',
            'core_revision': carrier.CORE_REVISION, 'hub_image_id': carrier.HUB_IMAGE_ID,
            'source_fingerprint': carrier.SOURCE_FINGERPRINT, 'catalog_sha256': carrier.CATALOG_SHA256,
            'contract_revision': carrier.CONTRACT_REVISION, 'wire_version': carrier.WIRE_VERSION,
            'fixture_pid': 12345, 'fixture_process_start': '987654321',
            'helper_sha256': 'a' * 64, 'ready_raw_sha256': hashlib.sha256(ready_line).hexdigest(),
            'hub_id': HUB_ID, 'upstream_origin': f'http://127.0.0.1:{self.server.server_port}',
            'android_base_url': 'http://127.0.0.1:8790', 'owner_id': OWNER_ID,
            'device_id': DEVICE_ID, 'session_epoch': 7, 'expected_operation': 'link.key_grant',
            'fault_mode': 'response-loss',
        }
        self.manifest = carrier.RootManifest.from_mapping(self.manifest_value)
        self.ready_line = ready_line
        self.ready = carrier.parse_ready(ready_line, self.manifest)
        self.adapter = carrier.FrameAdapter(self.manifest, self.ready)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request_frame(self, path: str = carrier.RPC_PATH, body: bytes | None = None,
            headers: dict[str, str] | None = None) -> dict[str, object]:
        packet = self.request_packet if body is None else body
        supplied_headers = {'content-type': 'application/json'} if headers is None else headers
        return {
            'kind': 'request', 'method': 'POST', 'path': path, 'headers': supplied_headers,
            'body_b64': base64.b64encode(packet).decode(), 'body_bytes': len(packet),
        }

    def root_envelope(self, mode: str = 'response-loss', response: bytes | None = None,
            *, restart: dict[str, object] | None = None) -> tuple[bytes, str]:
        raw_event = make_fault_line(mode, self.request_packet, response)
        wrapper = {
            'schema': carrier.ROOT_READY_SCHEMA, 'run_id': RUN_ID,
            'hub_source': self.manifest.hub_source(),
            'fault_ready_raw_base64': base64.b64encode(raw_event).decode(),
            'fault_ready_raw_sha256': hashlib.sha256(raw_event).hexdigest(),
            'restart': restart if restart is not None else {'status': 'NOT_REQUIRED', 'receipt_sha256': None},
        }
        raw_wrapper = compact(wrapper)
        return raw_wrapper, hashlib.sha256(raw_wrapper).hexdigest()

    def test_selected_http_response_is_always_a_drop_then_exact_recovery_bytes_return(self) -> None:
        self.adapter.preflight_origin()
        selected = self.adapter.handle_frame(self.request_frame())
        self.assertEqual(selected, {'kind': 'drop'})
        self.assertEqual(self.adapter.router.state, 'AWAITING_FAULT_READY')
        self.assertEqual(self.server.calls[-1], ('POST', carrier.RPC_PATH, self.request_packet))  # type: ignore[index]

        envelope, digest = self.root_envelope(response=self.response_packet)
        self.adapter.install_root_ready_envelope(envelope, expected_sha256=digest)
        recovery = self.adapter.handle_frame(self.request_frame(carrier.RECOVER_PATH))
        self.assertEqual(recovery['kind'], 'response')
        self.assertEqual(base64.b64decode(recovery['body_b64'], validate=True), self.response_packet)
        self.assertEqual(self.server.calls[-1], ('POST', carrier.RECOVER_PATH, self.request_packet))  # type: ignore[index]

        evidence = self.adapter.evidence_snapshot()
        self.assertEqual(evidence['state'], 'RECOVERY_RESPONDED')
        self.assertEqual(evidence['request_sha256'], hashlib.sha256(self.request_packet).hexdigest())
        self.assertEqual(evidence['response_sha256'], hashlib.sha256(self.response_packet).hexdigest())
        self.assertEqual(evidence['expected_response_sha256'], evidence['response_sha256'])
        self.assertEqual(evidence['restart_status'], 'NOT_REQUIRED')
        self.assertEqual(evidence['root_ready_envelope_sha256'], digest)
        self.assertNotIn('owner_id', evidence)
        self.assertFalse(evidence['payload_persisted'])

        # A second recovery is rejected without a second upstream request.
        count = len(self.server.calls)  # type: ignore[arg-type]
        self.assertEqual(self.adapter.handle_frame(self.request_frame(carrier.RECOVER_PATH)), {'kind': 'drop'})
        self.assertEqual(len(self.server.calls), count)  # type: ignore[arg-type]
        self.assertEqual(self.adapter.router.state, 'FAILED')

    def test_actual_upstream_connection_close_maps_to_drop_not_http_200(self) -> None:
        self.server.drop_selected = True  # type: ignore[attr-defined]
        result = self.adapter.handle_frame(self.request_frame())
        self.assertEqual(result, {'kind': 'drop'})
        self.assertNotIn('status', result)
        self.assertEqual(self.adapter.router.state, 'AWAITING_FAULT_READY')
        self.assertEqual(len(self.server.calls), 1)  # type: ignore[arg-type]

    def test_response_loss_recovery_digest_mismatch_is_dropped(self) -> None:
        self.assertEqual(self.adapter.handle_frame(self.request_frame()), {'kind': 'drop'})
        expected = make_response_packet()
        # Same public route, different opaque ciphertext bytes.
        expected = expected.replace(
            base64.b64encode(b'opaque response ciphertext fixture'),
            base64.b64encode(b'different opaque response ciphertext'))
        envelope, digest = self.root_envelope(response=expected)
        self.adapter.install_root_ready_envelope(envelope, expected_sha256=digest)
        self.assertEqual(self.adapter.handle_frame(self.request_frame(carrier.RECOVER_PATH)), {'kind': 'drop'})
        self.assertEqual(self.adapter.router.state, 'RECOVERY_DROPPED')
        self.assertEqual(len(self.server.calls), 2)  # type: ignore[arg-type]

    def test_no_bearer_or_extra_request_headers_and_no_query_routes(self) -> None:
        query = self.request_frame()
        query['path'] = carrier.RPC_PATH + '?follow=1'
        self.assertEqual(self.adapter.handle_frame(query), {'kind': 'drop'})
        self.assertEqual(self.server.calls, [])  # type: ignore[comparison-overlap]

        # A separate fresh adapter demonstrates the auth-header rejection.
        self.adapter = carrier.FrameAdapter(self.manifest, self.ready)
        denied = self.request_frame(headers={'authorization': 'Bearer forbidden'})
        self.assertEqual(self.adapter.handle_frame(denied), {'kind': 'drop'})
        self.assertEqual(self.server.calls, [])  # type: ignore[comparison-overlap]

    def test_ready_envelope_requires_external_hash_and_root_restart_for_uncertain(self) -> None:
        for mode in carrier.FAULT_MODES:
            response = self.response_packet if mode == 'response-loss' else None
            raw_event = make_fault_line(mode, self.request_packet, response)
            scope = carrier.RawRoutingScope(RUN_ID, HUB_ID, OWNER_ID, DEVICE_ID, 7,
                'link.key_grant', mode)
            parsed = carrier.parse_fault_ready(raw_event, scope, self.request_packet)
            self.assertEqual(parsed.mode, mode)
            self.assertEqual(parsed.request_sha256, hashlib.sha256(self.request_packet).hexdigest())
        uncertain_raw = make_fault_line('uncertain', self.request_packet)
        uncertain_manifest_value = dict(self.manifest_value)
        uncertain_ready_line = compact({
            'event': 'READY', 'mode': 'uncertain', 'operation': 'link.key_grant',
            'listen': f'127.0.0.1:{self.server.server_port}',
            'contract_revision': carrier.CONTRACT_REVISION,
            'catalog_sha256': carrier.CATALOG_SHA256, 'wire_version': carrier.WIRE_VERSION,
        }) + b'\n'
        uncertain_manifest_value.update({
            'fault_mode': 'uncertain',
            'ready_raw_sha256': hashlib.sha256(uncertain_ready_line).hexdigest(),
        })
        uncertain_manifest = carrier.RootManifest.from_mapping(uncertain_manifest_value)
        uncertain_scope = uncertain_manifest.routing_scope()
        wrapper = {
            'schema': carrier.ROOT_READY_SCHEMA, 'run_id': RUN_ID,
            'hub_source': uncertain_manifest.hub_source(),
            'fault_ready_raw_base64': base64.b64encode(uncertain_raw).decode(),
            'fault_ready_raw_sha256': hashlib.sha256(uncertain_raw).hexdigest(),
            'restart': {'status': 'NOT_REQUIRED', 'receipt_sha256': None},
        }
        encoded = compact(wrapper)
        with self.assertRaises(ValueError):
            carrier.parse_ready_envelope(encoded, uncertain_scope, self.request_packet,
                uncertain_manifest, expected_sha256=hashlib.sha256(encoded).hexdigest())

        wrapper['restart'] = {'status': 'VERIFIED', 'receipt_sha256': 'b' * 64}
        encoded = compact(wrapper)
        parsed = carrier.parse_ready_envelope(encoded, uncertain_scope, self.request_packet,
            uncertain_manifest, expected_sha256=hashlib.sha256(encoded).hexdigest())
        self.assertEqual(parsed.restart_status, 'VERIFIED')
        with self.assertRaises(ValueError):
            carrier.parse_ready_envelope(encoded, uncertain_scope, self.request_packet,
                uncertain_manifest, expected_sha256='c' * 64)

    def test_scenario_v2_is_exactly_four_fields_and_pinned_to_run(self) -> None:
        raw = compact({
            'schema': carrier.SCENARIO_SCHEMA, 'run_id': RUN_ID,
            'expected_operation': 'link.key_grant', 'fault_mode': 'legacy',
        })
        parsed = carrier.parse_scenario(raw, run_id=RUN_ID)
        self.assertEqual(parsed.fault_mode, 'legacy')
        with self.assertRaises(ValueError):
            carrier.parse_scenario(compact({
                'schema': carrier.SCENARIO_SCHEMA, 'run_id': RUN_ID,
                'expected_operation': 'link.key_grant', 'fault_mode': 'legacy', 'extra': False,
            }))
        with self.assertRaises(ValueError):
            carrier.parse_scenario(raw, run_id='v164-another-slot')

    def test_manifest_rejects_url_rewrite_and_unapproved_emulator_port(self) -> None:
        for value in ('http://127.0.0.1:8790/rpc', 'http://127.0.0.1:8790?x=1',
                'http://10.0.2.2:8791', 'http://localhost:8790'):
            manifest = dict(self.manifest_value)
            manifest['android_base_url'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                carrier.RootManifest.from_mapping(manifest)


if __name__ == '__main__':
    unittest.main(verbosity=2)
