#!/usr/bin/env python3
"""Payload-silent TCP forwarding inside an owned disposable Android container.

ADB reverse connects the guest to this loopback listener. The caller must pin
the exact disposable Hub image and Docker network before supplying its IP.
This transport adapter never parses, decrypts or logs Client packets.
"""

import argparse
import ipaddress
import select
import socket
import socketserver
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--target-ip', required=True)
    parser.add_argument('--target-port', type=int, required=True)
    args = parser.parse_args()
    address = ipaddress.IPv4Address(args.target_ip)
    if not address.is_private or address.is_loopback or address.is_unspecified or \
            not all(1024 <= port <= 65535 for port in (args.listen_port, args.target_port)):
        parser.error('expected a private disposable Hub IP and nonprivileged ports')
    slots = threading.BoundedSemaphore(16)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if not slots.acquire(blocking=False):
                return
            try:
                with socket.create_connection((str(address), args.target_port), timeout=5) as upstream:
                    peers = {self.request: upstream, upstream: self.request}
                    while peers:
                        ready, _, _ = select.select(list(peers), [], [], 60)
                        if not ready:
                            return
                        for source in ready:
                            chunk = source.recv(64 * 1024)
                            destination = peers[source]
                            if chunk:
                                destination.sendall(chunk)
                            else:
                                destination.shutdown(socket.SHUT_WR)
                                del peers[source]
            except (OSError, ValueError):
                pass
            finally:
                slots.release()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

        def handle_error(self, _request, _client_address):
            pass

    with Server(('127.0.0.1', args.listen_port), Handler) as server:
        print('FORWARD_READY', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
