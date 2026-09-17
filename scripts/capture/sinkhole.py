#!/usr/bin/env python3
"""Catch-all TCP listener for the malware capture VM.

Every outbound connection a sample makes, other than to the npm registry, is
redirected here by harden-vm.sh. The connection completes normally from the
sample's point of view, which is the point: the connect() syscall succeeds and
the TCP session reaches ESTABLISHED, so the monitor records tcp_remote_ips,
tcp_state_transitions and tcp_remote_ports faithfully. Dropping the traffic
instead would truncate every C2 attempt at SYN_SENT and destroy exactly the
features the capture exists to collect.

It also produces a useful secondary record. The original destination is
recovered via SO_ORIGINAL_DST, so the log shows where each sample *meant* to
connect, not just that it tried something.

Nothing is ever forwarded. Received bytes are logged (truncated, hex-escaped)
and discarded.

Usage:
    python3 sinkhole.py --port 9999 --log /var/log/capture/sinkhole.jsonl
"""

from __future__ import annotations

import argparse
import json
import socket
import socketserver
import struct
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

# Linux-specific getsockopt level/option for recovering the pre-DNAT
# destination address.
SO_ORIGINAL_DST = 80

MAX_CAPTURE_BYTES = 512
RECV_TIMEOUT_SECS = 5.0


def original_destination(sock: socket.socket) -> tuple[str, int] | None:
    """Return the pre-DNAT destination of sock, or None if unavailable.

    Without this the log would only ever show the sinkhole's own address,
    which tells us a sample tried to connect somewhere but not where.
    """
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None

    # struct sockaddr_in: family (2), port (2, network order), addr (4)
    _family, port, a, b, c, d = struct.unpack("!HHBBBB", raw[:8])
    return f"{a}.{b}.{c}.{d}", port


class SinkholeHandler(socketserver.BaseRequestHandler):
    log_lock = threading.Lock()
    log_path: Path | None = None

    def handle(self) -> None:
        peer_ip, peer_port = self.client_address[:2]
        dest = original_destination(self.request)

        payload = b""
        try:
            self.request.settimeout(RECV_TIMEOUT_SECS)
            payload = self.request.recv(MAX_CAPTURE_BYTES)
        except (OSError, socket.timeout):
            # A client that connects and says nothing is still worth recording;
            # plenty of C2 implants wait for the server to speak first.
            pass
        finally:
            try:
                self.request.close()
            except OSError:
                pass

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": peer_ip,
            "source_port": peer_port,
            "original_dest_ip": dest[0] if dest else None,
            "original_dest_port": dest[1] if dest else None,
            "bytes_received": len(payload),
            "payload_preview": payload[:MAX_CAPTURE_BYTES].hex() or None,
        }
        self.emit(record)

    def emit(self, record: dict) -> None:
        line = json.dumps(record)

        with SinkholeHandler.log_lock:
            print(line, flush=True)
            if SinkholeHandler.log_path is not None:
                with SinkholeHandler.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0",
                        help="address to bind (default: all interfaces)")
    parser.add_argument("--port", type=int, default=9999,
                        help="port to listen on; must match SINKHOLE_PORT in harden-vm.sh")
    parser.add_argument("--log", type=Path, default=None,
                        help="append JSONL records to this file as well as stdout")
    args = parser.parse_args()

    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        SinkholeHandler.log_path = args.log

    server = ThreadedTCPServer((args.host, args.port), SinkholeHandler)
    print(
        f"sinkhole listening on {args.host}:{args.port}"
        + (f", logging to {args.log}" if args.log else ""),
        file=sys.stderr,
        flush=True,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("sinkhole stopping", file=sys.stderr)
    finally:
        server.shutdown()
        server.server_close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
