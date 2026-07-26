"""Mac-side telemetry collector: a dependency-free TCP server that receives the iOS
DEBUG build's newline-delimited JSON telemetry and buffers it in memory by phase.

Stdlib only (socket, threading) so `python -m harness.collector` runs anywhere the
backend runs — no extra installs for the local operator (or local Claude Code) to fight.

Usage is normally indirect: `runner.py` starts a Collector, marks phase boundaries as
the operator steps through the test, and reads back the events captured in each phase
window for scoring. It can also run standalone to eyeball the live stream:

    python -m harness.collector --host 0.0.0.0 --port 7731
"""
from __future__ import annotations

import argparse
import socket
import threading
import time
from typing import Callable, List, Optional

from harness.protocol import TelemetryEvent


class Collector:
    """Accepts one or more phone connections; appends every event to a shared, locked
    list with a harness arrival timestamp. Thread-safe; snapshot() is cheap."""

    def __init__(self, host: str = "0.0.0.0", port: int = 7731,
                 on_event: Optional[Callable[[TelemetryEvent], None]] = None):
        self.host = host
        self.port = port
        self._events: List[TelemetryEvent] = []
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []
        self._running = False
        self._on_event = on_event

    # --- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(4)
        self._sock.settimeout(0.5)
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    # --- internals ---------------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._sock is not None
        while self._running:
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._read_conn, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _read_conn(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        buf = b""
        with conn:
            while self._running:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = TelemetryEvent.from_line(line.decode("utf-8"))
                    except (ValueError, TypeError):
                        continue  # skip malformed lines rather than crash a run
                    ev.rx_t = time.monotonic()
                    with self._lock:
                        self._events.append(ev)
                    if self._on_event:
                        self._on_event(ev)

    # --- reads -------------------------------------------------------------
    def snapshot(self) -> List[TelemetryEvent]:
        with self._lock:
            return list(self._events)

    def since(self, rx_start: float) -> List[TelemetryEvent]:
        """Events whose harness arrival time is >= rx_start (a phase window)."""
        with self._lock:
            return [e for e in self._events if e.rx_t is not None and e.rx_t >= rx_start]

    def count(self) -> int:
        with self._lock:
            return len(self._events)


def _main() -> None:
    ap = argparse.ArgumentParser(description="Atlas debug-telemetry collector")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=7731)
    args = ap.parse_args()
    c = Collector(host=args.host, port=args.port,
                  on_event=lambda e: print(e.to_line(), flush=True))
    c.start()
    print(f"[collector] listening on {args.host}:{args.port} (Ctrl-C to stop)", flush=True)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        c.stop()
        print(f"\n[collector] stopped; {c.count()} events captured", flush=True)


if __name__ == "__main__":
    _main()
