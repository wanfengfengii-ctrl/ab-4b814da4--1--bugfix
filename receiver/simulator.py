"""Emergency broadcast gateway simulator.

Behaviour contract (the thing the real gateway would implement):
  * POST /ingest with headers X-Delivery-Id, X-Signature and a JSON body.
  * The HMAC-SHA256 signature is verified over (deliveryId, SHA-256(body))
    with the shared secret; bad/missing signatures are rejected with 401.
  * Each deliveryId is business-accepted at most once and persisted in
    SQLite. Re-delivery of the same deliveryId with the identical body
    replays the ORIGINAL acceptance (HTTP 200, duplicate=true) - this is what
    makes a retry after "admitted then connection dropped" safe.
  * Same deliveryId with a different body is tampering -> 409.
  * Unknown deliveryId and valid request -> 201 accepted once.

Every /ingest request (including rejected ones) is appended to request_log so
tests can prove each retry carried the identical body and signature.

Test-only fault injection behind X-Sim-Token (POST /sim/control):
  {"mode": "http", "code": 503, "count": 2}   next 2 requests get that code
  {"mode": "drop", "count": 1}                accept (if valid) then drop TCP
  {"mode": "delay", "count": 1, "delay": 4}   stall before accepting, then 201
  {"mode": null}                              clear
Already-accepted deliveries are replayed BEFORE fault injection, so a
drop/delay/5xx after the first acceptance never loses the acknowledgement.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from app.signing import body_digest, verify

RECEIVER_DB = os.getenv("RECEIVER_DB", os.path.join("data", "receiver.db"))
RECEIVER_HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")
RECEIVER_PORT = int(os.getenv("RECEIVER_PORT", "9090"))
SHARED_SECRET = os.getenv("SHARED_SECRET", "dev-shared-secret-change-me")
SIM_TOKEN = os.getenv("SIM_FAULT_TOKEN", "dev-sim-token")

_create = """
CREATE TABLE IF NOT EXISTS receipts (
    delivery_id TEXT PRIMARY KEY,
    body_sha256 TEXT NOT NULL,
    accepted_at REAL NOT NULL,
    receipt_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    delivery_id TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    body_text TEXT,
    signature TEXT,
    http_status INTEGER NOT NULL
) STRICT;
"""

_db_lock = threading.Lock()


def open_db(path: str) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.executescript(_create)
    # Migration for databases created before request bodies were retained.
    try:
        conn.execute("ALTER TABLE request_log ADD COLUMN body_text TEXT")
    except sqlite3.OperationalError:
        pass  # column already present
    conn.commit()
    return conn


class FaultPlan:
    def __init__(self) -> None:
        self.mode: str | None = None
        self.code = 503
        self.count = 0
        self.delay = 0.0
        self._lock = threading.Lock()

    def configure(self, spec: dict) -> None:
        mode = spec.get("mode")
        if mode is not None and mode not in ("http", "drop", "delay"):
            raise ValueError("mode must be one of: http, drop, delay")
        with self._lock:
            self.mode = mode
            self.code = int(spec.get("code", 503))
            self.count = int(spec.get("count", 1))
            self.delay = float(spec.get("delay", 4.0))

    def consume(self) -> dict | None:
        """Return the fault to apply for this request, or None."""
        with self._lock:
            if self.mode is None or self.count <= 0:
                return None
            self.count -= 1
            fault = {"mode": self.mode, "code": self.code, "delay": self.delay}
            if self.count <= 0:
                self.mode = None
            return fault


FAULT = FaultPlan()


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "BroadcastGatewaySim/1.0"

    # Injected by build_server / main:
    db: sqlite3.Connection = None  # type: ignore[assignment]
    secret: str = SHARED_SECRET
    sim_token: str = SIM_TOKEN
    fault: FaultPlan = FAULT

    def log_message(self, fmt: str, *args) -> None:
        logging.getLogger("gateway-sim").info("%s - %s", self.address_string(), fmt % args)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The client (delivery worker) timed out or gave up and closed the
            # connection; the acceptance itself is already durable.
            self.close_connection = True

    def _log_request(self, delivery_id: str, body: bytes, signature: str, status: int) -> None:
        body_digest_hex = body_digest(body) if body else ""
        body_text = body.decode("utf-8", "replace") if body else None
        with _db_lock:
            self.db.execute(
                "INSERT INTO request_log"
                " (ts, delivery_id, body_sha256, body_text, signature, http_status)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), delivery_id, body_digest_hex, body_text, signature, status),
            )
            self.db.commit()

    def do_GET(self) -> None:  # noqa: N802
        split = urlsplit(self.path)
        path = split.path
        if path == "/healthz":
            self.db.execute("SELECT 1").fetchone()
            self._json(200, {"status": "ok", "service": "broadcast-gateway-sim"})
            return
        if path == "/sim/accepted":
            rows = self.db.execute(
                "SELECT delivery_id, accepted_at FROM receipts ORDER BY accepted_at"
            ).fetchall()
            self._json(200, {"accepted": [dict(r) for r in rows]})
            return
        if path == "/sim/requests":
            query = parse_qs(split.query)
            delivery_id = (query.get("deliveryId") or [""])[0]
            if delivery_id:
                rows = self.db.execute(
                    "SELECT ts, delivery_id, body_sha256, body_text, signature, http_status"
                    " FROM request_log WHERE delivery_id = ? ORDER BY id",
                    (delivery_id,),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT ts, delivery_id, body_sha256, body_text, signature, http_status"
                    " FROM request_log ORDER BY id"
                ).fetchall()
            self._json(200, {"requests": [dict(r) for r in rows]})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802, C901
        path = urlsplit(self.path).path
        if path == "/sim/control":
            self._control()
            return
        if path != "/ingest":
            self._json(404, {"error": "not found"})
            return

        delivery_id = self.headers.get("X-Delivery-Id", "")
        signature = self.headers.get("X-Signature", "")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid Content-Length"})
            return
        body = self.rfile.read(length) if 0 < length <= 1_000_000 else b""

        if not delivery_id:
            self._json(400, {"error": "missing X-Delivery-Id"})
            return
        if not body:
            self._json(400, {"error": "empty body"})
            return
        if not verify(self.secret, delivery_id, body, signature):
            self._log_request(delivery_id, body, signature, 401)
            self._json(401, {"error": "signature verification failed"})
            return

        # Idempotent replay takes precedence: once accepted, always acknowledged.
        row = self.db.execute(
            "SELECT receipt_json, body_sha256 FROM receipts WHERE delivery_id = ?",
            (delivery_id,),
        ).fetchone()
        if row is not None:
            if row["body_sha256"] != body_digest(body):
                self._log_request(delivery_id, body, signature, 409)
                self._json(409, {"error": "deliveryId reused with different body",
                                 "deliveryId": delivery_id})
                return
            receipt = json.loads(row["receipt_json"])
            receipt["duplicate"] = True
            receipt["message"] = "already accepted; replaying original acceptance"
            self._log_request(delivery_id, body, signature, 200)
            self._json(200, receipt)
            return

        fault = self.fault.consume()
        if fault and fault["mode"] == "delay":
            time.sleep(fault["delay"])
        if fault and fault["mode"] == "http":
            self._log_request(delivery_id, body, signature, fault["code"])
            self._json(fault["code"], {"error": f"injected fault {fault['code']}"})
            return

        # First (and only) business acceptance.
        receipt = self._accept(delivery_id, body)
        if fault and fault["mode"] == "drop":
            # Gateway admitted it, but the connection dies before any response
            # reaches the API. The acceptance is already durable.
            self._log_request(delivery_id, body, signature, 0)
            logging.getLogger("gateway-sim").warning(
                "injected drop for delivery %s AFTER durable acceptance", delivery_id)
            self.close_connection = True
            try:
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            except OSError:
                pass
            return
        status = 201 if not receipt.get("duplicate") else 200
        self._log_request(delivery_id, body, signature, status)
        self._json(status, receipt)

    def _control(self) -> None:
        if self.headers.get("X-Sim-Token") != self.sim_token:
            self._json(401, {"error": "sim control requires X-Sim-Token"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            spec = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            self.fault.configure(spec)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, {"configured": {"mode": self.fault.mode, "count": self.fault.count,
                                        "code": self.fault.code, "delay": self.fault.delay}})

    def _accept(self, delivery_id: str, body: bytes) -> dict:
        now = time.time()
        receipt = {
            "accepted": True,
            "deliveryId": delivery_id,
            "gatewayReceiptId": uuid.uuid4().hex,
            "acceptedAt": now,
            "duplicate": False,
        }
        with _db_lock:
            self.db.execute(
                "INSERT OR IGNORE INTO receipts"
                " (delivery_id, body_sha256, accepted_at, receipt_json)"
                " VALUES (?, ?, ?, ?)",
                (delivery_id, body_digest(body), now,
                 json.dumps(receipt, sort_keys=True)),
            )
            self.db.commit()
            saved_row = self.db.execute(
                "SELECT receipt_json FROM receipts WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        saved = json.loads(saved_row["receipt_json"])
        if saved["gatewayReceiptId"] != receipt["gatewayReceiptId"]:
            # Concurrent first-post race: the other writer owns the acceptance.
            saved["duplicate"] = True
            saved["message"] = "concurrent dedupe: original acceptance replayed"
        return saved


def build_server(host: str, port: int, db_path: str,
                 secret: str = SHARED_SECRET, token: str = SIM_TOKEN,
                 fault: FaultPlan | None = None) -> ThreadingHTTPServer:
    db = open_db(db_path)

    class _ConfiguredHandler(GatewayHandler):
        pass

    _ConfiguredHandler.db = db
    _ConfiguredHandler.secret = secret
    _ConfiguredHandler.sim_token = token
    _ConfiguredHandler.fault = fault if fault is not None else FAULT
    httpd = ThreadingHTTPServer((host, port), _ConfiguredHandler)
    httpd.daemon_threads = True
    httpd.db = db  # type: ignore[attr-defined]
    return httpd


import logging  # noqa: E402

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s gateway-sim %(message)s",
)


def main() -> int:
    httpd = build_server(RECEIVER_HOST, RECEIVER_PORT, RECEIVER_DB,
                         SHARED_SECRET, SIM_TOKEN, FAULT)
    logging.getLogger("gateway-sim").info(
        "gateway simulator listening on %s:%s (db=%s)", RECEIVER_HOST, RECEIVER_PORT, RECEIVER_DB)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        httpd.db.close()  # type: ignore[attr-defined]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
