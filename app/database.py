"""SQLite-backed durable storage.

A single database file holds:
  * alerts    - one row per alertKey (the idempotency / conflict anchor)
  * deliveries- one row per delivery attempt stream (exactly one per alert)

The worker advances delivery state with short transactions, so a crash at any
point leaves a consistent state that restarts recover from:
  pending    -> delivering (claimed) -> delivered
                              \-------> failed (4xx or retries exhausted)
An interrupted claim is simply `delivering` with an old heartbeat and gets
reclaimed by the next worker pass.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Iterable, Optional

STATUS_PENDING = "pending"
STATUS_DELIVERING = "delivering"
STATUS_DELIVERED = "delivered"
FAILED = "failed"
TERMINAL_STATUSES = (STATUS_DELIVERED, FAILED)

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_key        TEXT PRIMARY KEY,
    alert_id         TEXT NOT NULL UNIQUE,
    body_json        TEXT NOT NULL,
    created_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    alert_id         TEXT PRIMARY KEY,
    delivery_id      TEXT NOT NULL UNIQUE,
    status           TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_result      TEXT,
    last_status_code INTEGER,
    last_error       TEXT,
    payload          BLOB NOT NULL,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    claimed_at       REAL
) STRICT;
"""


class Database:
    """Thread-safe wrapper keeping one connection per thread."""

    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        conn = self._connect()
        try:
            conn.executescript(_CREATE_SQL)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------ accept
    def accept_alert(self, alert_key: str, body: dict) -> tuple[str, str, bytes, str]:
        """Idempotent insert.

        Returns (status, alert_id, delivery_payload, delivery_id) where status
        is "created", "replayed", or raises ConflictError for same-key/
        different-body. Creates the delivery row atomically in the same tx.
        """
        from .models import (ConflictError, canonical_dumps, display_dumps,
                             json_equal, parse_json)  # models has no db deps

        now = time.time()
        with self._write_lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT alert_id, body_json FROM alerts WHERE alert_key = ?",
                    (alert_key,),
                ).fetchone()
                body_json = canonical_dumps(body)
                if row is not None:
                    # Compare by exact numeric meaning rather than by bytes:
                    # an equal value spelled differently (1 vs 1.0) is the
                    # same content, while distinct readings float would merge
                    # (e.g. 9007199254740992 vs ...4993) must conflict.
                    if not json_equal(parse_json(row["body_json"]), body):
                        stored = parse_json(row["body_json"])
                        raise ConflictError(
                            f"alertKey {alert_key!r} already accepted with different content: "
                            f"stored={display_dumps(stored)} "
                            f"submitted={display_dumps(body)}")
                    delivery = conn.execute(
                        "SELECT delivery_id, payload FROM deliveries WHERE alert_id = ?",
                        (row["alert_id"],),
                    ).fetchone()
                    conn.commit()
                    return ("replayed", row["alert_id"],
                            delivery["payload"], delivery["delivery_id"])

                alert_id = uuid.uuid4().hex
                delivery_id = uuid.uuid4().hex
                payload = canonical_dumps(
                    {"deliveryId": delivery_id, "alertId": alert_id, "alert": body},
                ).encode("utf-8")
                conn.execute(
                    "INSERT INTO alerts (alert_key, alert_id, body_json, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (alert_key, alert_id, body_json, now),
                )
                conn.execute(
                    "INSERT INTO deliveries (alert_id, delivery_id, status, attempts,"
                    " payload, created_at, updated_at)"
                    " VALUES (?, ?, ?, 0, ?, ?, ?)",
                    (alert_id, delivery_id, STATUS_PENDING, payload, now, now),
                )
                conn.commit()
                return ("created", alert_id, payload, delivery_id)
            except Exception:
                conn.rollback()
                raise

    # ------------------------------------------------------------------ worker
    def claim_next(self, stale_after: float, now: Optional[float] = None) -> Optional[sqlite3.Row]:
        """Atomically claim a pending alert or a stale in-flight delivery."""
        now = now if now is not None else time.time()
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM deliveries"
                " WHERE status = ?"
                "    OR (status = ? AND (claimed_at IS NULL OR claimed_at < ?))"
                " ORDER BY created_at LIMIT 1",
                (STATUS_PENDING, STATUS_DELIVERING, now - stale_after),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            conn.execute(
                "UPDATE deliveries SET status = ?, claimed_at = ?, updated_at = ?"
                " WHERE alert_id = ?",
                (STATUS_DELIVERING, now, now, row["alert_id"]),
            )
            conn.commit()
            return conn.execute(
                "SELECT * FROM deliveries WHERE alert_id = ?", (row["alert_id"],)
            ).fetchone()
        except Exception:
            conn.rollback()
            raise

    def record_attempt(self, alert_id: str, *, delivered: bool,
                       status_code: Optional[int], result: str,
                       error: Optional[str], fail: bool) -> None:
        now = time.time()
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            new_status = (STATUS_DELIVERED if delivered
                          else FAILED if fail else STATUS_DELIVERING)
            # The claim (claimed_at) is intentionally kept across the retry
            # backoff so peer workers do not deliver the same alert
            # concurrently; a crashed process loses it via the stale timeout.
            conn.execute(
                "UPDATE deliveries SET status = ?, attempts = attempts + 1,"
                " last_result = ?, last_status_code = ?, last_error = ?,"
                " updated_at = ?"
                " WHERE alert_id = ?",
                (new_status, result, status_code, error, now, alert_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ------------------------------------------------------------------ queries
    def get_delivery(self, alert_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM deliveries WHERE alert_id = ?", (alert_id,)
        ).fetchone()

    def delivery_by_key(self, alert_key: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT d.* FROM deliveries d JOIN alerts a ON a.alert_id = d.alert_id"
            " WHERE a.alert_key = ?",
            (alert_key,),
        ).fetchone()

    def list_non_terminal(self) -> Iterable[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM deliveries WHERE status NOT IN (?, ?)",
            TERMINAL_STATUSES,
        ).fetchall()
