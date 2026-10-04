"""HTTP API for seismic alert submission and status queries.

Endpoints
---------
POST /api/alerts
    Body: {alertKey, station, sequence, severity, observedAt, reading}
    201 first acceptance  -> {alertId, deliveryId, status: "pending", replayed: false}
    200 idempotent replay -> same alertId/deliveryId, replayed: true
    409 same alertKey, different content
    400 malformed body

GET /api/alerts/{alertId}
    200 -> {alertId, status, attempts, lastResult, lastStatusCode, lastError,
            unique: true/false, deliveredAt...}
    404 unknown alertId

GET /healthz -> {"status": "ok"}

The response language is deliberately explicit for the duty officer: a
delivered alert reports that the gateway business-accepted exactly one copy
(unique acceptance); a failed alert states whether non-retryable response or
exhausted retries caused the terminal failure.
"""
from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import Settings
from .database import Database
from .models import ConflictError, ValidationError, parse_alert

log = logging.getLogger("api")

TERMINAL_FAILURE_REASONS = {
    "failed_non_retryable": "gateway returned a non-retryable 4xx response",
    "failed_retries_exhausted": "all delivery attempts (timeouts, connection "
                                "drops or gateway 5xx) have been exhausted",
}


def _failure_reason(last_result: str | None, attempts: int) -> str:
    if last_result and last_result.startswith("http_4"):
        return TERMINAL_FAILURE_REASONS["failed_non_retryable"]
    return TERMINAL_FAILURE_REASONS["failed_retries_exhausted"]


class AlertHandler(BaseHTTPRequestHandler):
    server_version = "SeismicAlertAPI/1.0"

    # Injected by make_server:
    db: Database = None  # type: ignore[assignment]
    settings: Settings = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        log.info("%s - %s", self.address_string(), fmt % args)

    # ------------------------------------------------------------------ helpers
    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code: int, error: str, **extra) -> None:
        payload = {"error": error}
        payload.update(extra)
        self._send_json(code, payload)

    # ------------------------------------------------------------------ routing
    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(200, {"status": "ok", "service": "alert-api"})
            return
        if path.startswith("/api/alerts/"):
            alert_id = path[len("/api/alerts/"):]
            if "/" in alert_id or not alert_id:
                self._error(404, "not found")
                return
            self._get_alert(alert_id)
            return
        self._error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/api/alerts":
            self._post_alert()
            return
        self._error(404, "not found")

    # ------------------------------------------------------------------ POST
    def _post_alert(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(400, "invalid Content-Length")
            return
        if length <= 0 or length > 65536:
            self._error(400, "request body must be 1..65536 bytes of JSON")
            return
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            alert = parse_alert(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._error(400, f"invalid JSON: {exc}")
            return
        except ValidationError as exc:
            self._error(400, str(exc))
            return

        try:
            outcome, alert_id, _payload, delivery_id = self.db.accept_alert(
                alert.alert_key, alert.to_dict())
        except ConflictError as exc:
            self._error(409, str(exc), alertKey=alert.alert_key)
            return

        row = self.db.get_delivery(alert_id)
        body = self._status_body(alert_id, delivery_id, row)
        body["replayed"] = outcome == "replayed"
        if outcome == "created":
            body["message"] = ("alert accepted, delivery scheduled; query this"
                               " alertId for the unique-acceptance result")
        else:
            body["message"] = ("idempotent replay: returning the original"
                               " alertId/deliveryId, no duplicate accepted")
        self._send_json(201 if outcome == "created" else 200, body)

    # ------------------------------------------------------------------ GET
    def _get_alert(self, alert_id: str) -> None:
        row = self.db.get_delivery(alert_id)
        if row is None:
            self._error(404, f"unknown alertId {alert_id!r}")
            return
        self._send_json(200, self._status_body(alert_id, row["delivery_id"], row))

    @staticmethod
    def _status_body(alert_id: str, delivery_id: str, row) -> dict:
        status = row["status"]
        attempts = row["attempts"]
        body: dict = {
            "alertId": alert_id,
            "deliveryId": delivery_id,
            "status": status,
            "attempts": attempts,
            "lastResult": row["last_result"],
            "lastStatusCode": row["last_status_code"],
            "lastError": row["last_error"],
        }
        if status == "delivered":
            body["unique"] = True
            body["conclusion"] = (
                f"DELIVERED: the emergency broadcast gateway business-accepted"
                f" this alert exactly once under deliveryId {delivery_id}"
                f" after {attempts} attempt(s); it cannot be accepted again.")
        elif status == "failed":
            body["unique"] = False
            reason = _failure_reason(row["last_result"], attempts)
            body["conclusion"] = (
                f"FAILED TERMINALLY after {attempts} attempt(s): {reason}.")
        elif status == "delivering":
            body["unique"] = None
            body["conclusion"] = (
                f"DELIVERING: {attempts} attempt(s) so far, delivery in"
                f" progress (retries keep the same deliveryId and body).")
        else:
            body["unique"] = None
            body["conclusion"] = "PENDING: accepted, waiting for first delivery attempt."
        return body


def make_server(settings: Settings) -> ThreadingHTTPServer:
    db = Database(settings.db_path)

    class _ConfiguredHandler(AlertHandler):
        pass

    _ConfiguredHandler.db = db
    _ConfiguredHandler.settings = settings
    httpd = ThreadingHTTPServer((settings.host, settings.port), _ConfiguredHandler)
    httpd.daemon_threads = True
    httpd.db = db  # type: ignore[attr-defined]
    httpd.settings = settings  # type: ignore[attr-defined]
    return httpd
