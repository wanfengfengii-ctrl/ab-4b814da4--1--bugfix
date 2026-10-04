"""Outbound delivery worker.

Delivery semantics:
  * the exact same bytes (the canonical payload created on first accept), the
    same deliveryId and the same HMAC signature are sent on every attempt;
  * network errors, timeouts, dropped connections and HTTP 5xx are retried,
    at most `max_retries` retries (i.e. up to 4 attempts total);
  * HTTP 4xx (including 409/400) fails immediately with no retry;
  * a 2xx response means the gateway business-accepted the delivery; because
    the receiver dedupes on deliveryId, an acknowledged-then-dropped response
    simply replays and gets the original acknowledgement;
  * all state lives in SQLite, so restarting the API mid-delivery resumes the
    same deliveryId and converges to delivered or failed.
"""
from __future__ import annotations

import logging
import threading
import urllib.error
import urllib.request

from .config import Settings
from .database import Database
from .signing import sign

log = logging.getLogger("delivery")

# Per the contract only gateway 5xx (plus client-side timeouts, disconnects
# and other network failures) are retried; every 4xx fails immediately.
RETRIABLE_STATUS = frozenset({500, 501, 502, 503, 504})


class DeliveryWorker(threading.Thread):
    def __init__(self, db: Database, settings: Settings):
        super().__init__(name="delivery-worker", daemon=True)
        self.db = db
        self.settings = settings
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("delivery worker started, target=%s", self.settings.receiver_url)
        while not self._stop_event.is_set():
            try:
                row = self.db.claim_next(self.settings.stale_after)
            except Exception:
                log.exception("claim query failed")
                self._wait(self.settings.poll_interval)
                continue
            if row is None:
                self._wait(self.settings.poll_interval)
                continue
            try:
                self._process(row)
            except Exception:
                log.exception("unexpected error processing alert %s", row["alert_id"])

    def _wait(self, seconds: float) -> None:
        self._stop_event.wait(seconds)

    def _process(self, row) -> None:
        alert_id = row["alert_id"]
        delivery_id = row["delivery_id"]
        payload: bytes = row["payload"]
        attempt_no = row["attempts"]  # attempts already consumed before this claim

        while not self._stop_event.is_set():
            signature = sign(self.settings.shared_secret, delivery_id, payload)
            outcome = self._attempt(delivery_id, payload, signature)
            attempt_no += 1

            if outcome["delivered"]:
                self.db.record_attempt(
                    alert_id, delivered=True,
                    status_code=outcome["status_code"],
                    result=outcome["result"], error=outcome.get("error"), fail=False)
                log.info("alert %s delivered on attempt %d", alert_id, attempt_no)
                return

            # max_retries counts retries *after* attempt one, so the total
            # number of attempts allowed is max_retries + 1 (default 4).
            max_attempts = self.settings.max_retries + 1
            retries_left = max_attempts - attempt_no
            retryable = outcome["retryable"] and retries_left > 0
            self.db.record_attempt(
                alert_id, delivered=False,
                status_code=outcome["status_code"],
                result=outcome["result"], error=outcome.get("error"),
                fail=not retryable)
            if not retryable:
                why = ("non-retryable response" if not outcome["retryable"]
                       else "retry budget exhausted")
                log.warning("alert %s failed after %d attempt(s): %s",
                            alert_id, attempt_no, why)
                return

            delay = self.settings.backoff_base * attempt_no
            log.info("alert %s attempt %d failed (%s), retry in %.1fs",
                     alert_id, attempt_no, outcome["result"], delay)
            if self._stop_event.wait(delay):
                return
            # Re-read in case an external recovery path settled it meanwhile.
            row = self.db.get_delivery(alert_id)
            if row is None or row["status"] in ("delivered", "failed"):
                return

    def _attempt(self, delivery_id: str, payload: bytes, signature: str) -> dict:
        headers = {
            "Content-Type": "application/json",
            "X-Delivery-Id": delivery_id,
            "X-Signature": signature,
        }
        request = urllib.request.Request(
            self.settings.receiver_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.settings.delivery_timeout) as resp:
                code = resp.status
                text = resp.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            code = exc.code
            text = ""
            try:
                text = exc.read(4096).decode("utf-8", "replace")
            except Exception:
                pass
            if code in RETRIABLE_STATUS:
                return {"delivered": False, "retryable": True, "status_code": code,
                        "result": f"http_{code}", "error": text[:500] or None}
            return {"delivered": False, "retryable": False, "status_code": code,
                    "result": f"http_{code}", "error": text[:500] or None}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Timeout, connection reset / dropped mid-response, DNS, refused...
            reason = getattr(exc, "reason", exc)
            return {"delivered": False, "retryable": True, "status_code": None,
                    "result": "network_error", "error": str(reason)[:500]}

        return {"delivered": True, "retryable": False, "status_code": code,
                "result": "accepted", "error": text[:500] or None}
