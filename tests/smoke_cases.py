"""End-to-end delivery scenarios shared by in-process and external smoke runs.

A "stack" only has to provide the small client interface defined by
StackProtocol, so the exact same assertions run:
  * in CI/local development against in-process servers, and
  * in docker-compose against the built api + receiver containers.
"""
from __future__ import annotations

import time
import uuid
from typing import Protocol


class StackProtocol(Protocol):
    def post_alert(self, payload: dict): ...
    def get_alert(self, alert_id: str): ...
    def wait_terminal(self, alert_id: str, timeout: float = 60.0) -> dict: ...
    def set_fault(self, spec: dict | None): ...
    def acceptance_count(self, delivery_id: str) -> int: ...
    def requests_for(self, delivery_id: str) -> list: ...


def _alert(run: str, n: int, **overrides) -> dict:
    payload = {
        "alertKey": f"{run}-K{n}",
        "station": f"STA-{n:02d}",
        "sequence": 100 + n,
        "severity": "major",
        "observedAt": "2026-10-04T08:30:00Z",
        "reading": 5.1 + n,
    }
    payload.update(overrides)
    return payload


# Each scenario returns a human-readable result line and raises on failure.

def scenario_happy_path(stack: StackProtocol, run: str) -> str:
    code, body = stack.post_alert(_alert(run, 1))
    assert code == 201, f"expected 201, got {code}: {body}"
    alert_id, delivery_id = body["alertId"], body["deliveryId"]
    assert alert_id and delivery_id, body
    assert body["status"] == "pending", body

    final = stack.wait_terminal(alert_id)
    assert final["status"] == "delivered", final
    assert final["attempts"] >= 1
    assert final["unique"] is True, final
    assert "exactly once" in final["conclusion"], final
    assert stack.acceptance_count(delivery_id) == 1, "gateway accepted more than once"

    # Idempotent replay: same key + same content replays the original result.
    code2, replay = stack.post_alert(_alert(run, 1))
    assert code2 == 200, replay
    assert replay["replayed"] is True
    assert replay["alertId"] == alert_id and replay["deliveryId"] == delivery_id
    final2 = stack.wait_terminal(alert_id)
    assert final2["status"] == "delivered"
    assert stack.acceptance_count(delivery_id) == 1, "replay caused a second acceptance"
    return "happy path: accepted once, replay returns the same alertId/deliveryId"


def scenario_conflict(stack: StackProtocol, run: str) -> str:
    code, body = stack.post_alert(_alert(run, 2, reading=1.0))
    assert code == 201, body
    # Let the first submission settle so its delivery cannot consume faults
    # injected by later scenarios.
    stack.wait_terminal(body["alertId"])
    code2, body2 = stack.post_alert(_alert(run, 2, reading=9.9))
    assert code2 == 409, f"same key different content must conflict, got {code2}: {body2}"
    return "conflict: same alertKey with different content rejected with 409"


def scenario_retry_identity_after_5xx(stack: StackProtocol, run: str) -> str:
    stack.set_fault({"mode": "http", "code": 503, "count": 2})
    code, body = stack.post_alert(_alert(run, 3))
    assert code == 201, body
    alert_id, delivery_id = body["alertId"], body["deliveryId"]

    final = stack.wait_terminal(alert_id)
    assert final["status"] == "delivered", final
    assert final["attempts"] == 3, f"expected 3 attempts, got {final['attempts']}"

    requests = stack.requests_for(delivery_id)
    assert [r["http_status"] for r in requests] == [503, 503, 201], requests
    bodies = {r["body_sha256"] for r in requests}
    sigs = {r["signature"] for r in requests}
    assert len(bodies) == 1, "retry bodies differ"
    assert len(sigs) == 1, "retry signatures differ"
    assert stack.acceptance_count(delivery_id) == 1
    return "5xx x2: retried with identical body/deliveryId/signature, then delivered once"


def scenario_drop_after_accept(stack: StackProtocol, run: str) -> str:
    stack.set_fault({"mode": "drop", "count": 1})
    code, body = stack.post_alert(_alert(run, 4))
    assert code == 201, body
    alert_id, delivery_id = body["alertId"], body["deliveryId"]

    final = stack.wait_terminal(alert_id)
    assert final["status"] == "delivered", final
    assert final["attempts"] == 2, f"retry expected after dropped ACK, got {final}"
    assert final["unique"] is True

    requests = stack.requests_for(delivery_id)
    assert len(bodies := {r["body_sha256"] for r in requests}) == 1
    assert len({r["signature"] for r in requests}) == 1
    assert [r["http_status"] for r in requests] == [0, 200], requests
    assert stack.acceptance_count(delivery_id) == 1, "must converge to one acceptance"
    return "admitted-then-disconnect: retry replayed the single acceptance, no duplication"


def scenario_timeout_then_success(stack: StackProtocol, run: str) -> str:
    # First attempt stalls beyond the client timeout and is never answered;
    # the retry (same deliveryId) succeeds.
    stack.set_fault({"mode": "delay", "count": 1, "delay": 4.0})
    code, body = stack.post_alert(_alert(run, 5))
    assert code == 201, body
    final = stack.wait_terminal(body["alertId"])
    assert final["status"] == "delivered", final
    assert final["attempts"] == 2, f"expected timeout then success, got {final}"
    assert stack.acceptance_count(body["deliveryId"]) == 1
    return "timeout: retried with the same deliveryId and delivered once"


def scenario_4xx_fails_immediately(stack: StackProtocol, run: str) -> str:
    stack.set_fault({"mode": "http", "code": 400, "count": 10})
    code, body = stack.post_alert(_alert(run, 6))
    assert code == 201, body
    final = stack.wait_terminal(body["alertId"])
    assert final["status"] == "failed", final
    assert final["attempts"] == 1, f"4xx must fail immediately, got {final}"
    assert final["lastStatusCode"] == 400
    assert "non-retryable 4xx" in final["conclusion"], final
    assert stack.acceptance_count(body["deliveryId"]) == 0
    return "4xx: terminal failure after exactly one attempt"


def scenario_retries_exhausted(stack: StackProtocol, run: str) -> str:
    stack.set_fault({"mode": "http", "code": 503, "count": 10})
    code, body = stack.post_alert(_alert(run, 7))
    assert code == 201, body
    alert_id = body["alertId"]

    # The duty officer must be able to see delivery in progress, too.
    seen = {"pending": False, "delivering": False}
    deadline = time.time() + 10
    while time.time() < deadline:
        _, status = stack.get_alert(alert_id)
        seen[status["status"]] = True
        if status["status"] == "failed":
            break
        time.sleep(0.05)

    final = stack.wait_terminal(alert_id)
    assert final["status"] == "failed", final
    assert final["attempts"] == 4, f"first attempt + 3 retries expected, got {final}"
    assert "exhausted" in final["conclusion"], final
    assert seen["delivering"], "delivering state was never observable"
    assert stack.acceptance_count(body["deliveryId"]) == 0
    return "5xx x10: failed terminally after 4 attempts (1 + 3 retries)"


SCENARIOS = [
    scenario_happy_path,
    scenario_conflict,
    scenario_retry_identity_after_5xx,
    scenario_drop_after_accept,
    scenario_timeout_then_success,
    scenario_4xx_fails_immediately,
    scenario_retries_exhausted,
]


def run_all(stack: StackProtocol, run: str | None = None) -> list[str]:
    run = run or uuid.uuid4().hex[:12]
    results = []
    for scenario in SCENARIOS:
        # Fault injection lives in the (possibly long-lived) gateway process,
        # so reset before and after every scenario to keep runs independent.
        stack.set_fault({"mode": None})
        try:
            results.append(scenario(stack, run))
        finally:
            stack.set_fault({"mode": None})
    return results
