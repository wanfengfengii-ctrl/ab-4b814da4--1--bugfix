"""End-to-end delivery scenarios shared by in-process and external smoke runs.

A "stack" only has to provide the small client interface defined by
StackProtocol, so the exact same assertions run:
  * in CI/local development against in-process servers, and
  * in docker-compose against the built api + receiver containers.
"""
from __future__ import annotations

import json
import time
import uuid
from decimal import Decimal
from typing import Protocol


class StackProtocol(Protocol):
    def post_alert(self, payload: dict): ...
    def post_alert_raw(self, raw: bytes): ...
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


def _raw_alert(alert_key: str, reading_literal: str, *, station: str = "STA-PREC",
               sequence: int = 1) -> bytes:
    # Built as text on purpose: values such as 9007199254740993 or
    # 0.10000000000000001 cannot survive a Python float round-trip, so a
    # dict-based client could not even express them on the wire.
    return (
        "{"
        f'"alertKey":{json.dumps(alert_key)},'
        f'"station":{json.dumps(station)},'
        f'"sequence":{sequence},'
        '"severity":"major",'
        '"observedAt":"2026-10-05T00:00:00Z",'
        f'"reading":{reading_literal}'
        "}"
    ).encode("utf-8")


def _delivered_body_text(stack: StackProtocol, delivery_id: str) -> str:
    requests = stack.requests_for(delivery_id)
    acked = [r for r in requests if r["http_status"] in (200, 201)]
    assert acked, f"gateway never acknowledged delivery {delivery_id}: {requests}"
    bodies = {r.get("body_text") for r in acked}
    assert len(bodies) == 1, f"gateway saw differing bodies: {bodies}"
    return next(iter(bodies))


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


def scenario_exact_number_precision(stack: StackProtocol, run: str) -> str:
    # Adjacent integers beyond the IEEE-754 safe range collapse to one double;
    # the API must keep them distinct all the way to the signed gateway body.
    big_key = f"{run}-PREC-BIG"
    raw_big_1 = _raw_alert(big_key, "9007199254740992")
    raw_big_2 = _raw_alert(big_key, "9007199254740993")
    code, body = stack.post_alert_raw(raw_big_1)
    assert code == 201, f"expected 201, got {code}: {body}"
    alert_id, delivery_id = body["alertId"], body["deliveryId"]
    final = stack.wait_terminal(alert_id)
    assert final["status"] == "delivered", final
    gateway_body = _delivered_body_text(stack, delivery_id)
    assert '"reading":9007199254740992' in gateway_body, (
        f"gateway body lost the exact reading: {gateway_body}")
    delivered_json = json.loads(gateway_body, parse_float=Decimal)
    assert delivered_json["alert"]["reading"] == Decimal("9007199254740992"), gateway_body
    assert stack.acceptance_count(delivery_id) == 1

    # Same key + an adjacent reading is a conflict, never an id replay.
    code2, body2 = stack.post_alert_raw(raw_big_2)
    assert code2 == 409, f"adjacent big integer must conflict, got {code2}: {body2}"
    assert "alertId" not in body2 and "deliveryId" not in body2, body2

    # Same key + byte-identical content still replays the original identifiers.
    code3, body3 = stack.post_alert_raw(raw_big_1)
    assert code3 == 200, body3
    assert body3["replayed"] is True
    assert body3["alertId"] == alert_id and body3["deliveryId"] == delivery_id
    assert stack.acceptance_count(delivery_id) == 1, "replay caused a second acceptance"

    # Distinguishable decimals that share one binary64 value must conflict too.
    dec_key = f"{run}-PREC-DEC"
    raw_dec_1 = _raw_alert(dec_key, "0.1")
    raw_dec_2 = _raw_alert(dec_key, "0.10000000000000001")
    code, body = stack.post_alert_raw(raw_dec_1)
    assert code == 201, body
    final = stack.wait_terminal(body["alertId"])
    assert final["status"] == "delivered", final
    gateway_body = _delivered_body_text(stack, body["deliveryId"])
    assert '"reading":0.1' in gateway_body and "0.10000000000000001" not in gateway_body, (
        gateway_body)
    code2, body2 = stack.post_alert_raw(raw_dec_2)
    assert code2 == 409, f"distinct decimals must conflict, got {code2}: {body2}"
    code3, body3 = stack.post_alert_raw(raw_dec_1)
    assert code3 == 200 and body3["replayed"] is True, body3

    # Ordinary readings through a normal JSON client keep working.
    ordinary = _alert(run, 8, reading=42.5)
    code, body = stack.post_alert(ordinary)
    assert code == 201, body
    assert stack.wait_terminal(body["alertId"])["status"] == "delivered"
    code2, body2 = stack.post_alert(ordinary)
    assert code2 == 200 and body2["replayed"] is True, body2
    assert body2["alertId"] == body["alertId"]
    code3, body3 = stack.post_alert(_alert(run, 8, reading=43))
    assert code3 == 409, f"ordinary reading change must conflict, got {code3}: {body3}"
    return ("exact JSON numbers: adjacent 2^53+ integers and 0.1 vs"
            " 0.10000000000000001 stay distinct in acceptance and in the signed"
            " gateway body; same-content replays stay compatible")


SCENARIOS = [
    scenario_happy_path,
    scenario_conflict,
    scenario_exact_number_precision,
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
