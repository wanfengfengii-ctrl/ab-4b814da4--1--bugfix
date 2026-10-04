#!/usr/bin/env python3
"""One-shot verification job.

Exit code 0 only when ALL of the following pass; 1 otherwise:

  1. build check   - every source file byte-compiles (the image has no deps,
                     so compilation is the whole build);
  2. code tests    - unit + in-process integration tests, including restart
                     recovery and all retry/idempotency semantics;
  3. delivery smoke- the same end-to-end scenarios executed over HTTP against
                     the running compose api + receiver containers.

Run in docker-compose as the `verify` service, or standalone with
API_URL / RECEIVER_URL pointing at a running stack.
"""
from __future__ import annotations

import compileall
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

# Make the repo root importable whether executed as `python scripts/verify.py`
# (only the script's own directory lands on sys.path) or via PYTHONPATH.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from tests import smoke_cases

API_URL = os.getenv("API_URL", "http://127.0.0.1:8080").rstrip("/")
RECEIVER_URL = os.getenv("RECEIVER_URL", "http://127.0.0.1:9090").rstrip("/")
SIM_TOKEN = os.getenv("SIM_FAULT_TOKEN", "compose-sim-token")


def _http(method: str, url: str, body=None, headers=None, timeout: float = 10.0):
    headers = dict(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
            headers.setdefault("Content-Type", "application/json")
        else:
            data = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            code = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        code = exc.code
    return code, json.loads(raw.decode("utf-8"))


def _wait_health(url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, _ = _http("GET", url, timeout=2)
            if code == 200:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


class ExternalStack:
    """StackProtocol adapter driving the containers over real HTTP."""

    def post_alert(self, payload):
        return _http("POST", f"{API_URL}/api/alerts", payload)

    def post_alert_text(self, raw):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return _http("POST", f"{API_URL}/api/alerts", raw,
                     headers={"Content-Type": "application/json"})

    def get_alert(self, alert_id):
        return _http("GET", f"{API_URL}/api/alerts/{alert_id}")

    def wait_terminal(self, alert_id, timeout=60.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, body = self.get_alert(alert_id)
            if body["status"] in ("delivered", "failed"):
                return body
            time.sleep(0.5)
        raise AssertionError(f"alert {alert_id} did not finish within {timeout}s")

    def set_fault(self, spec):
        return _http("POST", f"{RECEIVER_URL}/sim/control", spec or {"mode": None},
                     headers={"X-Sim-Token": SIM_TOKEN})

    def acceptance_count(self, delivery_id):
        _, body = _http("GET", f"{RECEIVER_URL}/sim/accepted")
        return sum(1 for row in body["accepted"] if row["delivery_id"] == delivery_id)

    def requests_for(self, delivery_id):
        _, body = _http("GET", f"{RECEIVER_URL}/sim/requests?deliveryId={delivery_id}")
        return body["requests"]


def check_build() -> tuple[bool, str]:
    print("\n=== [1/3] BUILD CHECK (compileall) ===")
    ok = compileall.compile_dir("app", quiet=1)
    ok = compileall.compile_dir("receiver", quiet=1) and ok
    ok = compileall.compile_dir("tests", quiet=1) and ok
    ok = compileall.compile_dir("scripts", quiet=1) and ok
    msg = "all sources compile cleanly" if ok else "compilation errors"
    print(f"build: {msg}")
    return ok, msg


def check_code_tests() -> tuple[bool, str]:
    print("\n=== [2/3] CODE TESTS (unit + in-process integration) ===")
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    ok = result.wasSuccessful()
    msg = f"{result.testsRun - len(result.failures) - len(result.errors)}" \
          f"/{result.testsRun} test cases passed"
    print(f"code tests: {msg}")
    return ok, msg


def check_delivery_smoke() -> tuple[bool, str]:
    print("\n=== [3/3] DELIVERY SMOKE (compose api + receiver over HTTP) ===")
    if not _wait_health(f"{API_URL}/healthz"):
        return False, f"API at {API_URL} never became healthy"
    if not _wait_health(f"{RECEIVER_URL}/healthz"):
        return False, f"receiver at {RECEIVER_URL} never became healthy"
    print(f"both services healthy ({API_URL}, {RECEIVER_URL})")

    try:
        # Unique run id so re-running verify never collides with earlier keys.
        run = f"compose-{int(time.time())}-{os.urandom(3).hex()}"
        lines = smoke_cases.run_all(ExternalStack(), run=run)
    except AssertionError as exc:
        return False, f"scenario assertion failed: {exc}"
    except Exception as exc:  # noqa: BLE001 - verify must summarise any failure
        return False, f"scenario error: {type(exc).__name__}: {exc}"
    for line in lines:
        print(f"  * {line}")
    return True, f"{len(lines)}/{len(lines)} delivery scenarios passed"


def main() -> int:
    print("Seismic alert delivery - verification job")
    print(f"API_URL={API_URL}  RECEIVER_URL={RECEIVER_URL}")

    results = []
    for check in (check_build, check_code_tests, check_delivery_smoke):
        try:
            ok, msg = check()
        except Exception as exc:  # noqa: BLE001
            ok, msg = False, f"{check.__name__} crashed: {type(exc).__name__}: {exc}"
            print(msg)
        results.append((check.__name__, ok, msg))

    print("\n================ VERIFICATION SUMMARY ================")
    for name, ok, msg in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {msg}")
    overall = all(ok for _, ok, _ in results)
    print("======================================================")
    print("OVERALL:", "PASS" if overall else "FAIL")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
