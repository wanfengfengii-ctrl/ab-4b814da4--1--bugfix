"""In-process end-to-end tests covering every required delivery scenario."""
from __future__ import annotations

import time
import unittest
import uuid

from app.signing import sign
from tests import smoke_cases
from tests.integration_support import TEST_SECRET, http_request, sample_alert, start_stack


class SmokeScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = start_stack(delivery_timeout=1.0, backoff_base=0.05)

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()

    def test_all_scenarios(self):
        results = smoke_cases.run_all(self.stack, run="inproc")
        for line in results:
            print(f"  * {line}")


class ApiBehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = start_stack(delivery_timeout=1.0, backoff_base=0.05)

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()

    def test_validation_errors_are_400(self):
        for bad in ({}, {"alertKey": "x"}, sample_alert("VAL-1", sequence=-3)):
            code, body = self.stack.post_alert(bad)
            self.assertEqual(code, 400, body)

    def test_unknown_alert_404(self):
        code, body = self.stack.get_alert("does-not-exist")
        self.assertEqual(code, 404, body)

    def test_healthz(self):
        from tests.integration_support import http_request
        code, body = http_request("GET", f"{self.stack.api_url}/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "ok")

    def test_pending_visible_before_delivery(self):
        stack = start_stack(delivery_timeout=0.5, backoff_base=0.05,
                            dead_receiver=True)
        try:
            code, body = stack.post_alert(sample_alert(f"PEND-{time.time_ns()}"))
            self.assertEqual(code, 201)
            observed = set()
            deadline = time.time() + 3
            while time.time() < deadline:
                _, got = stack.get_alert(body["alertId"])
                observed.add(got["status"])
                if got["attempts"] >= 1:
                    break
                time.sleep(0.05)
            self.assertTrue(observed & {"pending", "delivering"})
            _, got = stack.get_alert(body["alertId"])
            self.assertGreaterEqual(got["attempts"], 1)
        finally:
            stack.stop()


    def test_restart_mid_delivery_resumes_with_same_delivery_id(self):
        # Gateway keeps failing; kill and restart the API process mid-delivery.
        # Recovery must reuse the persisted deliveryId/body and converge.
        stack = start_stack(delivery_timeout=1.0, backoff_base=0.1)
        try:
            stack.set_fault({"mode": "http", "code": 503, "count": 100})
            code, body = stack.post_alert(sample_alert("RESTART-5XX"))
            self.assertEqual(code, 201)
            alert_id, delivery_id = body["alertId"], body["deliveryId"]

            deadline = time.time() + 5
            while time.time() < deadline:
                _, got = stack.get_alert(alert_id)
                if got["attempts"] >= 1:
                    break
                time.sleep(0.05)
            _, before = stack.get_alert(alert_id)
            self.assertEqual(before["status"], "delivering")

            # Restart clears the fault and reclaims the stale claim immediately.
            stack.set_fault({"mode": None})
            stack.restart_api(stale_after=0.0, backoff_base=0.05)

            final = stack.wait_terminal(alert_id)
            self.assertEqual(final["status"], "delivered", final)
            self.assertEqual(final["deliveryId"], delivery_id)
            requests = stack.requests_for(delivery_id)
            self.assertEqual(len({r["body_sha256"] for r in requests}), 1)
            self.assertEqual(len({r["signature"] for r in requests}), 1)
            self.assertEqual(stack.acceptance_count(delivery_id), 1)
        finally:
            stack.stop()

    def test_restart_after_gateway_admitted_then_connection_dropped(self):
        # The gateway durably accepted once but the ACK was lost; the API is
        # restarted before its own retry. Restart must replay and converge to
        # delivered without a second business acceptance.
        stack = start_stack(delivery_timeout=1.0, backoff_base=30.0)
        try:
            stack.set_fault({"mode": "drop", "count": 1})
            code, body = stack.post_alert(sample_alert("RESTART-DROP"))
            self.assertEqual(code, 201)
            alert_id, delivery_id = body["alertId"], body["deliveryId"]

            deadline = time.time() + 5
            while time.time() < deadline:
                if stack.acceptance_count(delivery_id) == 1:
                    break
                time.sleep(0.05)
            self.assertEqual(stack.acceptance_count(delivery_id), 1)

            stack.restart_api(stale_after=0.0, backoff_base=0.05)
            final = stack.wait_terminal(alert_id)
            self.assertEqual(final["status"], "delivered", final)
            self.assertEqual(final["attempts"], 2)
            statuses = [r["http_status"] for r in stack.requests_for(delivery_id)]
            self.assertEqual(statuses, [0, 200])
            self.assertEqual(stack.acceptance_count(delivery_id), 1)
        finally:
            stack.stop()


class GatewaySimulatorSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = start_stack()

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()

    def _ingest(self, delivery_id, body: bytes, signature, headers=None):
        hdrs = {"X-Delivery-Id": delivery_id, "X-Signature": signature}
        hdrs.update(headers or {})
        return http_request("POST", f"{self.stack.sim_url}/ingest", body, hdrs)

    def test_missing_or_bad_signature_rejected(self):
        body = b'{"x":1}'
        did = uuid.uuid4().hex
        code, resp = self._ingest(did, body, "garbage")
        self.assertEqual(code, 401, resp)
        code, resp = self._ingest(did, body, "")
        self.assertEqual(code, 401, resp)
        self.assertEqual(self.stack.acceptance_count(did), 0)

    def test_valid_signature_then_tampered_body_conflicts(self):
        did = uuid.uuid4().hex
        body1 = b'{"v":1}'
        sig1 = sign(TEST_SECRET, did, body1)
        code, resp = self._ingest(did, body1, sig1)
        self.assertEqual(code, 201, resp)

        # Attacker reuses the deliveryId/signature with altered bytes.
        body2 = b'{"v":2}'
        sig2 = sign(TEST_SECRET, did, body2)  # valid sig for the new body
        code, resp = self._ingest(did, body2, sig2)
        self.assertEqual(code, 409, resp)
        # Old signature on the new body must not verify at all.
        code, resp = self._ingest(did, body2, sig1)
        self.assertEqual(code, 401, resp)
        # Idempotent replay of the exact original request succeeds.
        code, resp = self._ingest(did, body1, sig1)
        self.assertEqual(code, 200, resp)
        self.assertTrue(resp["duplicate"])
        self.assertEqual(self.stack.acceptance_count(did), 1)

    def test_sim_control_requires_token(self):
        code, resp = http_request(
            "POST", f"{self.stack.sim_url}/sim/control", {"mode": "drop"})
        self.assertEqual(code, 401, resp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
