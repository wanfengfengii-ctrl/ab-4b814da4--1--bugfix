"""Unit tests for validation, signing and the idempotency store."""
from __future__ import annotations

import tempfile
import unittest

from app.database import Database, STATUS_PENDING
from app.models import ConflictError, ValidationError, parse_alert
from app.signing import body_digest, sign, verify

VALID = {
    "alertKey": "AK-1", "station": "STA", "sequence": 1,
    "severity": "major", "observedAt": "2026-10-04T00:00:00Z", "reading": 3.2,
}


class ModelTests(unittest.TestCase):
    def test_valid(self):
        alert = parse_alert(dict(VALID))
        self.assertEqual(alert.alert_key, "AK-1")
        self.assertEqual(alert.sequence, 1)

    def test_missing_field(self):
        bad = dict(VALID)
        del bad["station"]
        with self.assertRaises(ValidationError):
            parse_alert(bad)

    def test_extra_field(self):
        bad = dict(VALID, surprise=1)
        with self.assertRaises(ValidationError):
            parse_alert(bad)

    def test_bad_types(self):
        for overrides in (
            {"alertKey": ""}, {"station": 7}, {"sequence": -1},
            {"sequence": True}, {"severity": "apocalyptic"},
            {"reading": "big"}, {"observedAt": None},
        ):
            with self.assertRaises(ValidationError, msg=overrides):
                parse_alert(dict(VALID, **overrides))

    def test_bool_reading_rejected(self):
        with self.assertRaises(ValidationError):
            parse_alert(dict(VALID, reading=True))


class SigningTests(unittest.TestCase):
    def test_deterministic_and_verifiable(self):
        body = b'{"x":1}'
        sig1 = sign("s", "d1", body)
        sig2 = sign("s", "d1", body)
        self.assertEqual(sig1, sig2)
        self.assertTrue(verify("s", "d1", body, sig1))

    def test_tampering_invalidates(self):
        body = b'{"x":1}'
        sig = sign("s", "d1", body)
        self.assertFalse(verify("s", "d1", b'{"x":2}', sig))  # body changed
        self.assertFalse(verify("s", "d2", body, sig))        # deliveryId changed
        self.assertFalse(verify("wrong", "d1", body, sig))    # secret changed
        self.assertFalse(verify("s", "d1", body, None))
        self.assertNotEqual(sign("s", "d1", body), sign("s", "d1", b'{"x":2}'))

    def test_digest_stable(self):
        self.assertEqual(body_digest(b"abc"), body_digest(b"abc"))


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self.tmp.name}/test.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_accept_then_replay_same_ids(self):
        outcome1, aid1, payload1, did1 = self.db.accept_alert("K", {"a": 1})
        outcome2, aid2, payload2, did2 = self.db.accept_alert("K", {"a": 1})
        self.assertEqual(outcome1, "created")
        self.assertEqual(outcome2, "replayed")
        self.assertEqual(aid1, aid2)
        self.assertEqual(did1, did2)
        self.assertEqual(payload1, payload2)
        row = self.db.get_delivery(aid1)
        self.assertEqual(row["status"], STATUS_PENDING)
        self.assertEqual(row["attempts"], 0)

    def test_same_key_different_content_conflicts(self):
        _, aid, _, _ = self.db.accept_alert("K", {"a": 1})
        with self.assertRaises(ConflictError):
            self.db.accept_alert("K", {"a": 2})
        # Original remains intact.
        _, replayed_aid, _, _ = self.db.accept_alert("K", {"a": 1})
        self.assertEqual(replayed_aid, aid)

    def test_distinct_keys_get_distinct_ids(self):
        _, aid1, _, did1 = self.db.accept_alert("K1", {"a": 1})
        _, aid2, _, did2 = self.db.accept_alert("K2", {"a": 1})
        self.assertNotEqual(aid1, aid2)
        self.assertNotEqual(did1, did2)

    def test_claim_cycle_and_attempt_recording(self):
        _, aid, _, _ = self.db.accept_alert("K", {"a": 1})
        claimed = self.db.claim_next(stale_after=30)
        self.assertEqual(claimed["alert_id"], aid)
        self.db.record_attempt(aid, delivered=False, status_code=503,
                               result="http_503", error=None, fail=False)
        row = self.db.get_delivery(aid)
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["status"], "delivering")
        # While freshly claimed it must not be claimed again.
        self.assertIsNone(self.db.claim_next(stale_after=30))
        # After the stale window the same delivery is reclaimable (crash recovery).
        stale = self.db.claim_next(stale_after=0)
        self.assertEqual(stale["alert_id"], aid)
        self.db.record_attempt(aid, delivered=True, status_code=201,
                               result="accepted", error=None, fail=False)
        row = self.db.get_delivery(aid)
        self.assertEqual(row["status"], "delivered")
        self.assertEqual(row["attempts"], 2)
        self.assertIsNone(self.db.claim_next(stale_after=0))

    def test_failed_is_terminal(self):
        _, aid, _, _ = self.db.accept_alert("K", {"a": 1})
        self.db.claim_next(stale_after=30)
        self.db.record_attempt(aid, delivered=False, status_code=400,
                               result="http_400", error="bad", fail=True)
        self.assertEqual(self.db.get_delivery(aid)["status"], "failed")
        self.assertIsNone(self.db.claim_next(stale_after=0))


if __name__ == "__main__":
    unittest.main()
