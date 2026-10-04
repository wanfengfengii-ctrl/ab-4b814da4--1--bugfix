"""Unit tests for validation, signing and the idempotency store."""
from __future__ import annotations

import tempfile
import unittest
from decimal import Decimal

from app.database import Database, STATUS_PENDING
from app.models import (
    ConflictError, ValidationError, canonical_json, content_equal,
    format_number, parse_alert, parse_alert_json,
)
from app.signing import body_digest, sign, verify

VALID = {
    "alertKey": "AK-1", "station": "STA", "sequence": 1,
    "severity": "major", "observedAt": "2026-10-04T00:00:00Z", "reading": 3.2,
}

RAW_TEMPLATE = (
    '{"alertKey":"%s","station":"STA","sequence":1,"severity":"major",'
    '"observedAt":"2026-10-04T00:00:00Z","reading":%s}'
)


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


class ExactNumberTests(unittest.TestCase):
    def _raw(self, key, literal):
        return RAW_TEMPLATE % (key, literal)

    def test_adjacent_big_integers_stay_distinct(self):
        a = parse_alert_json(self._raw("K", "9007199254740992"))
        b = parse_alert_json(self._raw("K", "9007199254740993"))
        self.assertEqual(a.reading, Decimal("9007199254740992"))
        self.assertEqual(b.reading, Decimal("9007199254740993"))
        self.assertNotEqual(a.reading, b.reading)
        self.assertNotEqual(a.to_dict(), b.to_dict())

    def test_adjacent_decimals_stay_distinct(self):
        a = parse_alert_json(self._raw("K", "0.1"))
        b = parse_alert_json(self._raw("K", "0.10000000000000001"))
        self.assertEqual(a.reading, Decimal("0.1"))
        self.assertEqual(b.reading, Decimal("0.10000000000000001"))
        self.assertNotEqual(a.reading, b.reading)

    def test_integer_and_exponent_literals(self):
        self.assertEqual(parse_alert_json(self._raw("K", "5")).reading, Decimal("5"))
        self.assertEqual(parse_alert_json(self._raw("K", "1e3")).reading, Decimal("1e3"))
        self.assertEqual(parse_alert_json(self._raw("K", "-2.50")).reading, Decimal("-2.50"))

    def test_float_inputs_remain_supported(self):
        alert = parse_alert(dict(VALID, reading=6.25))
        self.assertEqual(alert.reading, Decimal("6.25"))

    def test_non_finite_numbers_rejected(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(ValidationError, msg=literal):
                parse_alert_json(self._raw("K", literal))

    def test_extreme_exponent_stays_compact(self):
        alert = parse_alert_json(self._raw("K", "1e99999"))
        rendered = format_number(alert.reading)
        self.assertLessEqual(len(rendered), 16)
        # The rendering must still express the exact same value.
        import json as _json
        self.assertEqual(_json.loads(rendered, parse_float=Decimal), alert.reading)

    def test_format_number_plain_json_literals(self):
        cases = {
            "5": "5", "5.0": "5.0", "0.10": "0.10", "0.1": "0.1",
            "0.001": "0.001", "100": "100", "1.5": "1.5",
            "-0.5": "-0.5", "9007199254740993": "9007199254740993",
        }
        for given, expected in cases.items():
            self.assertEqual(format_number(Decimal(given)), expected, given)
            # Every rendering must be a valid, exact JSON number literal.
            import json as _json
            self.assertEqual(_json.loads(expected, parse_float=Decimal), Decimal(given))

    def test_canonical_json_keeps_numbers_exact_and_stable(self):
        body1 = {"reading": Decimal("9007199254740992"), "z": 1, "a": "x"}
        body2 = {"reading": Decimal("9007199254740993"), "z": 1, "a": "x"}
        text1 = canonical_json(body1)
        self.assertIn('"reading":9007199254740992', text1)
        self.assertEqual(text1, canonical_json(body1))  # deterministic
        self.assertNotEqual(text1, canonical_json(body2))
        dec = canonical_json({"reading": Decimal("0.10000000000000001")})
        self.assertIn("0.10000000000000001", dec)

    def test_content_equal_numeric_semantics(self):
        self.assertTrue(content_equal({"reading": Decimal("5")}, {"reading": Decimal("5.0")}))
        self.assertTrue(content_equal({"reading": 5.0}, {"reading": Decimal("5")}))
        self.assertFalse(content_equal(
            {"reading": Decimal("9007199254740992")},
            {"reading": Decimal("9007199254740993")}))
        self.assertFalse(content_equal(
            {"reading": Decimal("0.1")}, {"reading": Decimal("0.10000000000000001")}))
        self.assertTrue(content_equal({"a": [1, Decimal("2.0")]}, {"a": [1, 2.0]}))
        self.assertFalse(content_equal({"a": 1}, {"a": 1, "b": 2}))
        self.assertFalse(content_equal({"a": True}, {"a": 1}))


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

    def test_legacy_double_format_body_still_replays(self):
        # A row written by the old version serialised numbers via json.dumps
        # (integral reading 5 stored as 5.0); same content must still replay.
        import json
        _, aid, _, did = self.db.accept_alert("K", {"reading": Decimal("5")})
        conn = self.db.conn
        conn.execute(
            "UPDATE alerts SET body_json = ? WHERE alert_id = ?",
            (json.dumps({"reading": 5.0}, sort_keys=True, separators=(",", ":")), aid),
        )
        conn.commit()
        outcome, replayed_aid, _, replayed_did = self.db.accept_alert(
            "K", {"reading": Decimal("5")})
        self.assertEqual(outcome, "replayed")
        self.assertEqual(replayed_aid, aid)
        self.assertEqual(replayed_did, did)

    def test_exact_number_conflict_at_store(self):
        self.db.accept_alert("K", {"reading": Decimal("9007199254740992")})
        with self.assertRaises(ConflictError):
            self.db.accept_alert("K", {"reading": Decimal("9007199254740993")})
        self.db.accept_alert("K", {"reading": Decimal("9007199254740992")})


if __name__ == "__main__":
    unittest.main()
