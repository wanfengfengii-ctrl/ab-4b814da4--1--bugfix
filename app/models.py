"""Domain model and JSON (de)serialisation for alert payloads.

The caller submits: alertKey, station, sequence, severity, observedAt, reading.
All fields except `reading` are strings/integers; `reading` may be any JSON
number. Validation here keeps the canonical stored body stable across replays.

Number precision
----------------
Python's ``float`` cannot carry every JSON number: the neighbouring integers
``9007199254740992`` and ``9007199254740993`` both round to the same float, as
do the distinct decimals ``0.1`` and ``0.10000000000000001``. To keep the
exact numeric meaning through acceptance, idempotency judgement and the signed
gateway payload, JSON numbers are parsed (see ``parse_json``) into
``JsonNumber`` holding the *exact source token*. Equality is numeric (based on
``decimal.Decimal``), so ``1``/``1.0``/``1.00`` are the same content while the
examples above stay distinguishable. Serialisation emits the original token
verbatim, never a re-rounded float.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal

REQUIRED_FIELDS = ("alertKey", "station", "sequence", "severity", "observedAt", "reading")
ALLOWED_SEVERITIES = ("info", "warning", "minor", "major", "critical")

# Strict RFC 8259 number grammar (also used to refuse NaN/Infinity/Hex).
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_INTEGER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)")


class ValidationError(ValueError):
    """Raised when a submitted alert body is missing fields or malformed."""


class ConflictError(ValueError):
    """Raised when the same alertKey is reused with different content."""


@dataclass(frozen=True)
class JsonNumber:
    """A JSON number preserving its exact source token.

    ``token`` is the exact spelling received from the caller (validated against
    the JSON number grammar); ``decimal`` gives the exact numeric value for
    comparisons without float rounding. Two numbers are equal iff their numeric
    values are equal (``1 == 1.0 == 1.00``), but adjacent values beyond the
    float-safe range and distinct decimals remain unequal.
    """

    token: str

    def __post_init__(self) -> None:
        if not isinstance(self.token, str) or not _NUMBER_RE.fullmatch(self.token):
            raise ValueError(f"not a JSON number: {self.token!r}")

    @property
    def decimal(self) -> Decimal:
        return Decimal(self.token)

    @classmethod
    def wrap(cls, value: "JsonNumber | int | float") -> "JsonNumber":
        """Coerce a plain Python number (e.g. in tests) to a JsonNumber."""
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            raise ValidationError("field reading must be a number")
        if isinstance(value, int):
            return cls(str(value))
        if isinstance(value, float):
            # json itself emits numbers via float.__repr__; reject non-finite
            # values, which are not legal JSON numbers.
            text = repr(value)
            if not _NUMBER_RE.fullmatch(text):
                raise ValidationError("field reading must be a finite JSON number")
            return cls(text)
        raise ValidationError("field reading must be a number")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, JsonNumber):
            return self.decimal == other.decimal
        if isinstance(other, bool):
            return NotImplemented
        if isinstance(other, int):
            return self.decimal == Decimal(other)
        if isinstance(other, float):
            return self.decimal == Decimal(repr(other))
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, JsonNumber):
            return self.decimal < other.decimal
        if isinstance(other, (int, float)) and not isinstance(other, bool):
            return self.decimal < Decimal(str(other))
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.decimal)

    def __repr__(self) -> str:
        return f"JsonNumber({self.token!r})"


def parse_json(raw: "bytes | str") -> object:
    """Parse JSON, representing every number literal as an exact JsonNumber.

    Raises ValueError / UnicodeDecodeError on malformed input. The parse hooks
    mean even integer fields arrive as JsonNumber tokens; validation in
    parse_alert decides whether a token is an acceptable integer.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8")

    def _reject_constant(value: str) -> None:
        raise ValueError(f"{value} is not a valid JSON number")

    return json.loads(
        raw,
        parse_int=JsonNumber,
        parse_float=JsonNumber,
        parse_constant=_reject_constant,
    )


def _encode(value: object, *, ensure_ascii: bool, compact: bool) -> str:
    if isinstance(value, JsonNumber):
        # Exact caller spelling; never round-trip through float.
        return value.token
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=ensure_ascii)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return json.dumps(value, ensure_ascii=ensure_ascii)
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise TypeError("JSON object keys must be strings")
        item_sep, kv_sep = ((",", ":") if compact else (", ", ": "))
        return "{" + item_sep.join(
            json.dumps(key, ensure_ascii=ensure_ascii)
            + kv_sep
            + _encode(value[key], ensure_ascii=ensure_ascii, compact=compact)
            for key in sorted(value)
        ) + "}"
    if isinstance(value, (list, tuple)):
        item_sep = "," if compact else ", "
        return "[" + item_sep.join(
            _encode(item, ensure_ascii=ensure_ascii, compact=compact)
            for item in value
        ) + "]"
    raise TypeError(f"not JSON-serialisable: {type(value).__name__}")


def canonical_dumps(value: object) -> str:
    """Compact, key-sorted JSON; number tokens are emitted verbatim."""
    return _encode(value, ensure_ascii=True, compact=True)


def display_dumps(value: object) -> str:
    """Human-readable JSON for error messages (spaces, non-ASCII preserved)."""
    return _encode(value, ensure_ascii=False, compact=False)


def _as_decimal(value: object):
    if isinstance(value, bool):
        return None
    if isinstance(value, JsonNumber):
        return value.decimal
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(repr(value))
    return None


def json_equal(a: object, b: object) -> bool:
    """Numeric-meaning-preserving structural equality of parsed JSON trees.

    Numbers compare by exact Decimal value (so a float tree loaded by plain
    json.loads still compares correctly against an exact tree); bools never
    compare equal to numbers.
    """
    da, db = _as_decimal(a), _as_decimal(b)
    if da is not None or db is not None:
        return da is not None and db is not None and da == db
    if isinstance(a, dict) or isinstance(b, dict):
        if not (isinstance(a, dict) and isinstance(b, dict)):
            return False
        if a.keys() != b.keys():
            return False
        return all(json_equal(a[key], b[key]) for key in a)
    if isinstance(a, (list, tuple)) or isinstance(b, (list, tuple)):
        if not (isinstance(a, (list, tuple)) and isinstance(b, (list, tuple))):
            return False
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    return a == b


@dataclass(frozen=True)
class Alert:
    alert_key: str
    station: str
    sequence: int
    severity: str
    observed_at: str
    reading: JsonNumber

    def to_dict(self) -> dict:
        return {
            "alertKey": self.alert_key,
            "station": self.station,
            "sequence": self.sequence,
            "severity": self.severity,
            "observedAt": self.observed_at,
            "reading": self.reading,
        }


def parse_alert(data: object) -> Alert:
    if not isinstance(data, dict):
        raise ValidationError("request body must be a JSON object")
    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise ValidationError(f"missing required field(s): {', '.join(missing)}")
    extra = sorted(set(data) - set(REQUIRED_FIELDS))
    if extra:
        raise ValidationError(f"unexpected field(s): {', '.join(extra)}")

    alert_key = data["alertKey"]
    station = data["station"]
    severity = data["severity"]
    observed_at = data["observedAt"]
    sequence = data["sequence"]
    reading = data["reading"]

    for name, value in (("alertKey", alert_key), ("station", station),
                        ("severity", severity), ("observedAt", observed_at)):
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"field {name} must be a non-empty string")
    if isinstance(sequence, bool):
        raise ValidationError("field sequence must be a non-negative integer")
    if isinstance(sequence, JsonNumber):
        # Only an integer literal (no fraction/exponent) counts as an integer.
        if not _INTEGER_RE.fullmatch(sequence.token):
            raise ValidationError("field sequence must be a non-negative integer")
        sequence_value = int(sequence.token)
    elif isinstance(sequence, int):
        sequence_value = int(sequence)
    else:
        raise ValidationError("field sequence must be a non-negative integer")
    if sequence_value < 0:
        raise ValidationError("field sequence must be a non-negative integer")
    if severity not in ALLOWED_SEVERITIES:
        raise ValidationError(
            f"field severity must be one of: {', '.join(ALLOWED_SEVERITIES)}")
    if isinstance(reading, bool):
        raise ValidationError("field reading must be a number")
    reading_value = JsonNumber.wrap(reading)

    return Alert(
        alert_key=alert_key.strip(),
        station=station.strip(),
        sequence=sequence_value,
        severity=severity,
        observed_at=observed_at.strip(),
        reading=reading_value,
    )
