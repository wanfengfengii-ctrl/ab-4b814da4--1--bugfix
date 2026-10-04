"""Domain model and exact-value JSON (de)serialisation for alert payloads.

The caller submits: alertKey, station, sequence, severity, observedAt, reading.
All fields except `reading` are strings/integers; `reading` may be any finite
JSON number.

JSON numbers are parsed with their *exact* numeric value: fractional/exp
literals become ``Decimal`` and integral literals stay arbitrary-precision
``int``.  Distinct legal values therefore stay distinct end to end -
validation, the idempotency/conflict comparison and the canonical signed
delivery body - e.g. 9007199254740992 vs 9007199254740993 (two doubles would
collapse) or 0.1 vs 0.10000000000000001.

``float`` values supplied directly to ``parse_alert`` (in-process callers and
tests) are accepted via their shortest round-trip ``repr``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal

REQUIRED_FIELDS = ("alertKey", "station", "sequence", "severity", "observedAt", "reading")
ALLOWED_SEVERITIES = ("info", "warning", "minor", "major", "critical")


class ValidationError(ValueError):
    """Raised when a submitted alert body is missing fields or malformed."""


class ConflictError(ValueError):
    """Raised when the same alertKey is reused with different content."""


@dataclass(frozen=True)
class Alert:
    alert_key: str
    station: str
    sequence: int
    severity: str
    observed_at: str
    reading: Decimal

    def to_dict(self) -> dict:
        return {
            "alertKey": self.alert_key,
            "station": self.station,
            "sequence": self.sequence,
            "severity": self.severity,
            "observedAt": self.observed_at,
            "reading": self.reading,
        }


# --------------------------------------------------------------------- parsing
def _reject_constant(name: str) -> Decimal:
    # json.loads only routes NaN/Infinity/-Infinity here.
    raise ValidationError(f"field reading must be a finite number, got {name}")


def parse_alert_json(raw: bytes | str) -> Alert:
    """Decode a submitted JSON body without losing numeric precision."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    data = json.loads(
        text,
        parse_float=Decimal,
        parse_constant=_reject_constant,
    )
    return parse_alert(data)


# ------------------------------------------------------------------ numbers
def as_exact_number(value: object) -> Decimal:
    """Coerce a JSON number (Decimal/int/float) to a finite Decimal."""
    if isinstance(value, bool):
        raise ValidationError("field reading must be a number")
    if isinstance(value, Decimal):
        number = value
    elif isinstance(value, int):
        number = Decimal(value)
    elif isinstance(value, float):
        # str(float) is the shortest repr that round-trips: the float's exact
        # value is preserved without introducing binary expansion noise.
        number = Decimal(str(value))
    else:
        raise ValidationError("field reading must be a number")
    if not number.is_finite():
        raise ValidationError("field reading must be a finite number")
    return number


def format_number(number: Decimal) -> str:
    """Render a Decimal as an exact JSON number literal.

    Ordinary magnitudes use plain notation ("0.1", "1000000"); magnitudes that
    would need more than a handful of leading/trailing zeroes keep exponent
    notation ("1e+99999") so a tiny request can never expand into huge bytes.
    Both spellings are exact and replay-compatible (numbers are also compared
    by value).
    """
    if not number.is_finite():
        raise ValidationError("field reading must be a finite number")
    if number == 0:
        return "0"
    sign, digits, exp = number.as_tuple()
    coefficient = "".join(str(d) for d in digits)
    if exp >= 0:
        if exp <= 6:
            literal = coefficient + "0" * exp
        else:
            literal = _scientific(coefficient, exp + len(digits) - 1)
    else:
        cut = len(coefficient) + exp
        if cut > 0:
            literal = coefficient[:cut] + "." + coefficient[cut:]
        elif -cut <= 6:
            literal = "0." + "0" * (-cut) + coefficient
        else:
            literal = _scientific(coefficient, exp + len(digits) - 1)
    return "-" + literal if sign else literal


def _scientific(coefficient: str, adjusted_exp: int) -> str:
    mantissa = coefficient[0] + ("." + coefficient[1:] if len(coefficient) > 1 else "")
    sign = "+" if adjusted_exp >= 0 else "-"
    return f"{mantissa}e{sign}{abs(adjusted_exp)}"


def canonical_json(value: object) -> str:
    """Stable compact JSON used for the stored body and signed delivery body.

    Keys are sorted and Decimal values are emitted as exact number literals,
    so equal numeric content always produces identical bytes.
    """
    if isinstance(value, Decimal):
        return format_number(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return format_number(Decimal(str(value)))
    if value is None:
        return "null"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            canonical_json(key) + ":" + canonical_json(value[key])
            for key in sorted(value)
        ) + "}"
    raise TypeError(f"cannot canonically serialize {type(value).__name__}")


def _as_decimal(value: object) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, float):
        return Decimal(str(value))
    return Decimal(value)


def content_equal(left: object, right: object) -> bool:
    """Compare decoded JSON bodies by value; numbers compare numerically.

    This also reconciles rows written by older versions, whose canonical body
    serialised numbers as doubles (e.g. integral reading 5 stored as ``5.0``):
    a numerically identical replay still counts as the same content.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float, Decimal)) and isinstance(right, (int, float, Decimal)):
        return _as_decimal(left) == _as_decimal(right)
    if isinstance(left, dict) and isinstance(right, dict):
        return (left.keys() == right.keys()
                and all(content_equal(left[k], right[k]) for k in left))
    if isinstance(left, list) and isinstance(right, list):
        return (len(left) == len(right)
                and all(content_equal(x, y) for x, y in zip(left, right)))
    return left == right


# ----------------------------------------------------------------- validation
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
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValidationError("field sequence must be a non-negative integer")
    if severity not in ALLOWED_SEVERITIES:
        raise ValidationError(
            f"field severity must be one of: {', '.join(ALLOWED_SEVERITIES)}")
    reading = as_exact_number(reading)

    return Alert(
        alert_key=alert_key.strip(),
        station=station.strip(),
        sequence=int(sequence),
        severity=severity,
        observed_at=observed_at.strip(),
        reading=reading,
    )
