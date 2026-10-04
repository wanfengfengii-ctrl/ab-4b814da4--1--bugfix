"""Domain model and JSON (de)serialisation for alert payloads.

The caller submits: alertKey, station, sequence, severity, observedAt, reading.
All fields except `reading` are strings/integers; `reading` may be any JSON
number. Validation here keeps the canonical stored body stable across replays.
"""
from __future__ import annotations

from dataclasses import dataclass

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
    reading: float

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
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValidationError("field sequence must be a non-negative integer")
    if severity not in ALLOWED_SEVERITIES:
        raise ValidationError(
            f"field severity must be one of: {', '.join(ALLOWED_SEVERITIES)}")
    if isinstance(reading, bool) or not isinstance(reading, (int, float)):
        raise ValidationError("field reading must be a number")

    return Alert(
        alert_key=alert_key.strip(),
        station=station.strip(),
        sequence=int(sequence),
        severity=severity,
        observed_at=observed_at.strip(),
        reading=float(reading),
    )
