"""HMAC-SHA256 request signing shared by the API and the gateway simulator.

The signature binds the (deliveryId, exact request body) pair to the shared
secret. It is deterministic, so every retry of the same delivery carries the
very same signature; any tampering with the body invalidates it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

SCHEME = "seismic-alert-v1"


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _signing_input(delivery_id: str, body: bytes) -> bytes:
    return f"{SCHEME}\n{delivery_id}\n{body_digest(body)}".encode("utf-8")


def sign(secret: str, delivery_id: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), _signing_input(delivery_id, body), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def verify(secret: str, delivery_id: str, body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    expected = sign(secret, delivery_id, body)
    return hmac.compare_digest(expected, signature)
