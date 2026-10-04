"""Runtime configuration for the alert API.

Everything is environment driven so the same image can be configured for
local development, docker-compose and tests without code changes.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    db_path: str
    shared_secret: str
    receiver_url: str
    delivery_timeout: float
    max_retries: int           # retries *after* the first attempt (3 => up to 4 attempts)
    backoff_base: float        # seconds; nth backoff = base * retry_number
    poll_interval: float       # worker queue polling interval
    stale_after: float         # interrupted in-flight claim is reclaimable after this
    sim_token: str

    @classmethod
    def from_env(cls) -> "Settings":
        timeout = float(os.getenv("DELIVERY_TIMEOUT", "2.0"))
        return cls(
            host=os.getenv("API_HOST", "0.0.0.0"),
            port=int(os.getenv("API_PORT", "8080")),
            db_path=os.getenv("API_DB", os.path.join("data", "api.db")),
            shared_secret=os.getenv("SHARED_SECRET", "dev-shared-secret-change-me"),
            receiver_url=os.getenv("RECEIVER_URL", "http://127.0.0.1:9090/ingest"),
            delivery_timeout=timeout,
            max_retries=int(os.getenv("DELIVERY_MAX_RETRIES", "3")),
            backoff_base=float(os.getenv("DELIVERY_BACKOFF_BASE", "0.5")),
            poll_interval=float(os.getenv("DELIVERY_POLL_INTERVAL", "0.05")),
            stale_after=float(os.getenv("DELIVERY_STALE_AFTER", str(timeout + 15.0))),
            sim_token=os.getenv("SIM_FAULT_TOKEN", "dev-sim-token"),
        )
