"""In-process test stack: gateway simulator + alert API + delivery worker."""
from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from app.config import Settings
from app.server import make_server
from app.worker import DeliveryWorker
from receiver.simulator import FaultPlan, build_server

TEST_SECRET = "unit-test-shared-secret"
TEST_SIM_TOKEN = "unit-test-sim-token"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_request(method: str, url: str, body: bytes | dict | None = None,
                 headers: dict | None = None, timeout: float = 10.0):
    """Return (status_code, parsed_json_or_text). Network errors propagate."""
    headers = dict(headers or {})
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        else:
            data = body
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, raw.decode("utf-8", "replace")


@dataclass
class Stack:
    api_url: str
    sim_url: str
    fault: FaultPlan
    tmpdir: tempfile.TemporaryDirectory
    _sim_httpd: object
    _api_httpd: object
    _worker: DeliveryWorker
    _threads: list
    _api_settings: Settings = None  # type: ignore[assignment]

    def stop(self) -> None:
        self._worker.stop()
        self._worker.join(timeout=5)
        shutdown = threading.Thread(target=self._api_httpd.shutdown, daemon=True)
        shutdown.start()
        shutdown.join(5)
        if self._sim_httpd is not None:
            shutdown = threading.Thread(target=self._sim_httpd.shutdown, daemon=True)
            shutdown.start()
            shutdown.join(5)
            self._sim_httpd.server_close()
        self._api_httpd.server_close()
        self.tmpdir.cleanup()

    def restart_api(self, *, stale_after: float = 0.0,
                    backoff_base: float | None = None) -> None:
        """Simulate an API/worker process restart against the same database."""
        self._worker.stop()
        self._worker.join(timeout=5)
        shutdown = threading.Thread(target=self._api_httpd.shutdown, daemon=True)
        shutdown.start()
        shutdown.join(5)
        self._api_httpd.server_close()

        new_settings = Settings(
            host=self._api_settings.host, port=self._api_settings.port,
            db_path=self._api_settings.db_path,
            shared_secret=self._api_settings.shared_secret,
            receiver_url=self._api_settings.receiver_url,
            delivery_timeout=self._api_settings.delivery_timeout,
            max_retries=self._api_settings.max_retries,
            backoff_base=(backoff_base if backoff_base is not None
                          else self._api_settings.backoff_base),
            poll_interval=self._api_settings.poll_interval,
            stale_after=stale_after,
            sim_token=self._api_settings.sim_token,
        )
        self._api_settings = new_settings
        self._api_httpd = make_server(new_settings)
        self._api_httpd.daemon_threads = True
        self._worker = DeliveryWorker(self._api_httpd.db, new_settings)
        thread = threading.Thread(target=self._api_httpd.serve_forever, daemon=True)
        thread.start()
        self._threads.append(thread)
        self._worker.start()
        _wait_health(f"{self.api_url}/healthz")

    # -- convenience clients --------------------------------------------------
    def post_alert(self, payload: dict):
        return http_request("POST", f"{self.api_url}/api/alerts", payload)

    def post_alert_text(self, raw: str | bytes):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return http_request(
            "POST", f"{self.api_url}/api/alerts", raw,
            headers={"Content-Type": "application/json"})

    def get_alert(self, alert_id: str):
        return http_request("GET", f"{self.api_url}/api/alerts/{alert_id}")

    def wait_terminal(self, alert_id: str, timeout: float = 20.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, body = self.get_alert(alert_id)
            if body["status"] in ("delivered", "failed"):
                return body
            time.sleep(0.1)
        raise AssertionError(f"alert {alert_id} did not reach terminal state in {timeout}s")

    def set_fault(self, spec: dict | None):
        return http_request(
            "POST", f"{self.sim_url}/sim/control", spec or {"mode": None},
            headers={"X-Sim-Token": TEST_SIM_TOKEN})

    def accepted(self):
        _, body = http_request("GET", f"{self.sim_url}/sim/accepted")
        return body["accepted"]

    def acceptance_count(self, delivery_id: str) -> int:
        return sum(1 for row in self.accepted() if row["delivery_id"] == delivery_id)

    def requests_for(self, delivery_id: str):
        _, body = http_request(
            "GET", f"{self.sim_url}/sim/requests?deliveryId={delivery_id}")
        return body["requests"]


def start_stack(*, delivery_timeout: float = 2.0, max_retries: int = 3,
                backoff_base: float = 0.05, stale_after: float = 30.0,
                dead_receiver: bool = False) -> Stack:
    tmpdir = tempfile.TemporaryDirectory(prefix="alert-test-")
    sim_port = free_port()
    api_port = free_port()
    fault = FaultPlan()
    if dead_receiver:
        sim_httpd = None
    else:
        sim_httpd = build_server(
            "127.0.0.1", sim_port, f"{tmpdir.name}/receiver.db",
            secret=TEST_SECRET, token=TEST_SIM_TOKEN, fault=fault)
    settings = Settings(
        host="127.0.0.1", port=api_port,
        db_path=f"{tmpdir.name}/api.db",
        shared_secret=TEST_SECRET,
        receiver_url=f"http://127.0.0.1:{sim_port}/ingest",
        delivery_timeout=delivery_timeout,
        max_retries=max_retries,
        backoff_base=backoff_base,
        poll_interval=0.03,
        stale_after=stale_after,
        sim_token=TEST_SIM_TOKEN,
    )
    api_httpd = make_server(settings)
    worker = DeliveryWorker(api_httpd.db, settings)
    api_httpd.worker = worker
    threads = []
    for target in (sim_httpd.serve_forever if sim_httpd else None,
                   api_httpd.serve_forever):
        if target is None:
            continue
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        threads.append(thread)
    worker.start()

    stack = Stack(
        api_url=f"http://127.0.0.1:{api_port}",
        sim_url=f"http://127.0.0.1:{sim_port}",
        fault=fault, tmpdir=tmpdir,
        _sim_httpd=sim_httpd, _api_httpd=api_httpd,
        _worker=worker, _threads=threads, _api_settings=settings,
    )
    _wait_health(f"{stack.api_url}/healthz")
    if sim_httpd is not None:
        _wait_health(f"{stack.sim_url}/healthz")
    return stack


def _wait_health(url: str, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            http_request("GET", url, timeout=2)
            return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"service at {url} never became healthy")


def sample_alert(key: str = "AK-001", **overrides) -> dict:
    payload = {
        "alertKey": key,
        "station": "STA-07",
        "sequence": 42,
        "severity": "major",
        "observedAt": "2026-10-04T08:30:00Z",
        "reading": 6.7,
    }
    payload.update(overrides)
    return payload
