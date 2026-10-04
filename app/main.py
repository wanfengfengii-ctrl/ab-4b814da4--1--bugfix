"""Entry point: run the alert API together with the delivery worker."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from .config import Settings
from .server import make_server
from .worker import DeliveryWorker


def main() -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("main")
    settings = Settings.from_env()
    httpd = make_server(settings)
    worker = DeliveryWorker(httpd.db, settings)  # type: ignore[attr-defined]

    stop_requested = threading.Event()

    def _request_stop(signum, frame):  # pragma: no cover - signal path
        log.info("signal %s received, shutting down", signum)
        stop_requested.set()

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    # serve_forever in its own thread so the signal handler (main thread) can
    # call httpd.shutdown() without deadlocking.
    server_thread = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    server_thread.start()
    worker.start()
    log.info("alert API listening on %s:%s (db=%s, receiver=%s)",
             settings.host, settings.port, settings.db_path, settings.receiver_url)

    try:
        stop_requested.wait()
    finally:
        worker.stop()
        httpd.shutdown()
        server_thread.join(timeout=5)
        worker.join(timeout=5)
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
