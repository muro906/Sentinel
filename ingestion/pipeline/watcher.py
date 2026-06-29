"""
Pipeline watcher – monitors the Zeek log directory for new/modified log files
and triggers extraction + Kafka publishing.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
from watchdog.observers import Observer

from features.extractor import extract_features
from kafka.producer import FeatureProducer

log = logging.getLogger(__name__)

ZEEK_LOG_DIR    = Path(os.getenv("ZEEK_LOG_DIR", "/zeek-logs"))
SETTLE_SECS     = float(os.getenv("LOG_SETTLE_SECS", "3"))
# Persisted across container restarts so we never re-publish the same log.
_PROCESSED_FILE = ZEEK_LOG_DIR / ".processed_logs"


def _load_processed() -> set[str]:
    try:
        return set(_PROCESSED_FILE.read_text().splitlines())
    except FileNotFoundError:
        return set()


def _mark_processed(path: str) -> None:
    with open(_PROCESSED_FILE, "a") as f:
        f.write(path + "\n")


class ZeekLogHandler(FileSystemEventHandler):
    """Fires whenever a Zeek log file is created or written to."""

    def __init__(self, producer: FeatureProducer) -> None:
        super().__init__()
        self._producer = producer
        self._processed: set[str] = _load_processed()
        log.info("[watcher] Loaded %d previously-processed log paths", len(self._processed))

    def _handle(self, path: Path) -> None:
        if path.suffix not in (".log",):
            return
        if path.name not in ("conn.log",):
            # We process conn.log; ssl/dns are enrichment pulled during extraction
            return
        key = str(path)
        if key in self._processed:
            # Already handled this exact file; skip unless mtime changed
            return

        log.info("[watcher] Detected: %s — waiting %ss for file to settle…", path, SETTLE_SECS)
        time.sleep(SETTLE_SECS)

        log_dir = path.parent
        log.info("[watcher] Extracting features from: %s", log_dir)
        vectors = extract_features(log_dir)

        if not vectors:
            log.warning("[watcher] No feature vectors extracted from %s", log_dir)
            return

        log.info("[watcher] Extracted %d feature vectors, publishing to Kafka…", len(vectors))
        sent = self._producer.publish(vectors)
        log.info("[watcher] %d vectors published.", sent)
        self._processed.add(key)
        _mark_processed(key)

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._handle(Path(event.src_path))

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not event.is_directory:
            self._handle(Path(event.src_path))


def run_watcher(producer: FeatureProducer) -> None:
    """Scan existing log directories then watch for new ones."""
    ZEEK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = ZeekLogHandler(producer)

    # Process any conn.log files that already exist
    for conn_log in ZEEK_LOG_DIR.rglob("conn.log"):
        log.info("[watcher] Bootstrapping existing log: %s", conn_log)
        handler._handle(conn_log)

    observer = Observer()
    observer.schedule(handler, str(ZEEK_LOG_DIR), recursive=True)
    observer.start()
    log.info("[watcher] Watching %s for Zeek logs…", ZEEK_LOG_DIR)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
