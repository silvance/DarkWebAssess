"""Cross-thread connection regression test.

Streamlit reruns each script execution on a fresh worker thread, and
APScheduler dispatches to its worker pool. With the default
`check_same_thread=True`, a connection cached at module-load time would
raise ProgrammingError when a query lands on a different thread —
exactly what v0.1.0 hit on the released .exe. This test verifies that
get_connection() returns connections we can use across threads.
"""
import os
import tempfile
import threading

import pytest

from app.database import get_connection, init_db


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass


def test_connection_can_be_used_from_a_different_thread(db_path):
    """The exact scenario the dashboard hits: one connection opened on
    thread A is read from thread B."""
    conn = get_connection(db_path)
    errors: list = []

    def query_from_other_thread():
        try:
            row = conn.execute("SELECT COUNT(*) AS n FROM documents").fetchone()
            assert row["n"] == 0
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=query_from_other_thread)
    t.start()
    t.join()
    conn.close()
    assert errors == [], f"cross-thread query raised: {errors!r}"


def test_concurrent_threads_can_query_simultaneously(db_path):
    """Sanity check that multiple readers don't deadlock under the
    busy_timeout + WAL config."""
    conn = get_connection(db_path)
    errors: list = []

    def loop():
        try:
            for _ in range(20):
                conn.execute("SELECT COUNT(*) FROM documents").fetchone()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=loop) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    conn.close()
    assert errors == [], f"concurrent reads raised: {errors!r}"
