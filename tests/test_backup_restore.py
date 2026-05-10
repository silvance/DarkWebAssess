import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from app import database as dbm
from app.database import get_connection, init_db
from app.repository import insert_document


@pytest.fixture
def temp_db(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    monkeypatch.setattr(dbm, "DATABASE_PATH", path)
    yield path
    if os.path.exists(path):
        os.unlink(path)
    if os.path.exists(path + ".bak"):
        os.unlink(path + ".bak")


def _seed_doc(conn, content_hash):
    return insert_document(
        conn,
        {
            "source_name": "Test",
            "source_type": "rss",
            "source_url": "https://x/y",
            "title": "t",
            "raw_text": "x",
            "raw_html": None,
            "language": None,
            "published_at": None,
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": content_hash,
        },
    )


def test_backup_command_creates_valid_sqlite(temp_db, monkeypatch, tmp_path, capsys):
    from app.cli import cmd_backup as appmain
    monkeypatch.setattr("app.config.DATABASE_PATH", temp_db)
    # Seed something so backup has content.
    with get_connection(temp_db) as conn:
        _seed_doc(conn, "h-1")
        conn.commit()
    out = tmp_path / "backup.db"

    class Args:
        output = str(out)

    appmain.cmd_backup(Args())
    assert out.exists()
    # Ensure the file is a real SQLite DB and contains our row.
    probe = sqlite3.connect(str(out))
    rows = probe.execute("SELECT COUNT(*) AS n FROM documents").fetchone()
    probe.close()
    assert rows[0] == 1


def test_restore_replaces_db_with_force(temp_db, monkeypatch, tmp_path):
    from app.cli import cmd_backup as appmain
    monkeypatch.setattr("app.config.DATABASE_PATH", temp_db)
    # First write A → backup → mutate → restore → expect A.
    with get_connection(temp_db) as conn:
        _seed_doc(conn, "h-A")
        conn.commit()
    backup_path = tmp_path / "backup.db"

    class BArgs:
        output = str(backup_path)
    appmain.cmd_backup(BArgs())

    with get_connection(temp_db) as conn:
        _seed_doc(conn, "h-B")
        conn.commit()
    assert get_connection(temp_db).execute(
        "SELECT COUNT(*) AS n FROM documents"
    ).fetchone()["n"] == 2

    class RArgs:
        input = str(backup_path)
        force = True
    appmain.cmd_restore(RArgs())
    n_after = get_connection(temp_db).execute(
        "SELECT COUNT(*) AS n FROM documents"
    ).fetchone()["n"]
    assert n_after == 1


def test_restore_refuses_invalid_file(temp_db, monkeypatch, tmp_path):
    from app.cli import cmd_backup as appmain
    monkeypatch.setattr("app.config.DATABASE_PATH", temp_db)
    bogus = tmp_path / "not-a-db"
    bogus.write_text("definitely not sqlite")

    class RArgs:
        input = str(bogus)
        force = True

    with pytest.raises(SystemExit):
        appmain.cmd_restore(RArgs())


def test_restore_writes_sidecar_bak(temp_db, monkeypatch, tmp_path):
    from app.cli import cmd_backup as appmain
    monkeypatch.setattr("app.config.DATABASE_PATH", temp_db)

    backup_path = tmp_path / "backup.db"

    class BArgs:
        output = str(backup_path)
    appmain.cmd_backup(BArgs())

    class RArgs:
        input = str(backup_path)
        force = True
    appmain.cmd_restore(RArgs())
    assert (Path(temp_db).with_suffix(Path(temp_db).suffix + ".bak")).exists() or \
           os.path.exists(temp_db + ".bak")
