"""SQLite backup / restore commands using the online-backup API."""
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.auth.audit import record_audit
from app.database import db_cursor


def _database_path() -> str:
    # Read at call time so tests can monkeypatch `app.config.DATABASE_PATH`
    # between module import and the command actually running.
    from app import config
    return config.DATABASE_PATH


def register(sub):
    pb = sub.add_parser("backup", help="Online-backup the SQLite DB to a file.")
    pb.add_argument("--output", help="Destination path. Defaults to data/backup-<UTC>.db")
    pb.set_defaults(func=cmd_backup)

    pr = sub.add_parser("restore", help="Restore the SQLite DB from a backup file.")
    pr.add_argument("input", help="Path to a previously-created backup .db.")
    pr.add_argument(
        "--force", action="store_true",
        help="Replace the current DB without confirmation.",
    )
    pr.set_defaults(func=cmd_restore)


def cmd_backup(args):
    output = args.output
    if not output:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = str(Path(_database_path()).parent / f"backup-{ts}.db")
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    src = sqlite3.connect(_database_path())
    dst = sqlite3.connect(output)
    try:
        with dst:
            src.backup(dst)
    finally:
        src.close()
        dst.close()

    with db_cursor() as conn:
        record_audit(conn, action="db_backup", actor="cli", payload={"output": output})
    print(f"Wrote backup → {output}")


def cmd_restore(args):
    src_path = Path(args.input)
    if not src_path.exists():
        print(f"Backup file not found: {src_path}")
        sys.exit(1)
    try:
        probe = sqlite3.connect(str(src_path))
        probe.execute("PRAGMA schema_version").fetchone()
        probe.close()
    except sqlite3.DatabaseError as exc:
        print(f"Refusing to restore: {src_path} is not a valid SQLite file ({exc}).")
        sys.exit(1)

    dst_path = Path(_database_path())
    if dst_path.exists() and not args.force:
        print(
            f"{dst_path} already exists. Re-run with --force to overwrite "
            f"(a sidecar copy will be saved to {dst_path}.bak first)."
        )
        sys.exit(1)

    if dst_path.exists():
        # Flush WAL into the main file so the .bak captures a complete snapshot.
        try:
            checkpoint = sqlite3.connect(str(dst_path))
            checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            checkpoint.close()
        except sqlite3.DatabaseError:
            pass
        sidecar = Path(str(dst_path) + ".bak")
        shutil.copy2(dst_path, sidecar)
        print(f"Saved current DB → {sidecar}")

    # Drop any leftover WAL/SHM sidecars so SQLite doesn't replay
    # post-backup writes onto the freshly-restored main DB.
    for suffix in ("-wal", "-shm"):
        leftover = Path(str(dst_path) + suffix)
        if leftover.exists():
            try:
                leftover.unlink()
            except OSError:
                pass

    shutil.copy2(src_path, dst_path)

    with db_cursor() as conn:
        record_audit(conn, action="db_restore", actor="cli",
                     payload={"input": str(src_path)})
    print(f"Restored {dst_path} from {src_path}.")
