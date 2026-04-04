import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.core.config import get_settings


def _resolve_sqlite_path(database_url: str) -> Path:
    if not database_url.startswith("sqlite:///"):
        raise ValueError("Only sqlite:/// URLs are supported in this starter backend.")
    relative_path = database_url.replace("sqlite:///", "", 1)
    return Path(relative_path).resolve()


def init_db() -> None:
    db_path = _resolve_sqlite_path(get_settings().database_url)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL DEFAULT 'pending',
                source_type TEXT NOT NULL,
                source_app TEXT,
                content_preview TEXT,
                label TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                should_block INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                provider_used TEXT,
                created_at TEXT NOT NULL,
                external_id TEXT,
                raw_text TEXT,
                raw_url TEXT,
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gmail_connections (
                email TEXT PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                expires_at INTEGER,
                watch_configured INTEGER NOT NULL DEFAULT 0,
                last_history_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _migrate_gmail_connections(connection)
        _migrate_scan_logs(connection)
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_logs_external_id
            ON scan_logs(external_id)
            WHERE external_id IS NOT NULL
            """
        )
        connection.commit()


def _migrate_scan_logs(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(scan_logs)").fetchall()
    }
    if "status" not in columns:
        connection.execute("ALTER TABLE scan_logs ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
    if "source_app" not in columns:
        connection.execute("ALTER TABLE scan_logs ADD COLUMN source_app TEXT")
    if "external_id" not in columns:
        connection.execute("ALTER TABLE scan_logs ADD COLUMN external_id TEXT")
    if "raw_text" not in columns:
        connection.execute("ALTER TABLE scan_logs ADD COLUMN raw_text TEXT")
    if "raw_url" not in columns:
        connection.execute("ALTER TABLE scan_logs ADD COLUMN raw_url TEXT")
    if "metadata" not in columns:
        connection.execute("ALTER TABLE scan_logs ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")


def _migrate_gmail_connections(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(gmail_connections)").fetchall()
    }
    if "last_history_id" not in columns:
        connection.execute("ALTER TABLE gmail_connections ADD COLUMN last_history_id TEXT")


@contextmanager
def get_db_connection() -> Iterator[sqlite3.Connection]:
    db_path = _resolve_sqlite_path(get_settings().database_url)
    connection = sqlite3.connect(db_path)
    try:
        yield connection
    finally:
        connection.close()
