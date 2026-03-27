"""SQLite storage for Traxerax Lite."""

import sqlite3
from pathlib import Path

from traxerax_lite.models import Event, Finding


DEFAULT_DB_PATH = "data/output/traxerax_lite.db"


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a SQLite connection, creating parent directories if needed."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create required tables if they do not already exist."""
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            raw TEXT NOT NULL,
            username TEXT,
            src_ip TEXT,
            port INTEGER,
            service TEXT,
            hostname TEXT,
            process TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            src_ip TEXT
        )
        """
    )

    connection.commit()


def insert_event(connection: sqlite3.Connection, event: Event) -> None:
    """Insert a normalized event into the database."""
    connection.execute(
        """
        INSERT INTO events (
            timestamp,
            source,
            event_type,
            raw,
            username,
            src_ip,
            port,
            service,
            hostname,
            process
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.timestamp.isoformat(sep=" "),
            event.source,
            event.event_type,
            event.raw,
            event.username,
            event.src_ip,
            event.port,
            event.service,
            event.hostname,
            event.process,
        ),
    )
    connection.commit()


def insert_finding(connection: sqlite3.Connection, finding: Finding) -> None:
    """Insert a detection finding into the database."""
    connection.execute(
        """
        INSERT INTO findings (
            timestamp,
            finding_type,
            severity,
            message,
            src_ip
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            finding.timestamp.isoformat(sep=" "),
            finding.finding_type,
            finding.severity,
            finding.message,
            finding.src_ip,
        ),
    )
    connection.commit()