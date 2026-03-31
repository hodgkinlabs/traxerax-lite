"""SQLite storage for Traxerax Lite."""

import hashlib
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
            event_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            raw TEXT NOT NULL,
            username TEXT,
            src_ip TEXT,
            port INTEGER,
            service TEXT,
            hostname TEXT,
            process TEXT,
            action TEXT,
            jail TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            src_ip TEXT
        )
        """
    )

    connection.commit()


def make_event_hash(event: Event) -> str:
    """Return a deterministic hash for an event."""
    payload = "|".join(
        [
            event.timestamp.isoformat(sep=" "),
            event.source,
            event.event_type,
            event.raw,
            str(event.username),
            str(event.src_ip),
            str(event.port),
            str(event.service),
            str(event.hostname),
            str(event.process),
            str(event.action),
            str(event.jail),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_finding_hash(finding: Finding) -> str:
    """Return a deterministic hash for a finding."""
    payload = "|".join(
        [
            finding.timestamp.isoformat(sep=" "),
            finding.finding_type,
            finding.severity,
            finding.message,
            str(finding.src_ip),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def insert_event(connection: sqlite3.Connection, event: Event) -> None:
    """Insert a normalized event into the database, ignoring duplicates."""
    event_hash = make_event_hash(event)

    connection.execute(
        """
        INSERT OR IGNORE INTO events (
            event_hash,
            timestamp,
            source,
            event_type,
            raw,
            username,
            src_ip,
            port,
            service,
            hostname,
            process,
            action,
            jail
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_hash,
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
            event.action,
            event.jail,
        ),
    )
    connection.commit()


def insert_finding(connection: sqlite3.Connection, finding: Finding) -> None:
    """Insert a detection finding into the database, ignoring duplicates."""
    finding_hash = make_finding_hash(finding)

    connection.execute(
        """
        INSERT OR IGNORE INTO findings (
            finding_hash,
            timestamp,
            finding_type,
            severity,
            message,
            src_ip
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            finding_hash,
            finding.timestamp.isoformat(sep=" "),
            finding.finding_type,
            finding.severity,
            finding.message,
            finding.src_ip,
        ),
    )
    connection.commit()