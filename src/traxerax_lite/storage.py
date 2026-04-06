"""SQLite storage for Traxerax Lite."""

import hashlib
import sqlite3
from pathlib import Path

from traxerax_lite.models import EnforcementAction, Event, Finding


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
            jail TEXT,
            method TEXT,
            path TEXT,
            status_code INTEGER
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

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS enforcement_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            raw TEXT NOT NULL,
            src_ip TEXT,
            action TEXT NOT NULL,
            service TEXT,
            process TEXT,
            jail TEXT
        )
        """
    )

    _migrate_legacy_fail2ban_events(connection)

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
            str(event.method),
            str(event.path),
            str(event.status_code),
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


def make_enforcement_action_hash(action: EnforcementAction) -> str:
    """Return a deterministic hash for an enforcement action."""
    payload = "|".join(
        [
            action.timestamp.isoformat(sep=" "),
            action.raw,
            str(action.src_ip),
            action.action,
            str(action.service),
            str(action.process),
            str(action.jail),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def insert_event(connection: sqlite3.Connection, event: Event) -> None:
    """Insert a normalized event into the database, ignoring duplicates."""
    if event.source == "fail2ban":
        insert_enforcement_action(
            connection,
            EnforcementAction(
                timestamp=event.timestamp,
                raw=event.raw,
                src_ip=event.src_ip,
                action=event.action or event.event_type.removeprefix("fail2ban_"),
                service=event.service,
                process=event.process,
                jail=event.jail,
            ),
        )
        return

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
            jail,
            method,
            path,
            status_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            event.method,
            event.path,
            event.status_code,
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


def insert_enforcement_action(
    connection: sqlite3.Connection,
    action: EnforcementAction,
) -> None:
    """Insert an enforcement action into the database, ignoring duplicates."""
    action_hash = make_enforcement_action_hash(action)

    connection.execute(
        """
        INSERT OR IGNORE INTO enforcement_actions (
            action_hash,
            timestamp,
            raw,
            src_ip,
            action,
            service,
            process,
            jail
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_hash,
            action.timestamp.isoformat(sep=" "),
            action.raw,
            action.src_ip,
            action.action,
            action.service,
            action.process,
            action.jail,
        ),
    )
    connection.commit()


def _migrate_legacy_fail2ban_events(connection: sqlite3.Connection) -> None:
    """Move legacy fail2ban rows out of events into enforcement_actions."""
    rows = connection.execute(
        """
        SELECT
            timestamp,
            raw,
            src_ip,
            action,
            service,
            process,
            jail
        FROM events
        WHERE source = 'fail2ban'
        """
    ).fetchall()

    for row in rows:
        connection.execute(
            """
            INSERT OR IGNORE INTO enforcement_actions (
                action_hash,
                timestamp,
                raw,
                src_ip,
                action,
                service,
                process,
                jail
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hashlib.sha256(
                    "|".join(
                        [
                            row["timestamp"],
                            row["raw"],
                            str(row["src_ip"]),
                            str(row["action"]),
                            str(row["service"]),
                            str(row["process"]),
                            str(row["jail"]),
                        ]
                    ).encode("utf-8")
                ).hexdigest(),
                row["timestamp"],
                row["raw"],
                row["src_ip"],
                row["action"] or "",
                row["service"],
                row["process"],
                row["jail"],
            ),
        )

    if rows:
        connection.execute(
            """
            DELETE FROM events
            WHERE source = 'fail2ban'
            """
        )
