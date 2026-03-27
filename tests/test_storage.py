"""Tests for SQLite storage."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
)


def test_initialize_database_creates_tables() -> None:
    """Database initialization should create events and findings tables."""
    connection = get_connection(":memory:")

    initialize_database(connection)

    cursor = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    )
    table_names = {row["name"] for row in cursor.fetchall()}

    assert "events" in table_names
    assert "findings" in table_names

    connection.close()


def test_insert_event_persists_event_row() -> None:
    """Inserted events should be stored in the events table."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="test raw event line",
        username="user1",
        src_ip="203.0.113.77",
        port=50001,
        service="ssh",
        hostname="debian",
        process="sshd",
    )

    insert_event(connection, event)

    row = connection.execute(
        """
        SELECT
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
        FROM events
        """
    ).fetchone()

    assert row is not None
    assert row["timestamp"] == "2026-03-25 10:01:20"
    assert row["source"] == "auth"
    assert row["event_type"] == "ssh_success_login"
    assert row["raw"] == "test raw event line"
    assert row["username"] == "user1"
    assert row["src_ip"] == "203.0.113.77"
    assert row["port"] == 50001
    assert row["service"] == "ssh"
    assert row["hostname"] == "debian"
    assert row["process"] == "sshd"

    connection.close()


def test_insert_finding_persists_finding_row() -> None:
    """Inserted findings should be stored in the findings table."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message="Successful SSH login after prior failures",
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    insert_finding(connection, finding)

    row = connection.execute(
        """
        SELECT
            timestamp,
            finding_type,
            severity,
            message,
            src_ip
        FROM findings
        """
    ).fetchone()

    assert row is not None
    assert row["timestamp"] == "2026-03-25 10:01:20"
    assert row["finding_type"] == "success_after_failures"
    assert row["severity"] == "high"
    assert row["message"] == "Successful SSH login after prior failures"
    assert row["src_ip"] == "203.0.113.77"

    connection.close()