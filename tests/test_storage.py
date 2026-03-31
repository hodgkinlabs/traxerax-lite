"""Tests for SQLite storage."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
    make_event_hash,
    make_finding_hash,
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


def test_make_event_hash_is_deterministic() -> None:
    """Same event data should always produce the same hash."""
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
        action=None,
        jail=None,
    )

    hash_1 = make_event_hash(event)
    hash_2 = make_event_hash(event)

    assert hash_1 == hash_2


def test_make_finding_hash_is_deterministic() -> None:
    """Same finding data should always produce the same hash."""
    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message="Successful SSH login after prior failures",
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    hash_1 = make_finding_hash(finding)
    hash_2 = make_finding_hash(finding)

    assert hash_1 == hash_2


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
        action=None,
        jail=None,
    )

    insert_event(connection, event)

    row = connection.execute(
        """
        SELECT
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
        FROM events
        """
    ).fetchone()

    assert row is not None
    assert row["event_hash"] == make_event_hash(event)
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
    assert row["action"] is None
    assert row["jail"] is None

    connection.close()


def test_insert_duplicate_event_is_ignored() -> None:
    """Duplicate events should not be inserted twice."""
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
        action=None,
        jail=None,
    )

    insert_event(connection, event)
    insert_event(connection, event)

    row = connection.execute(
        "SELECT COUNT(*) AS count FROM events"
    ).fetchone()

    assert row is not None
    assert row["count"] == 1

    connection.close()


def test_insert_fail2ban_event_persists_action_and_jail() -> None:
    """Inserted fail2ban events should store action and jail."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 8),
        source="fail2ban",
        event_type="fail2ban_ban",
        raw="test fail2ban line",
        src_ip="185.10.10.1",
        service="sshd",
        process="fail2ban",
        action="ban",
        jail="actions",
    )

    insert_event(connection, event)

    row = connection.execute(
        """
        SELECT
            event_hash,
            source,
            event_type,
            src_ip,
            service,
            process,
            action,
            jail
        FROM events
        """
    ).fetchone()

    assert row is not None
    assert row["event_hash"] == make_event_hash(event)
    assert row["source"] == "fail2ban"
    assert row["event_type"] == "fail2ban_ban"
    assert row["src_ip"] == "185.10.10.1"
    assert row["service"] == "sshd"
    assert row["process"] == "fail2ban"
    assert row["action"] == "ban"
    assert row["jail"] == "actions"

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
            finding_hash,
            timestamp,
            finding_type,
            severity,
            message,
            src_ip
        FROM findings
        """
    ).fetchone()

    assert row is not None
    assert row["finding_hash"] == make_finding_hash(finding)
    assert row["timestamp"] == "2026-03-25 10:01:20"
    assert row["finding_type"] == "success_after_failures"
    assert row["severity"] == "high"
    assert row["message"] == "Successful SSH login after prior failures"
    assert row["src_ip"] == "203.0.113.77"

    connection.close()


def test_insert_duplicate_finding_is_ignored() -> None:
    """Duplicate findings should not be inserted twice."""
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
    insert_finding(connection, finding)

    row = connection.execute(
        "SELECT COUNT(*) AS count FROM findings"
    ).fetchone()

    assert row is not None
    assert row["count"] == 1

    connection.close()