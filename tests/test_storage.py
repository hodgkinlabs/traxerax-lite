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


def test_insert_nginx_event_persists_http_fields() -> None:
    """Inserted nginx events should store method, path, and status code."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 4),
        source="nginx",
        event_type="nginx_suspicious_request",
        raw="nginx line",
        src_ip="185.10.10.1",
        service="nginx",
        process="nginx",
        method="GET",
        path="/wp-login.php",
        status_code=404,
    )

    insert_event(connection, event)

    row = connection.execute(
        """
        SELECT
            event_hash,
            source,
            event_type,
            src_ip,
            method,
            path,
            status_code
        FROM events
        """
    ).fetchone()

    assert row is not None
    assert row["event_hash"] == make_event_hash(event)
    assert row["source"] == "nginx"
    assert row["event_type"] == "nginx_suspicious_request"
    assert row["src_ip"] == "185.10.10.1"
    assert row["method"] == "GET"
    assert row["path"] == "/wp-login.php"
    assert row["status_code"] == 404

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
    )

    insert_event(connection, event)
    insert_event(connection, event)

    row = connection.execute(
        "SELECT COUNT(*) AS count FROM events"
    ).fetchone()

    assert row is not None
    assert row["count"] == 1

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