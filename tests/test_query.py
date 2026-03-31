"""Tests for SQLite query helpers."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.query import (
    get_event_counts_by_type,
    get_finding_counts_by_type,
    get_top_event_source_ips,
    get_top_finding_source_ips,
)
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
)


def test_get_event_counts_by_type_returns_grouped_counts() -> None:
    """Event count query should group events by event_type."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw2",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 3),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="raw3",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )

    rows = get_event_counts_by_type(connection)

    assert len(rows) == 2
    assert rows[0]["event_type"] == "ssh_failed_login"
    assert rows[0]["count"] == 2
    assert rows[1]["event_type"] == "fail2ban_ban"
    assert rows[1]["count"] == 1

    connection.close()


def test_get_finding_counts_by_type_returns_grouped_counts() -> None:
    """Finding count query should group findings by finding_type."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 1",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 2",
            src_ip="185.10.10.2",
            timestamp=datetime(2026, 3, 25, 10, 0, 6),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="ip_banned_after_auth_activity",
            severity="medium",
            message="Correlation finding",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 8),
        ),
    )

    rows = get_finding_counts_by_type(connection)

    assert len(rows) == 2
    assert rows[0]["finding_type"] == "root_login_attempt"
    assert rows[0]["count"] == 2
    assert rows[1]["finding_type"] == "ip_banned_after_auth_activity"
    assert rows[1]["count"] == 1

    connection.close()


def test_get_top_event_source_ips_returns_ranked_ips() -> None:
    """Top event IP query should return IPs ordered by frequency."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw2",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 3),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw3",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 4),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw4",
            src_ip="203.0.113.77",
            service="ssh",
            process="sshd",
        ),
    )

    rows = get_top_event_source_ips(connection)

    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["count"] == 3
    assert rows[1]["src_ip"] == "203.0.113.77"
    assert rows[1]["count"] == 1

    connection.close()


def test_get_top_finding_source_ips_returns_ranked_ips() -> None:
    """Top finding IP query should return IPs ordered by frequency."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 1",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 5),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt 2",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 6),
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="success_after_failures",
            severity="high",
            message="Success after failures",
            src_ip="203.0.113.77",
            timestamp=datetime(2026, 3, 25, 10, 1, 20),
        ),
    )

    rows = get_top_finding_source_ips(connection)

    assert rows[0]["src_ip"] == "185.10.10.1"
    assert rows[0]["count"] == 2
    assert rows[1]["src_ip"] == "203.0.113.77"
    assert rows[1]["count"] == 1

    connection.close()