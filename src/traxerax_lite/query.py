"""SQLite query helpers for summary reporting."""

import sqlite3


def get_event_counts_by_type(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return counts of events grouped by event_type."""
    cursor = connection.execute(
        """
        SELECT event_type, COUNT(*) AS count
        FROM events
        GROUP BY event_type
        ORDER BY count DESC, event_type ASC
        """
    )
    return cursor.fetchall()


def get_finding_counts_by_type(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return counts of findings grouped by finding_type."""
    cursor = connection.execute(
        """
        SELECT finding_type, COUNT(*) AS count
        FROM findings
        GROUP BY finding_type
        ORDER BY count DESC, finding_type ASC
        """
    )
    return cursor.fetchall()


def get_top_event_source_ips(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return most frequently seen source IPs in events."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS count
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC, src_ip ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()


def get_top_finding_source_ips(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return most frequently seen source IPs in findings."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS count
        FROM findings
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC, src_ip ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cursor.fetchall()