"""SQLite query helpers for summary and investigation reporting."""

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


def get_ips_seen_in_auth_and_fail2ban(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return IPs present in both auth and fail2ban event sources."""
    cursor = connection.execute(
        """
        SELECT e.src_ip
        FROM events AS e
        WHERE e.src_ip IS NOT NULL
        GROUP BY e.src_ip
        HAVING
            SUM(CASE WHEN e.source = 'auth' THEN 1 ELSE 0 END) > 0
            AND
            SUM(CASE WHEN e.source = 'fail2ban' THEN 1 ELSE 0 END) > 0
        ORDER BY e.src_ip ASC
        """
    )
    return cursor.fetchall()


def get_ips_with_root_attempt_and_ban(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return IPs that attempted root login and were later banned."""
    cursor = connection.execute(
        """
        SELECT DISTINCT root_events.src_ip
        FROM events AS root_events
        JOIN events AS ban_events
            ON root_events.src_ip = ban_events.src_ip
        WHERE root_events.event_type = 'ssh_root_login_attempt'
          AND ban_events.event_type = 'fail2ban_ban'
          AND root_events.src_ip IS NOT NULL
        ORDER BY root_events.src_ip ASC
        """
    )
    return cursor.fetchall()


def get_top_ips_by_finding_count(
    connection: sqlite3.Connection,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Return IPs ranked by total finding count."""
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


def get_repeat_banned_ips(
    connection: sqlite3.Connection,
    min_bans: int = 2,
) -> list[sqlite3.Row]:
    """Return IPs that have been banned multiple times."""
    cursor = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS ban_count
        FROM events
        WHERE event_type = 'fail2ban_ban'
          AND src_ip IS NOT NULL
        GROUP BY src_ip
        HAVING COUNT(*) >= ?
        ORDER BY ban_count DESC, src_ip ASC
        """,
        (min_bans,),
    )
    return cursor.fetchall()


def get_returned_after_ban_ips(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Return IPs that showed auth/nginx activity after a prior ban."""
    cursor = connection.execute(
        """
        WITH first_ban AS (
            SELECT src_ip, MIN(timestamp) AS first_ban_time
            FROM events
            WHERE event_type = 'fail2ban_ban'
              AND src_ip IS NOT NULL
            GROUP BY src_ip
        )
        SELECT e.src_ip, COUNT(*) AS post_ban_events
        FROM events AS e
        JOIN first_ban AS b
            ON e.src_ip = b.src_ip
        WHERE e.timestamp > b.first_ban_time
          AND e.source IN ('auth', 'nginx')
        GROUP BY e.src_ip
        ORDER BY post_ban_events DESC, e.src_ip ASC
        """
    )
    return cursor.fetchall()


def get_persistent_multi_source_ips(
    connection: sqlite3.Connection,
    min_total_events: int = 4,
) -> list[sqlite3.Row]:
    """Return IPs with sustained activity across multiple sources."""
    cursor = connection.execute(
        """
        SELECT
            src_ip,
            COUNT(DISTINCT source) AS source_count,
            COUNT(*) AS total_events
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        HAVING COUNT(DISTINCT source) >= 2
           AND COUNT(*) >= ?
        ORDER BY total_events DESC, src_ip ASC
        """,
        (min_total_events,),
    )
    return cursor.fetchall()


def get_root_attempt_ips_with_repeat_activity(
    connection: sqlite3.Connection,
    min_auth_events: int = 3,
) -> list[sqlite3.Row]:
    """Return IPs with root attempts and repeated auth activity."""
    cursor = connection.execute(
        """
        SELECT
            src_ip,
            COUNT(*) AS auth_event_count,
            SUM(
                CASE WHEN event_type = 'ssh_root_login_attempt'
                     THEN 1 ELSE 0 END
            ) AS root_attempt_count
        FROM events
        WHERE src_ip IS NOT NULL
          AND source = 'auth'
        GROUP BY src_ip
        HAVING root_attempt_count > 0
           AND auth_event_count >= ?
        ORDER BY auth_event_count DESC, src_ip ASC
        """,
        (min_auth_events,),
    )
    return cursor.fetchall()


def get_events_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return ordered events for a given source IP."""
    cursor = connection.execute(
        """
        SELECT
            timestamp,
            source,
            event_type,
            username,
            port,
            service,
            hostname,
            process,
            action,
            jail,
            method,
            path,
            status_code,
            raw
        FROM events
        WHERE src_ip = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_findings_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return ordered findings for a given source IP."""
    cursor = connection.execute(
        """
        SELECT
            timestamp,
            finding_type,
            severity,
            message
        FROM findings
        WHERE src_ip = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_ip_overview(
    connection: sqlite3.Connection,
    src_ip: str,
) -> sqlite3.Row | None:
    """Return first seen, last seen, and total event count for an IP."""
    cursor = connection.execute(
        """
        SELECT
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen,
            COUNT(*) AS total_events
        FROM events
        WHERE src_ip = ?
        """,
        (src_ip,),
    )
    row = cursor.fetchone()
    if row is None or row["total_events"] == 0:
        return None
    return row


def get_ip_total_findings(
    connection: sqlite3.Connection,
    src_ip: str,
) -> int:
    """Return total finding count for an IP."""
    cursor = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        WHERE src_ip = ?
        """,
        (src_ip,),
    )
    row = cursor.fetchone()
    return 0 if row is None else row["count"]


def get_event_counts_by_source_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return event counts grouped by source for an IP."""
    cursor = connection.execute(
        """
        SELECT source, COUNT(*) AS count
        FROM events
        WHERE src_ip = ?
        GROUP BY source
        ORDER BY count DESC, source ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_event_counts_by_type_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return event counts grouped by event_type for an IP."""
    cursor = connection.execute(
        """
        SELECT event_type, COUNT(*) AS count
        FROM events
        WHERE src_ip = ?
        GROUP BY event_type
        ORDER BY count DESC, event_type ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_finding_counts_by_type_for_ip(
    connection: sqlite3.Connection,
    src_ip: str,
) -> list[sqlite3.Row]:
    """Return finding counts grouped by finding_type for an IP."""
    cursor = connection.execute(
        """
        SELECT finding_type, COUNT(*) AS count
        FROM findings
        WHERE src_ip = ?
        GROUP BY finding_type
        ORDER BY count DESC, finding_type ASC
        """,
        (src_ip,),
    )
    return cursor.fetchall()


def get_ip_persistence_stats(
    connection: sqlite3.Connection,
    src_ip: str,
) -> sqlite3.Row | None:
    """Return persistence-oriented aggregate stats for an IP."""
    cursor = connection.execute(
        """
        SELECT
            COUNT(*) AS total_events,
            COUNT(DISTINCT source) AS source_count,
            SUM(
                CASE WHEN event_type = 'fail2ban_ban'
                     THEN 1 ELSE 0 END
            ) AS ban_count,
            SUM(
                CASE WHEN event_type = 'ssh_root_login_attempt'
                     THEN 1 ELSE 0 END
            ) AS root_attempt_count,
            SUM(
                CASE WHEN source = 'auth'
                     THEN 1 ELSE 0 END
            ) AS auth_event_count
        FROM events
        WHERE src_ip = ?
        """,
        (src_ip,),
    )
    row = cursor.fetchone()
    if row is None or row["total_events"] == 0:
        return None
    return row


def get_ip_post_ban_activity_count(
    connection: sqlite3.Connection,
    src_ip: str,
) -> int:
    """Return count of auth/nginx events after the first ban for an IP."""
    cursor = connection.execute(
        """
        WITH first_ban AS (
            SELECT MIN(timestamp) AS first_ban_time
            FROM events
            WHERE src_ip = ?
              AND event_type = 'fail2ban_ban'
        )
        SELECT COUNT(*) AS count
        FROM events
        WHERE src_ip = ?
          AND source IN ('auth', 'nginx')
          AND timestamp > (SELECT first_ban_time FROM first_ban)
        """,
        (src_ip, src_ip),
    )
    row = cursor.fetchone()
    return 0 if row is None else row["count"]