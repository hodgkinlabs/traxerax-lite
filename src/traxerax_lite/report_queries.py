"""Report generation from stored SQLite data."""

import sqlite3

from traxerax_lite.query import (
    get_event_counts_by_type,
    get_finding_counts_by_type,
    get_events_for_ip,
    get_findings_for_ip,
    get_ips_seen_in_auth_and_fail2ban,
    get_ips_with_root_attempt_and_ban,
    get_top_event_source_ips,
    get_top_finding_source_ips,
    get_top_ips_by_finding_count,
)


def build_summary_report(connection: sqlite3.Connection) -> str:
    """Build a human-readable summary report from stored data."""
    event_counts = get_event_counts_by_type(connection)
    finding_counts = get_finding_counts_by_type(connection)
    top_event_ips = get_top_event_source_ips(connection)
    top_finding_ips = get_top_finding_source_ips(connection)
    cross_source_ips = get_ips_seen_in_auth_and_fail2ban(connection)
    root_then_ban_ips = get_ips_with_root_attempt_and_ban(connection)
    top_ips_by_finding_count = get_top_ips_by_finding_count(connection)

    lines: list[str] = []
    lines.append("[REPORT] summary")
    lines.append("")

    lines.append("event_counts_by_type:")
    if event_counts:
        for row in event_counts:
            lines.append(f"  - {row['event_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("finding_counts_by_type:")
    if finding_counts:
        for row in finding_counts:
            lines.append(f"  - {row['finding_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("top_event_source_ips:")
    if top_event_ips:
        for row in top_event_ips:
            lines.append(f"  - {row['src_ip']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("top_finding_source_ips:")
    if top_finding_ips:
        for row in top_finding_ips:
            lines.append(f"  - {row['src_ip']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("cross_source_ips:")
    if cross_source_ips:
        for row in cross_source_ips:
            lines.append(f"  - {row['src_ip']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("root_attempts_followed_by_ban:")
    if root_then_ban_ips:
        for row in root_then_ban_ips:
            lines.append(f"  - {row['src_ip']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("top_ips_by_finding_count:")
    if top_ips_by_finding_count:
        for row in top_ips_by_finding_count:
            lines.append(f"  - {row['src_ip']}: {row['count']}")
    else:
        lines.append("  - none")

    return "\n".join(lines)


def build_ip_report(
    connection: sqlite3.Connection,
    src_ip: str,
) -> str:
    """Build a timeline-style report for a single IP address."""
    events = get_events_for_ip(connection, src_ip)
    findings = get_findings_for_ip(connection, src_ip)

    lines: list[str] = []
    lines.append(f"[REPORT] ip={src_ip}")
    lines.append("")

    lines.append("timeline:")
    if events:
        for row in events:
            details: list[str] = []
            details.append(f"source={row['source']}")
            details.append(f"type={row['event_type']}")

            if row["username"] is not None:
                details.append(f"user={row['username']}")
            if row["port"] is not None:
                details.append(f"port={row['port']}")
            if row["service"] is not None:
                details.append(f"service={row['service']}")
            if row["hostname"] is not None:
                details.append(f"host={row['hostname']}")
            if row["process"] is not None:
                details.append(f"process={row['process']}")
            if row["action"] is not None:
                details.append(f"action={row['action']}")
            if row["jail"] is not None:
                details.append(f"jail={row['jail']}")
            if row["method"] is not None:
                details.append(f"method={row['method']}")
            if row["path"] is not None:
                details.append(f"path={row['path']}")
            if row["status_code"] is not None:
                details.append(f"status={row['status_code']}")

            lines.append(
                f"  - {row['timestamp']} | " + " ".join(details)
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("findings:")
    if findings:
        for row in findings:
            lines.append(
                f"  - {row['timestamp']} | "
                f"{row['severity'].upper()} "
                f"{row['finding_type']} "
                f"| {row['message']}"
            )
    else:
        lines.append("  - none")

    return "\n".join(lines)