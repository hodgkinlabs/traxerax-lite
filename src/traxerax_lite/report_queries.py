"""Report generation from stored SQLite data."""

import sqlite3

from traxerax_lite.query import (
    get_event_counts_by_type,
    get_finding_counts_by_type,
    get_top_event_source_ips,
    get_top_finding_source_ips,
)


def build_summary_report(connection: sqlite3.Connection) -> str:
    """Build a human-readable summary report from stored data."""
    event_counts = get_event_counts_by_type(connection)
    finding_counts = get_finding_counts_by_type(connection)
    top_event_ips = get_top_event_source_ips(connection)
    top_finding_ips = get_top_finding_source_ips(connection)

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

    return "\n".join(lines)