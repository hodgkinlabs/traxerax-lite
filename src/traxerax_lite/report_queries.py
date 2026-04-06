"""Report generation from stored SQLite data."""

import sqlite3
from datetime import datetime

from traxerax_lite.query import (
    get_enforcement_actions_for_ip,
    get_event_counts_by_source_for_ip,
    get_event_counts_by_type,
    get_event_counts_by_type_for_ip,
    get_events_for_ip,
    get_finding_counts_by_type,
    get_finding_counts_by_type_for_ip,
    get_findings_for_ip,
    get_ip_enforcement_summary,
    get_ip_overview,
    get_nginx_error_status_counts_for_ip,
    get_ip_persistence_stats,
    get_ip_post_ban_activity_count,
    get_ip_post_ban_return_count,
    get_ip_total_findings,
    get_ips_seen_in_auth_and_fail2ban,
    get_ips_with_root_attempt_and_ban,
    get_persistent_multi_source_ips,
    get_repeat_banned_ips,
    get_returned_after_ban_ips,
    get_root_attempt_ips_with_repeat_activity,
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
    auth_enforced_ips = get_ips_seen_in_auth_and_fail2ban(connection)
    root_then_ban_ips = get_ips_with_root_attempt_and_ban(connection)
    top_ips_by_finding_count = get_top_ips_by_finding_count(connection)

    repeat_banned_ips = get_repeat_banned_ips(connection)
    returned_after_ban_ips = get_returned_after_ban_ips(connection)
    persistent_multi_source_ips = get_persistent_multi_source_ips(connection)
    root_attempt_repeat_ips = get_root_attempt_ips_with_repeat_activity(connection)

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
    lines.append("auth_ips_with_enforcement:")
    if auth_enforced_ips:
        for row in auth_enforced_ips:
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

    lines.append("")
    lines.append("repeat_banned_ips:")
    if repeat_banned_ips:
        for row in repeat_banned_ips:
            lines.append(f"  - {row['src_ip']}: {row['ban_count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("returned_after_ban_ips:")
    if returned_after_ban_ips:
        for row in returned_after_ban_ips:
            lines.append(
                f"  - {row['src_ip']}: "
                f"returns={row['return_count']} "
                f"events={row['post_ban_events']}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("persistent_multi_source_ips:")
    if persistent_multi_source_ips:
        for row in persistent_multi_source_ips:
            lines.append(
                f"  - {row['src_ip']}: "
                f"events={row['total_events']} "
                f"sources={row['source_count']}"
            )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("root_attempt_ips_with_repeat_activity:")
    if root_attempt_repeat_ips:
        for row in root_attempt_repeat_ips:
            lines.append(
                f"  - {row['src_ip']}: "
                f"auth_events={row['auth_event_count']} "
                f"root_attempts={row['root_attempt_count']}"
            )
    else:
        lines.append("  - none")

    return "\n".join(lines)


def build_ip_report(
    connection: sqlite3.Connection,
    src_ip: str,
) -> str:
    """Build a timeline-style report for a single IP address."""
    overview = get_ip_overview(connection, src_ip)
    total_findings = get_ip_total_findings(connection, src_ip)
    source_counts = get_event_counts_by_source_for_ip(connection, src_ip)
    event_type_counts = get_event_counts_by_type_for_ip(connection, src_ip)
    finding_type_counts = get_finding_counts_by_type_for_ip(connection, src_ip)
    enforcement_summary = get_ip_enforcement_summary(connection, src_ip)
    nginx_error_status_counts = get_nginx_error_status_counts_for_ip(
        connection,
        src_ip,
    )
    persistence_stats = get_ip_persistence_stats(connection, src_ip)
    post_ban_activity_count = get_ip_post_ban_activity_count(connection, src_ip)
    post_ban_return_count = get_ip_post_ban_return_count(connection, src_ip)

    events = get_events_for_ip(connection, src_ip)
    enforcement_actions = get_enforcement_actions_for_ip(connection, src_ip)
    findings = get_findings_for_ip(connection, src_ip)

    lines: list[str] = []
    lines.append(f"[REPORT] ip={src_ip}")
    lines.append("")

    lines.append("overview:")
    if overview is not None:
        lines.append(f"  - first_seen: {overview['first_seen']}")
        lines.append(f"  - last_seen: {overview['last_seen']}")
        lines.append(f"  - total_events: {overview['total_events']}")
        lines.append(f"  - total_findings: {total_findings}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("enforcement:")
    if enforcement_summary is not None:
        ever_banned = (enforcement_summary["ban_count"] or 0) >= 1
        timely_ban = _format_ban_delay(
            first_observed_time=enforcement_summary["first_observed_time"],
            first_ban_time=enforcement_summary["first_ban_time"],
        )
        lines.append(f"  - ever_banned: {'yes' if ever_banned else 'no'}")
        lines.append(f"  - ban_count: {enforcement_summary['ban_count'] or 0}")
        lines.append(
            f"  - unban_count: {enforcement_summary['unban_count'] or 0}"
        )
        lines.append(
            f"  - first_ban_time: "
            f"{enforcement_summary['first_ban_time'] or 'none'}"
        )
        lines.append(
            f"  - last_ban_time: "
            f"{enforcement_summary['last_ban_time'] or 'none'}"
        )
        lines.append(
            f"  - last_unban_time: "
            f"{enforcement_summary['last_unban_time'] or 'none'}"
        )
        lines.append(f"  - first_ban_delay: {timely_ban}")
        lines.append(
            f"  - controls_seen: "
            f"{enforcement_summary['controls_seen'] or 'none'}"
        )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("persistence_flags:")
    if persistence_stats is not None:
        repeat_banned = persistence_stats["ban_count"] >= 2
        returned_after_ban = post_ban_return_count >= 1
        persistent_multi_source = (
            persistence_stats["source_count"] >= 2
            and persistence_stats["total_events"] >= 4
        )
        root_attempt_from_repeat_ip = (
            persistence_stats["root_attempt_count"] >= 1
            and persistence_stats["auth_event_count"] >= 3
        )

        lines.append(f"  - source_count: {persistence_stats['source_count']}")
        lines.append(f"  - ban_count: {persistence_stats['ban_count']}")
        lines.append(
            f"  - root_attempt_count: "
            f"{persistence_stats['root_attempt_count']}"
        )
        lines.append(
            f"  - auth_event_count: {persistence_stats['auth_event_count']}"
        )
        lines.append(
            f"  - post_ban_activity_events: {post_ban_activity_count}"
        )
        lines.append(
            f"  - post_ban_return_count: {post_ban_return_count}"
        )
        lines.append(f"  - repeat_banned: {'yes' if repeat_banned else 'no'}")
        lines.append(
            f"  - returned_after_ban: "
            f"{'yes' if returned_after_ban else 'no'}"
        )
        lines.append(
            f"  - persistent_multi_source: "
            f"{'yes' if persistent_multi_source else 'no'}"
        )
        lines.append(
            f"  - root_attempt_from_repeat_ip: "
            f"{'yes' if root_attempt_from_repeat_ip else 'no'}"
        )
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("event_counts_by_source:")
    if source_counts:
        for row in source_counts:
            lines.append(f"  - {row['source']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("event_counts_by_type:")
    if event_type_counts:
        for row in event_type_counts:
            lines.append(f"  - {row['event_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("finding_counts_by_type:")
    if finding_type_counts:
        for row in finding_type_counts:
            lines.append(f"  - {row['finding_type']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("nginx_error_status_counts:")
    if nginx_error_status_counts:
        for row in nginx_error_status_counts:
            lines.append(f"  - {row['status_code']}: {row['count']}")
    else:
        lines.append("  - none")

    lines.append("")
    lines.append("enforcement_timeline:")
    if enforcement_actions:
        for row in enforcement_actions:
            details: list[str] = []
            details.append(f"action={row['action']}")
            if row["service"] is not None:
                details.append(f"service={row['service']}")
            if row["process"] is not None:
                details.append(f"process={row['process']}")
            if row["jail"] is not None:
                details.append(f"jail={row['jail']}")
            lines.append(f"  - {row['timestamp']} | " + " ".join(details))
    else:
        lines.append("  - none")

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

            lines.append(f"  - {row['timestamp']} | " + " ".join(details))
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


def _format_ban_delay(
    first_observed_time: str | None,
    first_ban_time: str | None,
) -> str:
    """Format time from first observed activity to first ban."""
    if first_observed_time is None or first_ban_time is None:
        return "none"

    observed = datetime.fromisoformat(first_observed_time)
    banned = datetime.fromisoformat(first_ban_time)
    delta = int((banned - observed).total_seconds())

    if delta < 0:
        return "before_observed_activity"
    return f"{delta}s"
