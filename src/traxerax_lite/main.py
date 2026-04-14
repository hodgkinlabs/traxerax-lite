"""CLI entry point for log ingestion and reporting."""

from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Callable

from traxerax_lite.baseline import should_suppress_action, should_suppress_event
from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.config import (
    BaselineSettings,
    load_baseline_settings,
    load_config,
    load_detection_settings,
    load_report_settings,
)
from traxerax_lite.detector import (
    DetectionState,
    process_enforcement_action,
    process_event,
)
from traxerax_lite.hunt import build_hunt_report
from traxerax_lite.incidents import rebuild_incidents
from traxerax_lite.models import EnforcementAction, Event
from traxerax_lite.parser import (
    parse_auth_line,
    parse_fail2ban_line,
    parse_mail_line,
    parse_nginx_access_line,
)
from traxerax_lite.report_queries import build_ip_report, build_summary_report
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_enforcement_action,
    insert_event,
    insert_finding,
)


def main() -> None:
    """Run the application."""
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger = logging.getLogger(__name__)

    config = load_config(args.config)
    detection_settings = load_detection_settings(config)
    report_settings = load_report_settings(config)
    baseline_settings = load_baseline_settings(config)
    nginx_config = config.get("nginx", {})
    nginx_paths = nginx_config.get("suspicious_paths", [])
    nginx_path_patterns = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in nginx_config.get("suspicious_path_patterns", [])
    ]
    local_timezone = datetime.now().astimezone().tzinfo or timezone.utc

    connection = get_connection(args.db_path)
    initialize_database(connection)

    try:
        if args.report:
            rebuild_incidents(connection, detection_settings)
            if args.report == "summary":
                logger.info(build_summary_report(connection, report_settings))
                return

            if args.report == "ip":
                if not args.ip:
                    parser.error("--report ip requires --ip")
                logger.info(build_ip_report(connection, args.ip, report_settings))
                return

            if args.report == "hunt":
                if not args.hunt_preset:
                    parser.error("--report hunt requires --hunt-preset")
                logger.info(
                    build_hunt_report(
                        connection,
                        preset=args.hunt_preset,
                    )
                )
                return

        if not any(
            (args.auth_log, args.fail2ban_log, args.nginx_log, args.mail_log)
        ):
            parser.error(
                "at least one log source must be provided: "
                "--auth-log, --fail2ban-log, --nginx-log, --mail-log, "
                "or use --report"
            )

        state = DetectionState.from_settings(detection_settings)
        parsed_count = 0
        finding_count = 0

        ordered_records = _collect_normalized_events(
            auth_log=args.auth_log,
            fail2ban_log=args.fail2ban_log,
            nginx_log=args.nginx_log,
            mail_log=args.mail_log,
            year=args.year,
            local_timezone=local_timezone,
            nginx_paths=nginx_paths,
            nginx_path_patterns=nginx_path_patterns,
        )
        _seed_detection_state_from_history(
            connection=connection,
            state=state,
            ordered_records=ordered_records,
            baseline_settings=baseline_settings,
        )

        for record in ordered_records:
            if isinstance(record, Event):
                if should_suppress_event(record, baseline_settings):
                    continue
                parsed_count += 1
                insert_event(connection, record)
                findings = process_event(record, state)
            else:
                if should_suppress_action(record, baseline_settings):
                    continue
                parsed_count += 1
                insert_enforcement_action(connection, record)
                findings = process_enforcement_action(record, state)

            for finding in findings:
                finding_count += 1
                insert_finding(connection, finding)

        rebuild_incidents(connection, detection_settings)

        logger.info("\n[SUMMARY]")
        logger.info(f"parsed_events={parsed_count}")
        logger.info(f"generated_findings={finding_count}")
        logger.info(f"database={args.db_path}")
    finally:
        connection.close()


def _collect_normalized_events(
    auth_log: str | None,
    fail2ban_log: str | None,
    nginx_log: str | None,
    mail_log: str | None,
    year: int | None,
    local_timezone: tzinfo,
    nginx_paths: list[str],
    nginx_path_patterns: list[re.Pattern[str]],
) -> list[Event | EnforcementAction]:
    """Collect parsed records from all sources and return them in time order."""
    collected: list[tuple[datetime, int, Event | EnforcementAction]] = []
    sequence = 0

    def collect_from_log(
        path: str | None,
        parser: Callable[[str], Event | EnforcementAction | None],
    ) -> None:
        nonlocal sequence
        if not path:
            return

        for line in read_lines(path):
            record = parser(line)
            if record is None:
                continue

            collected.append((record.timestamp, sequence, record))
            sequence += 1

    collect_from_log(
        auth_log,
        lambda line: parse_auth_line(
            line,
            year=year,
            local_timezone=local_timezone,
        ),
    )
    collect_from_log(
        fail2ban_log,
        lambda line: parse_fail2ban_line(
            line,
            local_timezone=local_timezone,
        ),
    )
    collect_from_log(
        nginx_log,
        lambda line: parse_nginx_access_line(
            line,
            nginx_paths,
            nginx_path_patterns,
        ),
    )
    collect_from_log(
        mail_log,
        lambda line: parse_mail_line(
            line,
            year=year,
            local_timezone=local_timezone,
        ),
    )

    collected.sort(key=lambda item: (item[0], item[1]))
    return [record for _, _, record in collected]


def _seed_detection_state_from_history(
    connection: sqlite3.Connection,
    state: DetectionState,
    ordered_records: list[Event | EnforcementAction],
    baseline_settings: BaselineSettings,
) -> None:
    """Warm the in-memory detector with recent persisted telemetry."""
    if not ordered_records:
        return

    earliest = ordered_records[0].timestamp
    max_window_seconds = max(
        state.auth_failure_window_seconds,
        state.mail_failure_window_seconds,
        state.mail_unique_username_window_seconds,
        state.http_error_window_seconds,
        state.success_after_failures_window_seconds,
        state.web_auth_correlation_window_seconds,
        state.web_ban_correlation_window_seconds,
        state.multi_source_window_seconds,
    )
    cutoff_time = earliest - timedelta(seconds=max_window_seconds)

    # Replaying only the recent persistence window keeps cross-source
    # correlations accurate without rebuilding detector state from all history.
    historical_events = connection.execute(
        """
        SELECT *
        FROM events
        WHERE timestamp >= ?
        ORDER BY timestamp ASC, id ASC
        """,
        (cutoff_time.isoformat(sep=" "),),
    ).fetchall()
    for row in historical_events:
        event = Event(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"],
            event_type=row["event_type"],
            raw=row["raw"],
            username=row["username"],
            src_ip=row["src_ip"],
            port=row["port"],
            service=row["service"],
            hostname=row["hostname"],
            process=row["process"],
            action=row["action"],
            jail=row["jail"],
            method=row["method"],
            path=row["path"],
            normalized_path=row["normalized_path"],
            query_string=row["query_string"],
            referrer=row["referrer"],
            user_agent=row["user_agent"],
            match_reason=row["match_reason"],
            bytes_sent=row["bytes_sent"],
            status_code=row["status_code"],
        )
        if not should_suppress_event(event, baseline_settings):
            process_event(event, state)

    historical_actions = connection.execute(
        """
        SELECT *
        FROM enforcement_actions
        WHERE timestamp >= ?
        ORDER BY timestamp ASC, id ASC
        """,
        (cutoff_time.isoformat(sep=" "),),
    ).fetchall()
    for row in historical_actions:
        action = EnforcementAction(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            raw=row["raw"],
            src_ip=row["src_ip"],
            action=row["action"],
            service=row["service"],
            process=row["process"],
            jail=row["jail"],
        )
        if not should_suppress_action(action, baseline_settings):
            process_enforcement_action(action, state)


if __name__ == "__main__":
    main()
