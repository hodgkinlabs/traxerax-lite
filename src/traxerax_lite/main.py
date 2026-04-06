"""Main entry point."""

import logging
from datetime import datetime, timezone, tzinfo
from typing import Callable

from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.config import load_config
from traxerax_lite.detector import (
    DetectionState,
    process_enforcement_action,
    process_event,
)
from traxerax_lite.models import EnforcementAction, Event
from traxerax_lite.parser import (
    parse_auth_line,
    parse_fail2ban_line,
    parse_mail_line,
    parse_nginx_access_line,
)
from traxerax_lite.report_queries import build_ip_report, build_summary_report
from traxerax_lite.reporter import (
    format_enforcement_action,
    format_event,
    format_finding,
    json_format_enforcement_action,
    json_format_event,
    json_format_finding,
)
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

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)

    config = load_config(args.config)
    nginx_config = config.get("nginx", {})
    nginx_paths = nginx_config.get("suspicious_paths", [])
    http_error_statuses = set(
        nginx_config.get(
            "error_status_codes",
            [400, 401, 403, 404, 408, 429, 444, 500, 502, 503, 504],
        )
    )
    http_error_threshold = int(
        nginx_config.get("repeated_error_threshold", 3)
    )
    local_timezone = datetime.now().astimezone().tzinfo or timezone.utc

    event_formatter = json_format_event if args.json else format_event
    finding_formatter = json_format_finding if args.json else format_finding
    enforcement_formatter = (
        json_format_enforcement_action
        if args.json
        else format_enforcement_action
    )

    connection = get_connection(args.db_path)
    initialize_database(connection)

    try:
        if args.report:
            if args.report == "summary":
                logger.info(build_summary_report(connection))
                return

            if args.report == "ip":
                if not args.ip:
                    parser.error("--report ip requires --ip")
                logger.info(build_ip_report(connection, args.ip))
                return

        if (
            not args.auth_log
            and not args.fail2ban_log
            and not args.nginx_log
            and not args.mail_log
        ):
            parser.error(
                "at least one log source must be provided: "
                "--auth-log, --fail2ban-log, --nginx-log, --mail-log, "
                "or use --report"
            )

        state = DetectionState(
            http_error_statuses=http_error_statuses,
            http_error_threshold=http_error_threshold,
        )
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
        )

        for record in ordered_records:
            parsed_count += 1
            if isinstance(record, Event):
                logger.info(event_formatter(record))
                insert_event(connection, record)
                findings = process_event(record, state)
            else:
                logger.info(enforcement_formatter(record))
                insert_enforcement_action(connection, record)
                findings = process_enforcement_action(record, state)

            for finding in findings:
                finding_count += 1
                logger.info(finding_formatter(finding))
                insert_finding(connection, finding)

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
        lambda line: parse_nginx_access_line(line, nginx_paths),
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


if __name__ == "__main__":
    main()
