"""Main entry point."""

from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.detector import DetectionState, process_event
from traxerax_lite.parser import (
    parse_auth_line,
    parse_fail2ban_line,
    parse_nginx_access_line,
)
from traxerax_lite.report_queries import build_ip_report, build_summary_report
from traxerax_lite.reporter import format_event, format_finding
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
)


def main() -> None:
    """Run the application."""
    parser = build_parser()
    args = parser.parse_args()

    connection = get_connection(args.db_path)
    initialize_database(connection)

    try:
        if args.report:
            if args.report == "summary":
                print(build_summary_report(connection))
                return

            if args.report == "ip":
                if not args.ip:
                    parser.error("--report ip requires --ip")
                print(build_ip_report(connection, args.ip))
                return

        if not args.auth_log and not args.fail2ban_log and not args.nginx_log:
            parser.error(
                "at least one log source must be provided: "
                "--auth-log, --fail2ban-log, --nginx-log, or use --report"
            )

        state = DetectionState()
        parsed_count = 0
        finding_count = 0

        if args.auth_log:
            for line in read_lines(args.auth_log):
                event = parse_auth_line(line, year=args.year)
                if event is None:
                    continue

                parsed_count += 1
                print(format_event(event))
                insert_event(connection, event)

                findings = process_event(event, state)
                for finding in findings:
                    finding_count += 1
                    print(format_finding(finding))
                    insert_finding(connection, finding)

        if args.fail2ban_log:
            for line in read_lines(args.fail2ban_log):
                event = parse_fail2ban_line(line)
                if event is None:
                    continue

                parsed_count += 1
                print(format_event(event))
                insert_event(connection, event)

                findings = process_event(event, state)
                for finding in findings:
                    finding_count += 1
                    print(format_finding(finding))
                    insert_finding(connection, finding)

        if args.nginx_log:
            for line in read_lines(args.nginx_log):
                event = parse_nginx_access_line(line)
                if event is None:
                    continue

                parsed_count += 1
                print(format_event(event))
                insert_event(connection, event)

                findings = process_event(event, state)
                for finding in findings:
                    finding_count += 1
                    print(format_finding(finding))
                    insert_finding(connection, finding)

        print("\n[SUMMARY]")
        print(f"parsed_events={parsed_count}")
        print(f"generated_findings={finding_count}")
        print(f"database={args.db_path}")
    finally:
        connection.close()


if __name__ == "__main__":
    main()