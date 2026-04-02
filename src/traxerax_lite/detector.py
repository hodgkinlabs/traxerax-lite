"""Detection logic for Traxerax Lite."""

from collections import defaultdict
from dataclasses import dataclass, field

from traxerax_lite.models import Event, Finding


@dataclass
class DetectionState:
    """In-memory state for detections and simple correlations."""

    failed_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    threshold_alerted: set[str] = field(default_factory=set)
    auth_activity_ips: set[str] = field(default_factory=set)
    fail2ban_banned_ips: set[str] = field(default_factory=set)

    suspicious_web_alerted: set[str] = field(default_factory=set)
    web_probe_ips: set[str] = field(default_factory=set)

    web_to_auth_alerted: set[str] = field(default_factory=set)
    web_to_ban_alerted: set[str] = field(default_factory=set)
    multi_source_alerted: set[str] = field(default_factory=set)


def process_event(event: Event, state: DetectionState) -> list[Finding]:
    """Process one event and return any generated findings."""
    findings: list[Finding] = []

    if event.src_ip is None:
        return findings

    if event.source == "auth":
        findings.extend(_process_auth_event(event, state))

    if event.source == "fail2ban":
        findings.extend(_process_fail2ban_event(event, state))

    if event.source == "nginx":
        findings.extend(_process_nginx_event(event, state))

    findings.extend(_check_cross_source_correlations(event, state))
    return findings


def _process_auth_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized auth event."""
    findings: list[Finding] = []

    state.auth_activity_ips.add(event.src_ip)

    if event.event_type == "ssh_root_login_attempt":
        findings.append(
            Finding(
                finding_type="root_login_attempt",
                severity="medium",
                message=(
                    f"Root login attempt detected from {event.src_ip}"
                ),
                src_ip=event.src_ip,
                timestamp=event.timestamp,
            )
        )

    if event.event_type in {"ssh_failed_login", "ssh_root_login_attempt"}:
        state.failed_counts[event.src_ip] += 1

        if (
            state.failed_counts[event.src_ip] >= 3
            and event.src_ip not in state.threshold_alerted
        ):
            state.threshold_alerted.add(event.src_ip)
            findings.append(
                Finding(
                    finding_type="repeated_failed_login",
                    severity="medium",
                    message=(
                        "Repeated failed SSH logins detected from "
                        f"{event.src_ip} "
                        f"({state.failed_counts[event.src_ip]} failures)"
                    ),
                    src_ip=event.src_ip,
                    timestamp=event.timestamp,
                )
            )

    if event.event_type == "ssh_success_login":
        prior_failures = state.failed_counts[event.src_ip]
        if prior_failures >= 1:
            findings.append(
                Finding(
                    finding_type="success_after_failures",
                    severity="high",
                    message=(
                        "Successful SSH login after prior failures from "
                        f"{event.src_ip} "
                        f"({prior_failures} failures before success)"
                    ),
                    src_ip=event.src_ip,
                    timestamp=event.timestamp,
                )
            )

    return findings


def _process_fail2ban_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized fail2ban event."""
    findings: list[Finding] = []

    if event.event_type == "fail2ban_ban":
        state.fail2ban_banned_ips.add(event.src_ip)

        if event.src_ip in state.auth_activity_ips:
            findings.append(
                Finding(
                    finding_type="ip_banned_after_auth_activity",
                    severity="medium",
                    message=(
                        "IP seen in auth activity was later banned by "
                        f"fail2ban: {event.src_ip}"
                    ),
                    src_ip=event.src_ip,
                    timestamp=event.timestamp,
                )
            )

    return findings


def _process_nginx_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized nginx event."""
    findings: list[Finding] = []

    if event.event_type == "nginx_suspicious_request":
        state.web_probe_ips.add(event.src_ip)

        if event.src_ip not in state.suspicious_web_alerted:
            state.suspicious_web_alerted.add(event.src_ip)
            findings.append(
                Finding(
                    finding_type="suspicious_web_probe",
                    severity="medium",
                    message=(
                        "Suspicious web probe detected from "
                        f"{event.src_ip} path={event.path}"
                    ),
                    src_ip=event.src_ip,
                    timestamp=event.timestamp,
                )
            )

    return findings


def _check_cross_source_correlations(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Generate higher-level findings from multi-source activity."""
    findings: list[Finding] = []
    ip = event.src_ip

    if ip in state.web_probe_ips and ip in state.auth_activity_ips:
        if ip not in state.web_to_auth_alerted:
            state.web_to_auth_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="web_probe_followed_by_auth_activity",
                    severity="medium",
                    message=(
                        "IP performed suspicious web probing and also "
                        f"showed auth activity: {ip}"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    if ip in state.web_probe_ips and ip in state.fail2ban_banned_ips:
        if ip not in state.web_to_ban_alerted:
            state.web_to_ban_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="web_probe_followed_by_fail2ban_ban",
                    severity="medium",
                    message=(
                        "IP performed suspicious web probing and was later "
                        f"banned by fail2ban: {ip}"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    if (
        ip in state.web_probe_ips
        and ip in state.auth_activity_ips
        and ip in state.fail2ban_banned_ips
    ):
        if ip not in state.multi_source_alerted:
            state.multi_source_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="multi_source_ip_activity",
                    severity="high",
                    message=(
                        "IP appeared across nginx, auth, and fail2ban: "
                        f"{ip}"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    return findings