"""Detection logic for Traxerax Lite."""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from traxerax_lite.models import EnforcementAction, Event, Finding


@dataclass
class DetectionState:
    """In-memory state for detections and simple correlations."""

    http_error_statuses: set[int] = field(default_factory=set)
    http_error_threshold: int = 3

    failed_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    threshold_alerted: set[str] = field(default_factory=set)

    auth_activity_ips: set[str] = field(default_factory=set)
    banned_ips: set[str] = field(default_factory=set)
    web_activity_ips: set[str] = field(default_factory=set)
    web_probe_ips: set[str] = field(default_factory=set)
    mail_activity_ips: set[str] = field(default_factory=set)
    first_auth_activity_time: dict[str, datetime] = field(default_factory=dict)
    first_fail2ban_ban_time: dict[str, datetime] = field(default_factory=dict)
    first_web_probe_time: dict[str, datetime] = field(default_factory=dict)
    http_error_counts: dict[tuple[str, int], int] = field(
        default_factory=lambda: defaultdict(int)
    )

    mail_failed_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    mail_threshold_alerted: set[str] = field(default_factory=set)

    auth_enforcement_alerted: set[str] = field(default_factory=set)
    web_enforcement_alerted: set[str] = field(default_factory=set)
    suspicious_web_alerted: set[str] = field(default_factory=set)
    repeated_http_error_alerted: set[tuple[str, int]] = field(
        default_factory=set
    )
    mail_fail2ban_alerted: set[str] = field(default_factory=set)

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

    if event.source == "nginx":
        findings.extend(_process_nginx_event(event, state))

    if event.source == "mail":
        findings.extend(_process_mail_event(event, state))

    findings.extend(_check_cross_source_correlations(event, state))
    return findings


def process_enforcement_action(
    action: EnforcementAction,
    state: DetectionState,
) -> list[Finding]:
    """Process one enforcement action and return any generated findings."""
    findings: list[Finding] = []

    if action.src_ip is None:
        return findings

    findings.extend(_process_fail2ban_action(action, state))
    findings.extend(_check_enforcement_correlations(action, state))
    return findings


def _process_auth_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized auth event."""
    findings: list[Finding] = []
    ip = event.src_ip

    state.auth_activity_ips.add(ip)
    state.first_auth_activity_time.setdefault(ip, event.timestamp)

    if event.event_type == "ssh_root_login_attempt":
        findings.append(
            Finding(
                finding_type="root_login_attempt",
                severity="medium",
                message=f"Root login attempt detected from {ip}",
                src_ip=ip,
                timestamp=event.timestamp,
            )
        )

    if event.event_type in {"ssh_failed_login", "ssh_root_login_attempt"}:
        state.failed_counts[ip] += 1

        if (
            state.failed_counts[ip] >= 3
            and ip not in state.threshold_alerted
        ):
            state.threshold_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="repeated_failed_login",
                    severity="medium",
                    message=(
                        "Repeated failed SSH logins detected from "
                        f"{ip} ({state.failed_counts[ip]} failures)"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    if event.event_type == "ssh_success_login":
        prior_failures = state.failed_counts[ip]
        if prior_failures >= 1:
            findings.append(
                Finding(
                    finding_type="success_after_failures",
                    severity="high",
                    message=(
                        "Successful SSH login after prior failures from "
                        f"{ip} ({prior_failures} failures before success)"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    return findings


def _process_fail2ban_action(
    action: EnforcementAction,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized enforcement action."""
    findings: list[Finding] = []
    ip = action.src_ip

    if action.action == "ban":
        state.banned_ips.add(ip)
        state.first_fail2ban_ban_time.setdefault(ip, action.timestamp)

        if ip in state.auth_activity_ips and ip not in state.auth_enforcement_alerted:
            state.auth_enforcement_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="ip_banned_after_auth_activity",
                    severity="medium",
                    message=(
                        "IP seen in auth activity was later banned by "
                        f"fail2ban: {ip}"
                    ),
                    src_ip=ip,
                    timestamp=action.timestamp,
                )
            )

        if ip in state.web_activity_ips and ip not in state.web_enforcement_alerted:
            state.web_enforcement_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="ip_banned_after_web_activity",
                    severity="medium",
                    message=(
                        "IP seen in web activity was later banned by "
                        f"fail2ban: {ip}"
                    ),
                    src_ip=ip,
                    timestamp=action.timestamp,
                )
            )

        if ip in state.mail_activity_ips and ip not in state.mail_fail2ban_alerted:
            state.mail_fail2ban_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="ip_banned_after_mail_activity",
                    severity="medium",
                    message=(
                        "IP seen in mail auth activity was later banned by "
                        f"fail2ban: {ip}"
                    ),
                    src_ip=ip,
                    timestamp=action.timestamp,
                )
            )

    return findings


def _process_nginx_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized nginx event."""
    findings: list[Finding] = []
    ip = event.src_ip

    state.web_activity_ips.add(ip)

    if event.event_type == "nginx_suspicious_request":
        state.web_probe_ips.add(ip)
        state.first_web_probe_time.setdefault(ip, event.timestamp)

        if ip not in state.suspicious_web_alerted:
            state.suspicious_web_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="suspicious_web_probe",
                    severity="medium",
                    message=(
                        "Suspicious web probe detected from "
                        f"{ip} path={event.path}"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    if (
        event.status_code is not None
        and event.status_code in state.http_error_statuses
    ):
        error_key = (ip, event.status_code)
        state.http_error_counts[error_key] += 1

        if (
            state.http_error_counts[error_key] >= state.http_error_threshold
            and error_key not in state.repeated_http_error_alerted
        ):
            state.repeated_http_error_alerted.add(error_key)
            findings.append(
                Finding(
                    finding_type="repeated_http_error_responses",
                    severity="medium",
                    message=(
                        "Repeated HTTP error responses detected from "
                        f"{ip} (status={event.status_code}, "
                        f"threshold={state.http_error_threshold})"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    return findings


def _process_mail_event(
    event: Event,
    state: DetectionState,
) -> list[Finding]:
    """Process a normalized mail auth event."""
    findings: list[Finding] = []
    ip = event.src_ip

    state.mail_activity_ips.add(ip)

    if event.event_type in {
        "dovecot_failed_login",
        "postfix_sasl_auth_failed",
    }:
        state.mail_failed_counts[ip] += 1

        if (
            state.mail_failed_counts[ip] >= 3
            and ip not in state.mail_threshold_alerted
        ):
            state.mail_threshold_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="repeated_mail_auth_failures",
                    severity="medium",
                    message=(
                        "Repeated mail authentication failures detected "
                        f"from {ip} ({state.mail_failed_counts[ip]} failures)"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    if event.event_type == "dovecot_success_login":
        prior_failures = state.mail_failed_counts[ip]
        if prior_failures >= 1:
            findings.append(
                Finding(
                    finding_type="mail_success_after_failures",
                    severity="high",
                    message=(
                        "Successful mail login after prior failures from "
                        f"{ip} ({prior_failures} failures before success)"
                    ),
                    src_ip=ip,
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

    web_probe_time = state.first_web_probe_time.get(ip)

    if (
        event.source == "auth"
        and web_probe_time is not None
        and web_probe_time < event.timestamp
    ):
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

    if (
        event.source == "fail2ban"
        and event.event_type == "fail2ban_ban"
        and web_probe_time is not None
        and web_probe_time < event.timestamp
    ):
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

    observed_sources = 0
    if ip in state.web_activity_ips:
        observed_sources += 1
    if ip in state.auth_activity_ips:
        observed_sources += 1
    if ip in state.mail_activity_ips:
        observed_sources += 1

    if observed_sources >= 2:
        if ip not in state.multi_source_alerted:
            state.multi_source_alerted.add(ip)
            findings.append(
                Finding(
                    finding_type="multi_source_ip_activity",
                    severity="high",
                    message=(
                        "IP appeared across multiple observed sources: "
                        f"{ip}"
                    ),
                    src_ip=ip,
                    timestamp=event.timestamp,
                )
            )

    return findings


def _check_enforcement_correlations(
    action: EnforcementAction,
    state: DetectionState,
) -> list[Finding]:
    """Generate findings that depend on enforcement timing."""
    findings: list[Finding] = []
    ip = action.src_ip

    web_probe_time = state.first_web_probe_time.get(ip)

    if (
        action.action == "ban"
        and web_probe_time is not None
        and web_probe_time < action.timestamp
    ):
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
                    timestamp=action.timestamp,
                )
            )

    return findings
