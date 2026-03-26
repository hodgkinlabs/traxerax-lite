"""Detection logic for Traxerax Lite."""

from collections import defaultdict
from dataclasses import dataclass, field

from traxerax_lite.models import Event, Finding


@dataclass
class DetectionState:
    """In-memory state for simple detections."""

    failed_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    threshold_alerted: set[str] = field(default_factory=set)


def process_event(event: Event, state: DetectionState) -> list[Finding]:
    """Process one event and return any generated findings."""
    findings: list[Finding] = []

    if event.src_ip is None:
        return findings

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