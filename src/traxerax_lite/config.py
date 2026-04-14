"""Configuration loading."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = "config/default.yaml"

DEFAULT_FINDING_SEVERITIES = {
    "root_login_attempt": "medium",
    "repeated_failed_login": "medium",
    "success_after_failures": "high",
    "suspicious_web_probe": "medium",
    "repeated_http_error_responses": "medium",
    "repeated_mail_auth_failures": "medium",
    "mail_password_spray_attempt": "high",
    "mail_success_after_failures": "high",
    "ip_banned_after_auth_activity": "medium",
    "ip_banned_after_mail_activity": "medium",
    "ip_banned_after_web_activity": "medium",
    "web_probe_followed_by_auth_activity": "medium",
    "web_probe_followed_by_fail2ban_ban": "medium",
    "multi_source_ip_activity": "high",
}


@dataclass(slots=True)
class DetectionSettings:
    """Normalized detection settings derived from YAML config."""

    auth_failed_login_threshold: int = 3
    mail_failed_login_threshold: int = 3
    mail_unique_username_threshold: int = 3
    http_error_threshold: int = 3
    http_error_statuses: set[int] = field(
        default_factory=lambda: {
            400,
            401,
            403,
            404,
            408,
            429,
            444,
            500,
            502,
            503,
            504,
        }
    )
    enabled_rules: dict[str, bool] = field(
        default_factory=lambda: {
            finding_type: True
            for finding_type in DEFAULT_FINDING_SEVERITIES
        }
    )
    finding_severities: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_FINDING_SEVERITIES)
    )


@dataclass(slots=True)
class ReportSettings:
    """Normalized report settings derived from YAML config."""

    top_noisy_source_ips_limit: int = 5
    top_risky_source_ips_limit: int = 5
    repeat_banned_ips_limit: int = 5
    returned_after_ban_ips_limit: int = 5
    repeat_banned_min_bans: int = 2
    persistent_multi_source_min_sources: int = 2
    persistent_multi_source_min_total_events: int = 4
    root_attempt_repeat_min_auth_events: int = 3
    returned_after_ban_min_returns: int = 1
    priority_incidents_enabled: bool = True
    priority_incidents_limit: int = 5
    priority_incidents_min_score: int = 1
    priority_severity_weights: dict[str, int] = field(
        default_factory=lambda: {
            "low": 1,
            "medium": 2,
            "high": 4,
            "critical": 6,
        }
    )
    priority_weight_total_findings: int = 0
    priority_weight_total_events: int = 0
    priority_weight_ban_count: int = 1
    priority_weight_repeat_banned: int = 3
    priority_weight_returned_after_ban: int = 4
    priority_weight_persistent_multi_source: int = 3
    priority_weight_root_attempt_repeat_ip: int = 3
    priority_weight_auth_web_crossover: int = 3
    priority_weight_bursty_activity: int = 2
    priority_weight_suspicious_web_probe: int = 2
    priority_weight_web_probe_followed_by_ban: int = 3


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load YAML config file."""
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {path}")

    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Config must contain a top-level mapping: {path}")

    return loaded


def load_detection_settings(config: dict[str, Any]) -> DetectionSettings:
    """Return normalized detection settings with defaults applied."""
    detection_config = _as_dict(config.get("detection"))
    thresholds = _as_dict(detection_config.get("thresholds"))
    rules = _as_dict(detection_config.get("rules"))
    severities = _as_dict(detection_config.get("severities"))
    nginx_config = _as_dict(config.get("nginx"))

    settings = DetectionSettings(
        auth_failed_login_threshold=int(
            thresholds.get("auth_failed_login", 3)
        ),
        mail_failed_login_threshold=int(
            thresholds.get("mail_failed_login", 3)
        ),
        mail_unique_username_threshold=int(
            thresholds.get("mail_unique_usernames", 3)
        ),
        http_error_threshold=int(
            thresholds.get(
                "repeated_http_error",
                nginx_config.get("repeated_error_threshold", 3),
            )
        ),
        http_error_statuses={
            int(status_code)
            for status_code in nginx_config.get(
                "error_status_codes",
                DetectionSettings().http_error_statuses,
            )
        },
    )

    for finding_type in settings.enabled_rules:
        settings.enabled_rules[finding_type] = bool(
            rules.get(finding_type, settings.enabled_rules[finding_type])
        )
        settings.finding_severities[finding_type] = str(
            severities.get(
                finding_type,
                settings.finding_severities[finding_type],
            )
        )

    return settings


def load_report_settings(config: dict[str, Any]) -> ReportSettings:
    """Return normalized report settings with defaults applied."""
    report_config = _as_dict(config.get("reporting"))
    limits = _as_dict(report_config.get("limits"))
    persistence = _as_dict(report_config.get("persistence"))
    priority = _as_dict(report_config.get("incident_priority"))
    priority_weights = _as_dict(priority.get("weights"))
    severity_weights = _as_dict(priority_weights.get("severity"))

    return ReportSettings(
        top_noisy_source_ips_limit=int(
            limits.get(
                "top_noisy_source_ips",
                limits.get("top_event_source_ips", 5),
            )
        ),
        top_risky_source_ips_limit=int(
            limits.get(
                "top_risky_source_ips",
                limits.get("top_finding_source_ips", 5),
            )
        ),
        repeat_banned_ips_limit=int(
            limits.get("repeat_banned_ips", 5)
        ),
        returned_after_ban_ips_limit=int(
            limits.get("returned_after_ban_ips", 5)
        ),
        repeat_banned_min_bans=int(
            persistence.get("repeat_banned_min_bans", 2)
        ),
        persistent_multi_source_min_sources=int(
            persistence.get("persistent_multi_source_min_sources", 2)
        ),
        persistent_multi_source_min_total_events=int(
            persistence.get("persistent_multi_source_min_total_events", 4)
        ),
        root_attempt_repeat_min_auth_events=int(
            persistence.get("root_attempt_repeat_min_auth_events", 3)
        ),
        returned_after_ban_min_returns=int(
            persistence.get("returned_after_ban_min_returns", 1)
        ),
        priority_incidents_enabled=bool(priority.get("enabled", True)),
        priority_incidents_limit=int(priority.get("limit", 5)),
        priority_incidents_min_score=int(priority.get("minimum_score", 1)),
        priority_severity_weights={
            "low": int(severity_weights.get("low", 1)),
            "medium": int(severity_weights.get("medium", 2)),
            "high": int(severity_weights.get("high", 4)),
            "critical": int(severity_weights.get("critical", 6)),
        },
        priority_weight_total_findings=int(
            priority_weights.get("total_findings", 0)
        ),
        priority_weight_total_events=int(
            priority_weights.get("total_events", 0)
        ),
        priority_weight_ban_count=int(
            priority_weights.get("ban_count", 1)
        ),
        priority_weight_repeat_banned=int(
            priority_weights.get("repeat_banned", 3)
        ),
        priority_weight_returned_after_ban=int(
            priority_weights.get("returned_after_ban", 4)
        ),
        priority_weight_persistent_multi_source=int(
            priority_weights.get("persistent_multi_source", 3)
        ),
        priority_weight_root_attempt_repeat_ip=int(
            priority_weights.get("root_attempt_repeat_ip", 3)
        ),
        priority_weight_auth_web_crossover=int(
            priority_weights.get("auth_web_crossover", 3)
        ),
        priority_weight_bursty_activity=int(
            priority_weights.get("bursty_activity", 2)
        ),
        priority_weight_suspicious_web_probe=int(
            priority_weights.get("suspicious_web_probe", 2)
        ),
        priority_weight_web_probe_followed_by_ban=int(
            priority_weights.get("web_probe_followed_by_ban", 3)
        ),
    )


def _as_dict(value: Any) -> dict[str, Any]:
    """Return a mapping-like config section or an empty dict."""
    return value if isinstance(value, dict) else {}
