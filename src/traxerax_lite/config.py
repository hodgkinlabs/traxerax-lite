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


def _as_dict(value: Any) -> dict[str, Any]:
    """Return a mapping-like config section or an empty dict."""
    return value if isinstance(value, dict) else {}
