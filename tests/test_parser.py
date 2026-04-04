"""Tests for log parsing."""

from datetime import timezone, timedelta

from traxerax_lite.parser import (
    parse_auth_line,
    parse_fail2ban_line,
    parse_mail_line,
    parse_nginx_access_line,
)


def test_parse_failed_login() -> None:
    """Failed SSH login lines should parse into an Event."""
    line = (
        "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
        "invalid user admin from 185.10.10.1 port 40001 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.event_type == "ssh_failed_login"
    assert event.username == "admin"
    assert event.src_ip == "185.10.10.1"


def test_parse_root_login_attempt() -> None:
    """Failed root SSH logins should parse as root login attempts."""
    line = (
        "Mar 25 10:00:05 debian sshd[2002]: Failed password for "
        "root from 185.10.10.1 port 40002 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.event_type == "ssh_root_login_attempt"
    assert event.username == "root"


def test_parse_success_login() -> None:
    """Successful SSH login lines should parse into an Event."""
    line = (
        "Mar 25 10:01:20 debian sshd[2005]: Accepted publickey for "
        "user1 from 203.0.113.77 port 50001 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.event_type == "ssh_success_login"
    assert event.username == "user1"


def test_parse_fail2ban_ban_line() -> None:
    """Fail2ban ban lines should parse into normalized events."""
    line = (
        "2026-03-25 10:00:08,123 fail2ban.actions        [3001]: "
        "NOTICE  [sshd] Ban 185.10.10.1"
    )

    event = parse_fail2ban_line(line)

    assert event is not None
    assert event.event_type == "fail2ban_ban"
    assert event.src_ip == "185.10.10.1"


def test_parse_fail2ban_line_normalizes_local_timezone_to_utc() -> None:
    """Fail2ban timestamps should normalize to UTC for cross-source ordering."""
    line = (
        "2026-03-25 10:00:08,123 fail2ban.actions        [3001]: "
        "NOTICE  [sshd] Ban 185.10.10.1"
    )

    event = parse_fail2ban_line(
        line,
        local_timezone=timezone(timedelta(hours=-7)),
    )

    assert event is not None
    assert event.timestamp.isoformat(sep=" ") == "2026-03-25 17:00:08"


def test_parse_nginx_suspicious_request() -> None:
    """Suspicious nginx paths should parse as nginx_suspicious_request."""
    line = (
        '185.10.10.1 - - [25/Mar/2026:10:00:04 +0000] '
        '"GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
    )

    event = parse_nginx_access_line(
        line,
        suspicious_paths={"/wp-login.php"},
    )

    assert event is not None
    assert event.event_type == "nginx_suspicious_request"
    assert event.path == "/wp-login.php"


def test_parse_dovecot_failed_login() -> None:
    """Dovecot failed login lines should parse into an Event."""
    line = (
        "Mar 25 10:11:40 debian dovecot: imap-login: "
        "Disconnected (auth failed, 1 attempts in 2 secs): "
        "user=<mailuser>, method=PLAIN, rip=198.51.100.20, "
        "lip=203.0.113.10, TLS, session=<abc123>"
    )

    event = parse_mail_line(line, year=2026)

    assert event is not None
    assert event.source == "mail"
    assert event.event_type == "dovecot_failed_login"
    assert event.username == "mailuser"
    assert event.src_ip == "198.51.100.20"
    assert event.service == "imap"


def test_parse_dovecot_success_login() -> None:
    """Dovecot success login lines should parse into an Event."""
    line = (
        "Mar 25 10:30:00 debian dovecot: imap-login: "
        "Login: user=<mailuser>, method=PLAIN, rip=198.51.100.20, "
        "lip=203.0.113.10, mpid=4201, TLS, session=<ghi789>"
    )

    event = parse_mail_line(line, year=2026)

    assert event is not None
    assert event.event_type == "dovecot_success_login"
    assert event.username == "mailuser"
    assert event.src_ip == "198.51.100.20"


def test_parse_postfix_sasl_failed_auth() -> None:
    """Postfix SASL failures should parse into an Event."""
    line = (
        "Mar 25 10:11:50 debian submission/smtpd[3101]: warning: "
        "unknown[198.51.100.20]: SASL LOGIN authentication failed: "
        "authentication failure"
    )

    event = parse_mail_line(line, year=2026)

    assert event is not None
    assert event.event_type == "postfix_sasl_auth_failed"
    assert event.src_ip == "198.51.100.20"
    assert event.service == "smtp"


def test_parse_unsupported_mail_line_returns_none() -> None:
    """Unsupported mail lines should return None."""
    line = (
        "Mar 25 11:00:00 debian postfix/qmgr[999]: 123ABCD: "
        "from=<example@example.com>, size=1234, nrcpt=1"
    )

    event = parse_mail_line(line, year=2026)

    assert event is None
