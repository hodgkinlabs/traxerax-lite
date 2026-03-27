"""Tests for auth log parsing."""

from traxerax_lite.parser import parse_auth_line


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
    assert event.port == 40001
    assert event.hostname == "debian"
    assert event.process == "sshd"
    assert event.service == "ssh"


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
    assert event.src_ip == "185.10.10.1"
    assert event.port == 40002


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
    assert event.src_ip == "203.0.113.77"
    assert event.port == 50001


def test_parse_unsupported_line_returns_none() -> None:
    """Unsupported auth lines should return None."""
    line = (
        "Mar 25 10:02:00 debian CRON[2100]: pam_unix(cron:session): "
        "session opened for user root(uid=0) by root(uid=0)"
    )

    event = parse_auth_line(line, year=2026)

    assert event is None