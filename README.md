# traxerax-lite

Lightweight, modular Linux security triage tool for parsing, correlating,
storing, and reporting on hostile activity across multiple log sources.

Traxerax-lite is built to extract meaningful security signal from noisy
internet-facing systems. It ingests raw logs, normalizes them into structured
events, applies deterministic detection logic, stores telemetry in SQLite, and
provides summary, per-IP, and hunt-oriented investigative reporting.

---

## Purpose

Default log tooling often produces large volumes of low-value output without
helping the operator understand what actually matters.

Traxerax-lite focuses on:

- extracting meaningful security events from raw logs
- correlating related activity across sources
- suppressing known-good activity before it wastes analyst time
- preserving data for later analysis
- grouping related evidence into incident-sized investigations
- generating concise, operator-friendly reports
- providing a clean, extensible Python architecture for security triage

---

## Installation

### Requirements

- Python 3.10+
- pip

### Install from source

```bash
git clone https://github.com/hodgkinlabs/traxerax-lite.git
cd traxerax-lite
pip install -e .
```

### Development setup

```bash
pip install -r requirements.txt
```

For local development runs without installing the package into the active
environment, prefix commands with `PYTHONPATH=src`.

---

## Usage

### Basic log processing

```bash
# Process authentication logs
python -m traxerax_lite.main --auth-log /var/log/auth.log

# Process multiple log types
python -m traxerax_lite.main \
  --auth-log /var/log/auth.log \
  --nginx-log /var/log/nginx/access.log \
  --fail2ban-log /var/log/fail2ban.log \
  --mail-log /var/log/mail.log

# Process with custom config
python -m traxerax_lite.main --config /path/to/config.yaml --auth-log /var/log/auth.log
```

### Generate reports

```bash
# Summary report
python -m traxerax_lite.main --report summary

# Per-IP investigation
python -m traxerax_lite.main --report ip --ip 185.10.10.1

# Hunt-oriented preset report
python -m traxerax_lite.main --report hunt --hunt-preset cross-source
```

### Hunt presets

The `hunt` report mode exposes a set of analyst-focused presets:

- `new-ips`
  - IPs first observed in the most recent 24 hours of stored telemetry
- `cross-source`
  - IPs seen across multiple sources such as nginx, auth, and mail
- `post-ban-returners`
  - IPs that resumed activity after a fail2ban ban window
- `auth-success-after-failures`
  - successful auth outcomes preceded by failures
- `sprayed-users`
  - likely mail password spray candidates
- `suspicious-paths`
  - most-requested suspicious nginx paths by request count and unique IPs

Example:

```bash
python -m traxerax_lite.main \
  --report hunt \
  --hunt-preset suspicious-paths \
  --db-path data/output/traxerax_lite.db
```

---

## Configuration

The tool uses a YAML configuration file at `config/default.yaml` to control
thresholds, time windows, incident grouping, baselining, and nginx probe
matching.

Example config:

```yaml
detection:
  thresholds:
    auth_failed_login: 3
    mail_failed_login: 3
    mail_unique_usernames: 3
    repeated_http_error: 3
  windows:
    auth_failed_login_seconds: 900
    mail_failed_login_seconds: 900
    mail_unique_usernames_seconds: 900
    repeated_http_error_seconds: 900
    success_after_failures_seconds: 3600
    web_to_auth_seconds: 3600
    web_to_ban_seconds: 3600
    multi_source_seconds: 3600
  incidents:
    gap_seconds: 1800
    minimum_evidence: 2
  rules:
    root_login_attempt: true
    repeated_failed_login: true
    suspicious_web_probe: true
    multi_source_ip_activity: true
  severities:
    success_after_failures: high
    suspicious_web_probe: medium

baseline:
  ignored_source_ips: []
  ignored_source_cidrs: []
  ignored_usernames: []
  ignored_nginx_paths: []
  ignored_user_agent_patterns: []

reporting:
  limits:
    top_noisy_source_ips: 5
    top_risky_source_ips: 5
    repeat_banned_ips: 5
    returned_after_ban_ips: 5
  persistence:
    repeat_banned_min_bans: 2
    persistent_multi_source_min_sources: 2
    persistent_multi_source_min_total_events: 4
    root_attempt_repeat_min_auth_events: 3
    returned_after_ban_min_returns: 1
  incident_priority:
    enabled: true
    limit: 5
    minimum_score: 1
    weights:
      severity:
        low: 1
        medium: 2
        high: 4
        critical: 6
      ban_count: 1
      repeat_banned: 3
      returned_after_ban: 4
      persistent_multi_source: 3
      root_attempt_repeat_ip: 3

nginx:
  error_status_codes:
    - 400
    - 401
    - 403
    - 404
    - 408
    - 429
    - 444
    - 500
    - 502
    - 503
    - 504
  suspicious_paths:
    - "/wp-login.php"
    - "/xmlrpc.php"
    - "/.env"
    - "/admin"
    - "/phpmyadmin"
  suspicious_path_patterns:
    - '(?:^|/)\.\.(?:/|%2f|%252f|\\)'
    - '(?:;|\||`|\$\(|\${)'
    - '(?:%00|\\x00|\x00)'
```

Configuration notes:

- `detection.thresholds` controls when threshold-based findings trigger.
- `detection.windows` controls the rolling time windows used for correlation.
- `detection.incidents` controls how closely related evidence is grouped into a
  single incident.
- `detection.rules` enables or disables individual findings.
- `detection.severities` overrides emitted severity per finding type.
- `baseline` suppresses known-benign activity before insertion and detection.
- `reporting.limits` controls how many IPs appear in summary rankings.
- `reporting.persistence` controls cutoffs used for persistence-oriented
  summary sections and IP-level flags.
- `reporting.incident_priority` controls scored IP prioritization in the
  summary report.

For backward compatibility, `nginx.repeated_error_threshold` is still honored
when `detection.thresholds.repeated_http_error` is not set.

---

## Current Capabilities

### 1. Multi-Source Log Parsing

Traxerax-lite currently supports:

- **Linux authentication logs**
  - failed SSH logins
  - root login attempts
  - successful SSH logins

- **fail2ban logs**
  - enforcement actions
  - ban and unban outcomes tied to prior activity

- **nginx access logs**
  - regular requests
  - suspicious requests based on configured paths or patterns
  - normalized paths and query strings
  - referrer and user-agent capture
  - path match reasons for suspicious probes
  - repeated configured HTTP error responses

- **mail authentication logs**
  - Dovecot failed logins
  - Dovecot successful logins
  - Postfix SASL authentication failures

All supported sources are normalized into a shared `Event` model, with richer
nginx request context preserved for later hunting.

---

### 2. Detection and Correlation

The current detection engine supports:

- **Root Login Attempt**
  - failed authentication attempt targeting `root`

- **Repeated Failed Logins**
  - threshold-based SSH failed login detection inside configurable time windows

- **Success After Failures**
  - successful SSH login following prior failed attempts from the same IP
  - uses rolling historical context from recent stored telemetry

- **Suspicious Web Probe**
  - nginx request to configured suspicious paths or regex-matched probe targets

- **Repeated HTTP Error Responses**
  - repeated configured nginx `4xx`/`5xx` responses from the same IP inside
    configurable time windows

- **Repeated Mail Auth Failures**
  - repeated Dovecot/Postfix authentication failures from the same IP inside
    configurable time windows

- **Mail Password Spray Attempt**
  - repeated failed mail logins from one IP against multiple usernames within a
    configurable time window

- **Mail Success After Failures**
  - successful mail login after prior mail auth failures

- **IP Banned After Auth Activity**
  - fail2ban ban following prior SSH/auth activity from the same IP

- **IP Banned After Mail Activity**
  - fail2ban ban following prior mail auth activity from the same IP

- **IP Banned After Web Activity**
  - fail2ban ban following prior nginx activity from the same IP

- **Web Probe Followed by Auth Activity**
  - suspicious nginx activity plus SSH/auth activity from the same IP

- **Web Probe Followed by fail2ban Ban**
  - suspicious nginx activity plus later fail2ban ban from the same IP

- **Multi-Source IP Activity**
  - IP observed across multiple sources inside a configurable correlation window

The detection engine also supports historical warm-start correlation by seeding
recent state from the existing SQLite database before processing new logs.
This makes incremental runs more useful for repeated activity and persistence
tracking.

All logic is deterministic and testable.

---

### 3. SQLite Persistence

Observed activity events, enforcement actions, findings, grouped incidents, and
incident evidence links are stored locally in SQLite.

Default database path:

```text
data/output/traxerax_lite.db
```

SQLite persistence supports:

- deduplicated normalized events
- deduplicated findings
- deduplicated enforcement actions
- grouped incidents with severity, score, and summary
- evidence links back to event, finding, and enforcement record IDs

---

### 4. Reporting

Traxerax-lite currently provides:

- **Summary reports**
  - environment overview
  - persistence indicators
  - top risky and top noisy IPs
  - incident queue

- **Per-IP reports**
  - activity overview and timeline
  - persistence flags
  - grouped incidents and evidence links
  - nginx status breakdown and request context

- **Hunt preset reports**
  - quick pivots for common threat-hunting questions

---

## Notes

- Baseline suppression happens before records are inserted into SQLite.
- If you process logs incrementally into the same database, recent historical
  activity can influence new detections through time-windowed warm-start state.
- The examples above use `python -m traxerax_lite.main`; if the package is not
  installed into the active environment, use `PYTHONPATH=src` for local
  development runs.
