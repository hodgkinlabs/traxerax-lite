# traxerax-lite

Lightweight, modular Linux security triage tool for parsing, correlating,
storing, and reporting on hostile activity across multiple log sources.

Traxerax-lite is built to extract meaningful security signal from noisy
internet-facing systems. It ingests raw logs, normalizes them into structured
events, applies deterministic detection logic, stores telemetry in SQLite, and
provides both summary and per-IP investigative reporting.

---

## Purpose

Default log tooling often produces large volumes of low-value output without
helping the operator understand what actually matters.

Traxerax-lite focuses on:

- extracting meaningful security events from raw logs
- correlating related activity across sources
- preserving data for later analysis
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

---

## Usage

### Basic log processing

```bash
# Process authentication logs
python -m traxerax_lite.main --auth-log /var/log/auth.log

# Process multiple log types
python -m traxerax_lite.main --auth-log /var/log/auth.log --nginx-log /var/log/nginx/access.log --fail2ban-log /var/log/fail2ban.log

# Process with custom config
python -m traxerax_lite.main --config /path/to/config.yaml --auth-log /var/log/auth.log
```

### Generate reports

```bash
# Summary report
python -m traxerax_lite.main --report summary

# Per-IP investigation
python -m traxerax_lite.main --report ip --ip 185.10.10.1
```

### Configuration

The tool uses a YAML configuration file (default: `config/default.yaml`) to define suspicious paths for nginx log analysis.

Example config:
```yaml
nginx:
  repeated_error_threshold: 3
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
```

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
  - suspicious requests based on configured paths
  - repeated configured HTTP error responses

- **mail authentication logs**
  - Dovecot failed logins
  - Dovecot successful logins
  - Postfix SASL authentication failures

All supported sources are normalized into a shared `Event` model.

---

### 2. Detection and Correlation

The current detection engine supports:

- **Root Login Attempt**
  - failed authentication attempt targeting `root`

- **Repeated Failed Logins**
  - threshold-based SSH failed login detection

- **Success After Failures**
  - successful SSH login following prior failed attempts from the same IP

- **Suspicious Web Probe**
  - nginx request to configured suspicious paths

- **Repeated HTTP Error Responses**
  - repeated configured nginx `4xx`/`5xx` responses from the same IP

- **Repeated Mail Auth Failures**
  - repeated Dovecot/Postfix authentication failures from the same IP

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
  - IP observed across nginx, auth, and fail2ban during the same run

All logic is deterministic and testable.

---

### 3. SQLite Persistence

Observed activity events, enforcement actions, and findings are stored locally in SQLite.

Default database path:

```text
data/output/traxerax_lite.db
