# Architecture

## Overview

Traxerax-lite is a modular security log analysis tool built in Python. It follows a pipeline architecture:

1. **Ingestion**: Read raw log files from multiple sources
2. **Parsing**: Normalize log entries into structured `Event` objects
3. **Detection**: Apply correlation rules to identify security findings
4. **Storage**: Persist events and findings in SQLite database
5. **Reporting**: Generate human-readable or JSON reports

## Core Components

### Models (`models.py`)

- `Event`: Represents a normalized security event with fields like timestamp, source, event_type, src_ip, etc.
- `Finding`: Represents a detected security issue with severity, message, and associated IP

### Parsers (`parser.py`)

Parsers for different log formats:
- `parse_auth_line()`: SSH authentication logs
- `parse_fail2ban_line()`: Fail2ban ban/unban events
- `parse_nginx_access_line()`: Nginx access logs
- `parse_mail_line()`: Mail server authentication logs

Each parser returns an `Event` object or `None` if parsing fails.

### Detector (`detector.py`)

Contains correlation logic in `process_event()`. Maintains `DetectionState` to track:
- Failed login counts per IP
- Recent events for correlation
- Ban status

Detection rules include:
- Root login attempts
- Repeated failed logins
- Success after failures
- Suspicious web probes
- Cross-source activity

### Storage (`storage.py`)

SQLite-based persistence:
- Events table: All parsed events
- Findings table: Detected security issues
- Uses SHA256 hashes to prevent duplicates
- Row factory for dict-like access

### Reporter (`reporter.py`)

Output formatting:
- Text format for terminal display
- JSON format for machine consumption
- Summary and per-IP reports

### Configuration (`config.py`)

YAML-based configuration loading. Currently defines suspicious nginx paths.

## Data Flow

```
Log Files → Parsers → Events → Detector → Findings
                    ↓          ↓
               Storage ←─────── Storage
                    ↓
               Reporter → Output
```

## Database Schema

### events table
- id (PK)
- event_hash (unique)
- timestamp, source, event_type, raw
- username, src_ip, port, service, hostname, process, action, jail, method, path, status_code

### findings table
- id (PK)
- finding_hash (unique)
- timestamp, finding_type, severity, message, src_ip

## Extensibility

The modular design allows easy addition of:
- New log parsers
- Additional detection rules
- Custom reporters
- Alternative storage backends