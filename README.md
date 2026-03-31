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

## Current Capabilities

### 1. Multi-Source Log Parsing

Traxerax-lite currently supports:

- **Linux authentication logs**
  - failed SSH logins
  - root login attempts
  - successful SSH logins

- **fail2ban logs**
  - ban events
  - unban events

Both sources are normalized into a shared `Event` model.

---

### 2. Detection and Correlation

The current detection engine supports:

- **Root Login Attempt**
  - any failed authentication attempt targeting `root`

- **Repeated Failed Logins**
  - threshold-based detection (default: 3 failures per IP)
  - emitted once per IP to reduce noise

- **Success After Failures**
  - successful SSH login following prior failures from the same IP

- **IP Banned After Auth Activity**
  - correlation finding triggered when an IP observed in auth activity is later
    banned by fail2ban during the same run

All logic is deterministic and testable.

---

### 3. SQLite Persistence

All events and findings are stored locally in SQLite.

Default database path:

```text
data/output/traxerax_lite.db