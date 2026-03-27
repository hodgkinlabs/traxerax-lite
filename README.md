# traxerax-lite

Minimal, modular log analysis and security triage tool for Linux systems.

Traxerax-lite ingests authentication logs, normalizes raw log data into
structured events, applies detection logic, and persists results for analysis.
The goal is to provide a clear, extensible foundation for understanding hostile
activity on exposed systems without the noise and opacity of traditional tools.

---

## Purpose

Most default log tooling (e.g., logwatch) produces large volumes of low-signal
output. This project focuses on:

* extracting meaningful security events from raw logs
* identifying actionable patterns (not just raw activity)
* preserving data for later analysis and correlation
* building a clean, extensible pipeline for multi-source log analysis

---

## Current Capabilities

### 1. Authentication Log Parsing (SSH)

Parses standard Linux auth logs and normalizes them into structured events.

Supported event types:

* `ssh_failed_login`
* `ssh_root_login_attempt`
* `ssh_success_login`

Extracted fields include:

* timestamp
* username
* source IP
* port
* hostname
* process

---

### 2. Detection Engine (Stateful)

Processes normalized events and generates findings based on behavior over time.

Current detections:

* **Root Login Attempt**

  * Any attempt to authenticate as `root`

* **Repeated Failed Logins**

  * Threshold-based detection (default: 3 failures per IP)
  * Triggered once per source IP to reduce noise

* **Success After Failures**

  * Successful login following prior failed attempts from the same IP
  * High severity due to potential credential compromise

---

### 3. Structured Output (Reporter Layer)

Events and findings are rendered into clean, operator-friendly terminal output:

```
[EVENT] 2026-03-25 10:01:10 source=auth type=ssh_failed_login ip=203.0.113.77 user=user1
[FINDING][HIGH] 2026-03-25 10:01:20 type=success_after_failures ip=203.0.113.77 message=...
```

---

### 4. SQLite Persistence

All parsed events and generated findings are stored locally:

```
data/output/traxerax_lite.db
```

Schema:

* `events` table → normalized log activity
* `findings` table → detection results

This enables:

* historical analysis
* correlation across runs
* future reporting capabilities

---

### 5. Test Coverage

Unit tests validate all core components:

* parser behavior (event extraction)
* detector logic (stateful findings)
* reporter formatting (output correctness)
* storage layer (database integrity)

Run tests with:

```
pytest
```

---

## Architecture Overview

The project is intentionally modular:

```
CLI → Collector → Parser → Detector → Reporter → Storage
```

### Components

* **cli.py**

  * Command-line interface and argument parsing

* **collector.py**

  * Reads raw log data (file-based ingestion)

* **parser.py**

  * Converts raw log lines into structured `Event` objects

* **detector.py**

  * Applies stateful logic and produces `Finding` objects

* **reporter.py**

  * Formats events and findings for human-readable output

* **storage.py**

  * Persists events and findings using SQLite

* **models.py**

  * Defines core data structures (`Event`, `Finding`)

---

## Design Principles

* **Signal over noise**

  * Focus on meaningful activity, not verbose logs

* **Separation of concerns**

  * Parsing, detection, formatting, and storage are isolated

* **Deterministic behavior**

  * All logic is testable and reproducible

* **Extensibility**

  * Designed to support additional log sources and correlation

* **Minimal dependencies**

  * Uses Python standard library where possible (e.g., sqlite3)

---

## Example Use Case

Run against an auth log:

```
python -m traxerax_lite.main --auth-log sample_logs/auth.log.sample
```

Produces:

* real-time parsed events
* immediate detection output
* persisted records in SQLite

---

## Roadmap (Next Steps)

### Near Term

* Fail2ban log parsing

  * Track bans/unbans and jail activity
  * Correlate defensive actions with auth behavior

* Nginx access log parsing

  * Detect scanning, probing, and enumeration attempts

---

### Mid Term

* Cross-source correlation

  * Link activity across SSH, web, and fail2ban logs
  * Identify multi-vector probing from the same IP

* Reporting layer

  * Summarize:

    * top hostile IPs
    * high-severity findings
    * repeat offenders
    * suspicious successful logins

---

### Future

* Email authentication logs (Postfix / Dovecot)
* Time-window-based detection (rate analysis)
* Live log ingestion (tail / streaming)
* Export formats (JSON, markdown reports)

---

## Why This Project

This project demonstrates:

* practical log parsing and normalization
* stateful detection logic design
* modular Python architecture
* test-driven development practices
* real-world security use case alignment

It is intentionally built from first principles rather than relying on
existing frameworks, to show clear understanding of the underlying mechanics.

---

## Status

Active development.
Core pipeline (parse → detect → store) is complete and stable.