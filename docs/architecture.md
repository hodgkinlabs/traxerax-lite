# Architecture

## Overview

`traxerax-lite` is a small, single-process Python application for replaying
security logs into a normalized event store, generating deterministic findings,
and rebuilding incident-sized summaries for later investigation.

The runtime is intentionally straightforward:

1. `cli.py` parses operator input.
2. `main.py` loads config, opens SQLite, and coordinates the pipeline.
3. `collector.py` streams raw log lines from the requested files.
4. `parser.py` converts each supported log format into normalized records.
5. `baseline.py` suppresses known-benign records before persistence.
6. `detector.py` applies stateful correlation and emits findings.
7. `storage.py` persists events, enforcement actions, findings, and incidents.
8. `report_queries.py` and `hunt.py` build operator-facing reports from SQLite.

The design favors explicit modules and SQL over framework abstraction. Most
behavior is easy to trace from the CLI entry point down to one parser, detector,
query, or report helper.

## Module Responsibilities

### `models.py`

Defines the three core records shared across the project:

- `Event`: normalized observed activity from auth, nginx, or mail sources
- `EnforcementAction`: ban or unban activity, primarily from fail2ban
- `Finding`: deterministic detection output produced from one or more records

These dataclasses are the boundary objects passed between parsing, detection,
storage, and reporting code.

### `config.py`

Loads YAML config and normalizes it into typed settings dataclasses:

- `DetectionSettings`
- `ReportSettings`
- `BaselineSettings`

This module is also where backward compatibility is handled for config names
and defaults, such as legacy nginx threshold settings and the older
`suppression` section name.

### `collector.py`

Provides minimal line-by-line file reading with clear filesystem error
messages. This layer intentionally stays thin so parser logic remains isolated
from file handling.

### `parser.py`

Normalizes raw log formats into `Event` records.

Current parser coverage:

- SSH auth failures, root login attempts, and successful logins
- fail2ban ban and unban actions
- nginx access requests, including suspicious-path classification
- dovecot and postfix mail authentication failures and successes

Parser helpers also normalize timestamps, preserve request context, and attach
fields such as `normalized_path`, `query_string`, `user_agent`, and
`match_reason` when available.

### `baseline.py`

Suppresses known-good activity before it affects stored telemetry or detector
state. Suppression currently supports:

- exact source IP matches
- source CIDR ranges
- ignored usernames
- ignored nginx paths
- ignored user-agent regex patterns

### `detector.py`

Owns stateful correlation. `DetectionState` tracks recent timestamps and alert
bookkeeping so the project can detect repeated failures, success-after-failure
patterns, web-to-auth correlations, web-to-ban correlations, and multi-source
activity without requerying the database for every record.

The detector has two entry points:

- `process_event(...)`
- `process_enforcement_action(...)`

Each returns zero or more `Finding` objects for the caller to persist.

### `storage.py`

Owns SQLite access for writes and schema setup.

Key behaviors:

- creates the required tables on startup
- enables foreign keys
- hashes normalized records to make inserts idempotent
- migrates older fail2ban rows out of the `events` table
- keeps schema evolution local with additive column checks

### `incidents.py`

Rebuilds incident groupings from persisted telemetry after ingestion or before
reporting. Incidents are derived records, not streaming state.

The incident builder:

- merges events, findings, and enforcement actions into a single evidence stream
- groups by `src_ip`
- starts a new incident when the evidence gap exceeds the configured window
- assigns severity and score from evidence composition
- persists evidence links in `incident_evidence`

### `query.py`

Contains SQL read helpers used by summary, IP, and hunt reports. This module is
query-heavy by design so reporting code can remain focused on presentation and
assessment logic instead of embedding raw SQL inline.

### `report_queries.py`

Builds the two main operator reports:

- environment summary report
- per-IP investigation report

This layer combines query results, simple scoring/assessment rules, and text
formatting into readable report output.

### `hunt.py`

Provides smaller report presets optimized for common investigative questions,
such as new IP discovery, cross-source activity, post-ban returners, suspicious
paths, and authentication success after prior failures.

### `reporter.py`

Formats individual normalized records as text or JSON. This is the lowest-level
presentation helper and is separate from higher-level stored-data reports.

### `main.py`

Coordinates the full runtime:

- parse CLI args
- load config
- initialize SQLite
- optionally run report mode
- collect and sort normalized records across sources
- warm the detector with recent persisted history
- suppress, persist, detect, and persist findings
- rebuild incidents
- log a concise processing summary

## Runtime Data Flow

### Ingestion mode

```text
CLI args
  -> config + parser setup
  -> read raw log lines
  -> parse to Event / EnforcementAction
  -> baseline suppression
  -> persist raw normalized records
  -> run detector
  -> persist findings
  -> rebuild incidents
  -> print summary
```

### Report mode

```text
CLI args
  -> config + database open
  -> rebuild incidents from persisted telemetry
  -> execute report queries
  -> render summary / IP / hunt output
```

## Ordering and State

Cross-source detections depend on timestamp ordering rather than input file
order. `main._collect_normalized_events(...)` collects records from all enabled
sources, annotates them with a stable sequence number, and sorts by:

1. parsed timestamp
2. collection sequence

That keeps replay deterministic and avoids correlation bugs when different log
files overlap in time.

Before processing new records, `main._seed_detection_state_from_history(...)`
replays only the recent persisted window needed for current detector rules. This
preserves context for correlations like "success after failures" without paying
the cost of rebuilding in-memory detector state from the entire database.

## Persistence Model

SQLite stores five logical tables:

- `events`: normalized auth, nginx, and mail telemetry
- `findings`: detector output keyed by deterministic hashes
- `enforcement_actions`: fail2ban-style control actions
- `incidents`: grouped investigative summaries
- `incident_evidence`: links from each incident to its evidence rows

Record hashes make ingestion idempotent when sample data or overlapping logs are
replayed more than once.

## Design Notes

- The project is intentionally synchronous. The workload is log replay and local
  SQLite writes, so extra concurrency would add complexity without much value.
- SQL is kept explicit instead of hidden behind an ORM. That makes the
  reporting logic easy to inspect and change.
- Detector state stays in memory while reports rely on persisted data. This
  keeps the streaming path simple and the reporting path reproducible.
- Incidents are rebuilt rather than updated incrementally. That trades a little
  extra work for simpler correctness and easier schema evolution.

## Cleanup Status

As of this pass, the codebase no longer carries the unused empty
`src/traxerax_lite/correlator.py` placeholder. The remaining modules all have a
clear runtime role in ingestion, detection, storage, or reporting.
