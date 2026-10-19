# CyberShield Desktop

**Explainable Event Correlation, Anomaly Detection and Root-Cause Ranking for Logs and Telemetry**

A Java 21 desktop application that turns many noisy log events into a few explained incidents, suggests the likely root cause of each incident, and measures how much alert noise it removes.

> **Status:** in development (academic project by two students). All data is synthetic. This project makes no claim about any company's internal systems, data or problems, and results on synthetic data do not show real-world accuracy.

## Problem

Complex systems (IT servers, equipment software, industrial and semiconductor tooling) produce large volumes of logs and alarms. One fault often triggers many downstream alarms, and clock differences between sources make it hard to tell which event came first. Alert overload and root-cause analysis are well-known problems; this project is a small, transparent attempt at them, not a complete solution.

## Features

- **Log import:** `.log`, `.txt` and documented CSV files (auth logs, telemetry, equipment alarms), read with Java NIO. Malformed lines are skipped and counted.
- **Normalization:** every format becomes one `LogEvent` model that keeps the original line.
- **Detection rules:** repeated authentication failures, telemetry threshold breaches, fail-then-success sequences.
- **Statistical anomaly detection:** transparent rolling mean and standard-deviation (z-score) baseline.
- **Event correlation:** alerts grouped into incidents by a configurable time window, event type, source and triggering rule.
- **Explainable alerts:** each alert shows the rule, observed value, threshold, severity and supporting events.
- **Root-cause ranking:** a precedence-based ranker learns how often one event type comes before another, tolerates a configurable clock skew, and shows the top three candidates with the evidence.
- **Incident management:** notes and status (Open, Investigating, Resolved).
- **JavaFX dashboard:** event counts, severity chart, incident summary, event timeline, raw alerts vs incidents, root-cause accuracy, filters, CSV export.
- **SQLite persistence:** events, alerts, incidents, root-cause candidates and notes.
- **Evaluation:** labeled synthetic datasets, precision, recall, F1, false-positive rate, alert reduction, throughput, and root-cause top-1 and top-3 accuracy at several skew levels.

## Technology stack

| Technology | Purpose |
| --- | --- |
| Java 21 | Application logic |
| JavaFX | Desktop UI |
| Spring Core | Dependency injection and configuration |
| Java NIO | Log file reading |
| SQLite + JDBC | Local storage |
| Maven | Build and dependencies |
| JUnit 5 | Testing |
| SLF4J + Logback | Logging |

Desktop only: no web server, REST API or browser interface.

## Architecture

```text
File (.log / .txt / .csv)
  -> LogImportService (Java NIO)
  -> EventParser -> LogEvent
  -> DetectionEngine (rules + anomaly detector) -> ThreatAlert
  -> CorrelationEngine -> Incident
  -> RootCauseRanker -> RootCauseCandidate
  -> Repositories (SQLite / JDBC)
  -> JavaFX UI
```

Package layout under `com.cybermonitor`: `config`, `model`, `parser`, `detection`, `correlation`, `anomaly`, `service`, `repository.sqlite`, `evaluation`, `reporting`, `ui`, `exception`. The UI never touches JDBC, and the engines never import JavaFX.

## Root-cause method

1. Train on historical incidents: count how often event type A occurs before event type B in the same incident.
2. If A and B are closer than the configured skew, count the pair as undecided.
3. Score each event type in a new incident by the average probability that it precedes the others.
4. Rank by score, break ties by earliest timestamp, and show the top three with supporting pairs.
5. Compare against a baseline that simply picks the earliest timestamp.

Training and test datasets use different random seeds.

## Getting started

Prerequisites: JDK 21, Maven 3.9+ (or IntelliJ IDEA, which bundles Maven), Git.

```bash
git clone https://github.com/vinuba20/CyberShield.git
cd CyberShield
mvn clean test
mvn javafx:run
```

In the app, choose the format, click **Import file...** and pick `data/sample/auth_sample.log`. With the default settings it produces 22 events, 4 alerts and 3 incidents, and skips 2 malformed lines. Open an alert to see why it was raised and which events support it; open an incident to change its status and add notes. Everything is stored in `cybershield.db` (ignored by Git) and is still there after a restart.

Settings (thresholds, time windows, database path) are in `src/main/resources/cybershield.properties` and are described in `docs/data-formats.md`, together with the file formats.

## Tests

`mvn test` runs the unit tests (parser, rules, correlation, filters, CSV export, evaluation, services), the SQLite repository tests and an end-to-end test that imports the sample file through Spring and SQLite, restarts the context, and checks that incidents, notes and status are still there.

## Evaluation

The evaluation compares:

1. Independent rule alerts vs correlated incidents (precision, recall, F1, false-positive rate, alert reduction, throughput).
2. Earliest-timestamp baseline vs precedence ranker (top-1 and top-3 accuracy at 0 s, 1 s and 3 s clock skew).

Run `com.cybermonitor.evaluation.EvaluationRunner` (in IntelliJ: right-click the class, Run, with the program arguments `42 docs/evaluation.md`) to generate seeded synthetic data, score the rules and correlation against the ground truth, and write the report. The measured results are in [docs/evaluation.md](docs/evaluation.md): rule comparison, threshold sweep, correlation-window sweep and a 10-seed stability check.

Limitations: the synthetic generator defines the attacks and the causal order, so results show the method works on the assumed structure, not on real systems or equipment. Forgetful users who fail three or more times and then succeed are flagged as compromises (false alerts), and low-and-slow attacks are missed by the short-window rule; both are visible in the report.

## Team and workflow

| Member | Area |
| --- | --- |
| Member 1 (Vinuba) | Security track: application skeleton (Maven, Spring, JavaFX, SQLite), import service and auth-log parser, brute-force and fail-then-success rules, repositories, correlation engine, incident workflow, filters, CSV export, alerts-vs-incidents evaluation |
| Member 2 | Equipment track: alarm and telemetry parsers, import screen, threshold rule, z-score detector, precedence statistics, root-cause ranker and panel, cascade generator, root-cause evaluation, dashboard, packaging |

Work is split by feature track so both members build algorithm code and application code. It follows the full [Product Requirements Document](docs/PRD.md), which lists tasks, phases and checkpoints.

### Git workflow

- Work on a feature branch (`feature/<name>`), never directly on `main`.
- Open a pull request; the other member reviews and approves it before it is merged.
- `main` always builds and passes `mvn test`.
- Never commit `*.db` files, `target/` or IDE files (see `.gitignore`).

## Roadmap

- [x] Phase 0: shared models and interfaces
- [ ] Phase 1: project setup and import (auth log)
- [ ] Phase 2: detection rules and storage (brute force, fail-then-success, SQLite)
- [ ] Phase 3: correlation and incident investigation
- [ ] Phase 4: root-cause ranking (Member 2)
- [ ] Phase 5: evaluation, filters, dashboard, export (security-track parts done; dashboard and root-cause evaluation by Member 2)
- [ ] Phase 6: documentation and packaging

## License

To be decided by the team.
