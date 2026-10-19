# CyberShield Desktop

**Explainable Event Correlation, Anomaly Detection and Root-Cause Ranking for Logs and Telemetry**

CyberShield Desktop is a Java 21 desktop application prototype. Its alarm parser, telemetry detection components, precedence ranker, synthetic cascade generator, and root-cause evaluation are implemented, but the end-to-end import, incident-persistence, and dashboard data pipelines are not yet connected.

> All checked-in examples and generated evaluation data are synthetic. Synthetic results do not establish real-world accuracy and do not describe any company's internal systems.

## Prerequisites

- JDK 21 (verify with `java -version` and `javac -version`)
- Maven 3.9 or newer (verify with `mvn -version`)
- A desktop environment supported by JavaFX

JavaFX controls, Spring Core, SQLite JDBC, SLF4J/Logback, and JUnit 5 are declared in `pom.xml`; Maven resolves them. No separate JavaFX installation is required for the Maven run goal.

## Build and run

From the repository root:

```powershell
mvn package
mvn javafx:run
```

The JavaFX Maven plugin launches `com.cybermonitor.Launcher`. `mvn package` builds the project JAR at `target/cybershield-0.1.0-SNAPSHOT.jar`; use `mvn javafx:run` to launch with the JavaFX runtime and Maven-resolved dependencies. This project does not currently create a self-contained native installer or cross-platform runtime image.

The app opens a dashboard shell and runs an SQLite connectivity check. By default SQLite creates `cybershield.db` in the current working directory; `*.db` is ignored by Git. To keep runtime data outside the checkout, set `JAVA_TOOL_OPTIONS` before launching. For example:

```powershell
$env:JAVA_TOOL_OPTIONS = "-Dcybershield.db.path=$env:LOCALAPPDATA\CyberShield\cybershield.db"
mvn javafx:run
Remove-Item Env:\JAVA_TOOL_OPTIONS
```

Spring detection beans require explicit configuration when requested:

```text
cybershield.telemetry.threshold
cybershield.telemetry.comparison   (GREATER_THAN, GREATER_THAN_OR_EQUAL, LESS_THAN, LESS_THAN_OR_EQUAL)
cybershield.telemetry.severity    (LOW, MEDIUM, HIGH, CRITICAL)
cybershield.anomaly.window-size
cybershield.anomaly.z-score-threshold
cybershield.anomaly.severity
cybershield.root-cause.skew-tolerance-seconds
```

No numeric threshold, anomaly cutoff/window, or severity is supplied as an implicit project default.

Run tests:

```powershell
mvn test
```

## Sample data

Samples are under [`data/sample/`](data/sample/):

- [`equipment-alarms.csv`](data/sample/equipment-alarms.csv) is a valid synthetic equipment-alarm CSV for `EquipmentAlarmCsvParser`.
- [`auth.log`](data/sample/auth.log) illustrates synthetic authentication events. It is documentation/demo material only: this checkout has no auth-log parser, so it cannot currently be imported by the application.

See [`docs/data-formats.md`](docs/data-formats.md) for column/line formats and parser support. The application currently has no import screen or file-import service, so samples are not loaded by the JavaFX window.

## Current capabilities

- Equipment-alarm CSV line parser; preserves the raw row.
- Configurable telemetry threshold `DetectionRule`.
- Rolling z-score anomaly detector over previous numeric readings, grouped by source and event type.
- Trainable precedence statistics and top-three root-cause ranker with explanations.
- Seeded synthetic cascade generator and reproducible root-cause evaluation at 0 s, 1 s, and 3 s injected skew.
- Focused SQLite storage for ranked root-cause candidates by incident ID.
- JavaFX dashboard view components for supplied data snapshots.

Implementation details and integration boundaries are described in [`docs/architecture.md`](docs/architecture.md).

## Known integration gaps and limitations

- There is no auth-log parser, telemetry CSV parser, import service, concrete `DetectionEngine`, or concrete `CorrelationEngine` in this checkout.
- `EventRepository`, `AlertRepository`, and `IncidentRepository` are interfaces only. Root-cause candidates have a standalone SQLite store, but incidents and events cannot yet be loaded from persistent storage.
- Spring creates `PrecedenceStatistics` and `RootCauseRanker`, but no application provider trains them from historical incidents. The FR20 evaluation trains its own ranker from a separate synthetic training dataset.
- The dashboard currently has no repository-backed provider and starts in an explicit “data unavailable” state. It only displays real snapshots/evaluation reports if a caller supplies them.
- The Maven package is not a standalone installer. Running the app requires JDK 21 and Maven with network access or a populated local dependency cache.
- The synthetic cascade topology and intervals encode the assumptions the ranker learns; evaluation results are not evidence of real equipment performance.
- No screenshot is checked in: the current running dashboard has no connected data, and no application capture has been verified for this deliverable.

## Demo

Follow [`docs/demo-script.md`](docs/demo-script.md) for a short verification/demo flow. It distinguishes implemented parser/evaluation behavior from app workflows that remain disconnected.

## Project structure

```text
src/main/java/com/cybermonitor/
  anomaly/       rolling z-score interface and implementation
  config/        Spring configuration
  correlation/  shared interfaces, precedence statistics and ranker
  detection/    shared interfaces and telemetry threshold rule
  evaluation/   synthetic cascades and root-cause evaluation
  model/         shared event, alert, incident and candidate records
  parser/        event parser interface and equipment-alarm CSV parser
  repository/    repository interfaces and SQLite connection/candidate store
  service/       incident service contract and startup health check
  ui/            JavaFX dashboard view and snapshot model
```

## Project references

- [Product requirements](docs/PRD.md)
- [Architecture and integration status](docs/architecture.md)
- [Data formats](docs/data-formats.md)
- [Demo script](docs/demo-script.md)
