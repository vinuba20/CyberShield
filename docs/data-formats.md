# Data formats

All checked-in examples are synthetic and contain no real system data.

## Equipment-alarm CSV

Implemented by `EquipmentAlarmCsvParser`. Each non-comment event line has exactly five columns in this order:

```text
timestamp,tool,component,code,severity
```

- `timestamp`: ISO-8601 instant, for example `2026-10-18T10:00:00Z`.
- `tool`: non-empty tool/source name; normalized to `LogEvent.source`.
- `component`: non-empty equipment component; retained in the normalized event message.
- `code`: non-empty alarm/event code; normalized to `LogEvent.eventType`.
- `severity`: non-empty text; retained in the normalized event message.

Blank lines, lines whose first non-whitespace character is `#`, and the case-insensitive header are ignorable. Quoted CSV fields and doubled quotes inside quoted fields are supported. An event row with any blank required field, an invalid timestamp, malformed quoting, or a field count other than five is malformed. The parser preserves the original row as `LogEvent.rawLine`; `LogEvent.value` and `user` are null for this format.

Example (the checked-in equipment sample uses these fields):

```csv
# Synthetic equipment alarm sample
timestamp,tool,component,code,severity
2026-10-18T10:00:00Z,Pump-1,Motor,PUMP_FAULT,CRITICAL
2026-10-18T10:00:15Z,Pump-1,Pressure-Sensor,PRESSURE_HIGH,HIGH
2026-10-18T10:00:30Z,Wafer-Handler-1,Arm,HANDLER_ALARM,HIGH
2026-10-18T10:00:45Z,Recipe-Controller-1,Recipe,RECIPE_ABORT,MEDIUM
```

The sample is under [`data/sample/equipment-alarms.csv`](../data/sample/equipment-alarms.csv). It can be parsed line-by-line with `EquipmentAlarmCsvParser`; the project does not yet include the file-import service/UI to load it into the running application.

## Synthetic authentication log example

[`data/sample/auth.log`](../data/sample/auth.log) is an illustrative text fixture with lines of this form:

```text
<ISO-8601 instant> <source> user=<user> <event-code>
```

For example:

```text
2026-10-18T10:00:00Z sshd user=demo LOGIN_FAILED
```

There is no authentication-log parser in the current source tree. The line convention and [`data/sample/auth.log`](../data/sample/auth.log) fixture are illustrative only, not an implemented import contract.

## Telemetry CSV

The PRD mentions telemetry CSV but the current source tree does not contain a telemetry parser or agreed column schema. No telemetry CSV sample is supplied as import-ready data. Numeric `LogEvent.value` values can be used directly with the threshold and rolling z-score components in code.
