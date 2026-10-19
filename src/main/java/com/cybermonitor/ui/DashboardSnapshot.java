package com.cybermonitor.ui;

import com.cybermonitor.evaluation.RootCauseEvaluation;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.Severity;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Immutable real-data values displayed by the dashboard. */
public record DashboardSnapshot(
        long eventCount,
        List<Incident> incidents,
        Optional<RootCauseEvaluation.EvaluationReport> rootCauseEvaluation) {

    public DashboardSnapshot {
        if (eventCount < 0) {
            throw new IllegalArgumentException("eventCount must not be negative");
        }
        incidents = List.copyOf(Objects.requireNonNull(incidents, "incidents must not be null"));
        if (incidents.stream().anyMatch(Objects::isNull)) {
            throw new NullPointerException("incidents must not contain null");
        }
        rootCauseEvaluation = Objects.requireNonNull(rootCauseEvaluation, "rootCauseEvaluation must not be null");
    }

    public int incidentCount() {
        return incidents.size();
    }

    public long rawAlertCount() {
        return incidents.stream().mapToLong(incident -> incident.alerts().size()).sum();
    }

    public Map<Severity, Long> incidentCountsBySeverity() {
        EnumMap<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, 0L);
        }
        for (Incident incident : incidents) {
            counts.compute(incident.severity(), (ignored, count) -> count + 1L);
        }
        return Map.copyOf(counts);
    }
}
