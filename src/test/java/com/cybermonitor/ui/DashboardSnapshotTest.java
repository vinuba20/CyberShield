package com.cybermonitor.ui;

import com.cybermonitor.evaluation.RootCauseEvaluation;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DashboardSnapshotTest {

    @Test
    void summarizesRepositoryDataAndIncidentSeverityWithoutInventingCounts() {
        Incident high = incident("high", Severity.HIGH, 2);
        Incident low = incident("low", Severity.LOW, 1);

        DashboardSnapshot snapshot = new DashboardSnapshot(23, List.of(high, low), Optional.empty());

        assertEquals(23, snapshot.eventCount());
        assertEquals(2, snapshot.incidentCount());
        assertEquals(3, snapshot.rawAlertCount());
        assertEquals(Map.of(
                Severity.LOW, 1L,
                Severity.MEDIUM, 0L,
                Severity.HIGH, 1L,
                Severity.CRITICAL, 0L), snapshot.incidentCountsBySeverity());
    }

    @Test
    void retainsActualEvaluationReportForDisplay() {
        RootCauseEvaluation.EvaluationReport report = new RootCauseEvaluation(
                new com.cybermonitor.evaluation.SyntheticCascadeGenerator())
                .evaluate(1L, 2L, 2, java.time.Duration.ZERO);

        DashboardSnapshot snapshot = new DashboardSnapshot(0L, List.of(), Optional.of(report));

        assertEquals(Optional.of(report), snapshot.rootCauseEvaluation());
    }

    @Test
    void rejectsInvalidSnapshotInputs() {
        assertThrows(IllegalArgumentException.class,
                () -> new DashboardSnapshot(-1, List.of(), Optional.empty()));
        assertThrows(NullPointerException.class,
                () -> new DashboardSnapshot(0, null, Optional.empty()));
        assertThrows(NullPointerException.class,
                () -> new DashboardSnapshot(0, List.of(), null));
    }

    private static Incident incident(String id, Severity severity, int alertCount) {
        List<ThreatAlert> alerts = java.util.stream.IntStream.range(0, alertCount)
                .mapToObj(index -> {
                    LogEvent event = new LogEvent(id + "-event-" + index,
                            Instant.parse("2026-10-18T10:00:00Z").plusSeconds(index),
                            "Pump-1", "PUMP_FAULT", null, null, "event", "raw");
                    return new ThreatAlert(id + "-alert-" + index, "RULE", severity, event.timestamp(),
                            event.source(), "reason", List.of(event));
                })
                .toList();
        return new Incident(id, "incident " + id, severity, IncidentStatus.OPEN, alerts,
                List.of(new RootCauseCandidate("PUMP_FAULT", "Pump-1", 1.0, "precedence evidence")), "");
    }
}
