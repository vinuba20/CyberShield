package com.cybermonitor.correlation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.OptionalDouble;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PrecedenceStatisticsTest {

    private static final Instant BASE_TIME = Instant.parse("2026-10-18T10:00:00Z");

    @Test
    void countsOrderingPerDistinctTypePairAndCalculatesProbability() {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);
        statistics.train(List.of(incident("ordered",
                event("a1", "A", 1),
                event("a2", "A", 2),
                event("b", "B", 3))));

        assertEquals(new PrecedenceStatistics.PairCounts(1, 0, 0), statistics.countsFor("A", "B"));
        assertEquals(new PrecedenceStatistics.PairCounts(0, 1, 0), statistics.countsFor("B", "A"));
        assertEquals(1.0, statistics.probabilityBefore("A", "B").orElseThrow());
        assertEquals(0.0, statistics.probabilityBefore("B", "A").orElseThrow());
    }

    @Test
    void countsExactTiesAsUndecidedEvenWithZeroTolerance() {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);
        statistics.train(List.of(incident("tie",
                event("a", "A", 1),
                event("b", "B", 1))));

        assertEquals(new PrecedenceStatistics.PairCounts(0, 0, 1), statistics.countsFor("A", "B"));
        assertEquals(0.5, statistics.probabilityBefore("A", "B").orElseThrow());
    }

    @Test
    void countsStrictlyWithinSkewAsUndecidedButOrdersAtBoundary() {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ofSeconds(2));
        statistics.train(List.of(
                incident("within",
                        event("a1", "A", 1),
                        event("b1", "B", 2)),
                incident("boundary",
                        event("a2", "A", 3),
                        event("b2", "B", 5))));

        assertEquals(new PrecedenceStatistics.PairCounts(1, 0, 1), statistics.countsFor("A", "B"));
        assertEquals(0.75, statistics.probabilityBefore("A", "B").orElseThrow());
    }

    @Test
    void usesEarliestOccurrenceOfEachEventTypeInAnIncident() {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);
        statistics.train(List.of(incident("repeated",
                event("a-late", "A", 5),
                event("b", "B", 3),
                event("a-early", "A", 1))));

        assertEquals(new PrecedenceStatistics.PairCounts(1, 0, 0), statistics.countsFor("A", "B"));
    }

    @Test
    void missingTrainingEvidenceHasNoProbabilityAndRetrainingReplacesCounts() {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);

        assertEquals(OptionalDouble.empty(), statistics.probabilityBefore("A", "B"));
        statistics.train(List.of(incident("first",
                event("a", "A", 1),
                event("b", "B", 2))));
        statistics.train(List.of());

        assertEquals(new PrecedenceStatistics.PairCounts(0, 0, 0), statistics.countsFor("A", "B"));
        assertFalse(statistics.probabilityBefore("A", "B").isPresent());
    }

    @Test
    void rejectsInvalidToleranceTrainingAndPairQueries() {
        assertThrows(IllegalArgumentException.class, () -> new PrecedenceStatistics(Duration.ofNanos(-1)));
        assertThrows(NullPointerException.class, () -> new PrecedenceStatistics(null));
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);
        assertThrows(NullPointerException.class, () -> statistics.train(null));
        assertThrows(NullPointerException.class, () -> statistics.probabilityBefore(null, "B"));
        assertThrows(IllegalArgumentException.class, () -> statistics.probabilityBefore("A", "A"));
        assertThrows(NullPointerException.class, () -> statistics.countsFor("A", null));
    }

    private static Incident incident(String id, LogEvent... events) {
        ThreatAlert alert = new ThreatAlert(
                "alert-" + id, "TEST", Severity.LOW, BASE_TIME, "test", "test evidence", List.of(events));
        return new Incident(id, "test incident", Severity.LOW, IncidentStatus.OPEN,
                List.of(alert), List.of(), "");
    }

    private static LogEvent event(String id, String eventType, int secondsAfterBase) {
        return new LogEvent(id, BASE_TIME.plusSeconds(secondsAfterBase), "source-" + eventType,
                eventType, null, null, "", "raw");
    }
}
