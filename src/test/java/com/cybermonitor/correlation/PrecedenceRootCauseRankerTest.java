package com.cybermonitor.correlation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrecedenceRootCauseRankerTest {

    private static final Instant BASE_TIME = Instant.parse("2026-10-18T10:00:00Z");

    @Test
    void ranksByAveragePrecedenceProbabilityAndReturnsAtMostThree() {
        PrecedenceStatistics statistics = trainedInOrder("A", "B", "C", "D");
        PrecedenceRootCauseRanker ranker = new PrecedenceRootCauseRanker(statistics);

        List<RootCauseCandidate> candidates = ranker.rank(incident("target",
                event("d", "D", 1),
                event("c", "C", 2),
                event("b", "B", 3),
                event("a", "A", 4)));

        assertEquals(3, candidates.size());
        assertEquals(List.of("A", "B", "C"),
                candidates.stream().map(RootCauseCandidate::eventType).toList());
        assertEquals(1.0, candidates.getFirst().score());
    }

    @Test
    void breaksEqualScoresByEarliestTimestamp() {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ofSeconds(5));
        statistics.train(List.of(incident("all-ties",
                event("a", "A", 1),
                event("b", "B", 1))));
        PrecedenceRootCauseRanker ranker = new PrecedenceRootCauseRanker(statistics);

        List<RootCauseCandidate> candidates = ranker.rank(incident("target",
                event("b-target", "B", 1),
                event("a-target", "A", 2)));

        assertEquals(List.of("B", "A"), candidates.stream().map(RootCauseCandidate::eventType).toList());
        assertEquals(0.5, candidates.getFirst().score());
        assertEquals(0.5, candidates.getLast().score());
    }

    @Test
    void returnsNoCandidatesWhenIncidentOrTrainingEvidenceIsInsufficient() {
        PrecedenceRootCauseRanker noTrainingRanker =
                new PrecedenceRootCauseRanker(new PrecedenceStatistics(Duration.ZERO));
        assertTrue(noTrainingRanker.rank(incident("no-training",
                event("a", "A", 1),
                event("b", "B", 2))).isEmpty());

        PrecedenceStatistics statistics = trainedInOrder("A", "B");
        PrecedenceRootCauseRanker ranker = new PrecedenceRootCauseRanker(statistics);
        assertTrue(ranker.rank(incident("one-type", event("a", "A", 1))).isEmpty());
        assertTrue(ranker.rank(incident("empty")).isEmpty());
    }

    @Test
    void returnsNoCandidatesIfAnyRequiredPairLacksTrainingEvidence() {
        PrecedenceStatistics statistics = trainedInOrder("A", "B");
        PrecedenceRootCauseRanker ranker = new PrecedenceRootCauseRanker(statistics);

        assertTrue(ranker.rank(incident("target",
                event("a", "A", 1),
                event("b", "B", 2),
                event("c", "C", 3))).isEmpty());
    }

    @Test
    void explanationsIncludeScoreAndSupportingPairProbabilities() {
        PrecedenceRootCauseRanker ranker =
                new PrecedenceRootCauseRanker(trainedInOrder("PUMP_FAULT", "PRESSURE_HIGH", "RECIPE_ABORT"));

        RootCauseCandidate candidate = ranker.rank(incident("target",
                event("pump", "PUMP_FAULT", 1),
                event("pressure", "PRESSURE_HIGH", 2),
                event("abort", "RECIPE_ABORT", 3))).getFirst();

        assertEquals("PUMP_FAULT", candidate.eventType());
        assertTrue(candidate.explanation().contains("Score 1.0000"));
        assertTrue(candidate.explanation().contains("PUMP_FAULT before PRESSURE_HIGH = 1.0000"));
        assertTrue(candidate.explanation().contains("PUMP_FAULT before RECIPE_ABORT = 1.0000"));
    }

    private static PrecedenceStatistics trainedInOrder(String... eventTypes) {
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);
        LogEvent[] events = new LogEvent[eventTypes.length];
        for (int index = 0; index < eventTypes.length; index++) {
            events[index] = event("training-" + eventTypes[index], eventTypes[index], index + 1);
        }
        statistics.train(List.of(incident("training", events)));
        return statistics;
    }

    private static Incident incident(String id, LogEvent... events) {
        if (events.length == 0) {
            return new Incident(id, "test incident", Severity.LOW, IncidentStatus.OPEN, List.of(), List.of(), "");
        }
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
