package com.cybermonitor.service;

import com.cybermonitor.correlation.RootCauseRanker;
import com.cybermonitor.correlation.TimeWindowCorrelationEngine;
import com.cybermonitor.detection.BruteForceRule;
import com.cybermonitor.detection.DefaultDetectionEngine;
import com.cybermonitor.detection.FailThenSuccessRule;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.parser.AuthLogParser;
import com.cybermonitor.testutil.InMemoryRepositories;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PipelineServiceTest {

    private final InMemoryRepositories.Events events = new InMemoryRepositories.Events();
    private final InMemoryRepositories.Alerts alerts = new InMemoryRepositories.Alerts();
    private final InMemoryRepositories.Incidents incidents = new InMemoryRepositories.Incidents();

    private PipelineService pipeline(RootCauseRanker ranker) {
        return new PipelineService(new LogImportService(), events,
                new DefaultDetectionEngine(List.of(new BruteForceRule(5, Duration.ofSeconds(10)),
                        new FailThenSuccessRule(3, Duration.ofSeconds(60))), List.of()),
                alerts, new TimeWindowCorrelationEngine(Duration.ofSeconds(300), true, false, false),
                incidents, ranker);
    }

    @Test
    void theSampleFileGoesThroughTheWholePipelineAsDocumented() {
        PipelineResult result = pipeline(null).importFile(Path.of("data/sample/auth_sample.log"), new AuthLogParser());

        assertEquals(22, result.imported().importedLines());
        assertEquals(2, result.imported().malformedLines());
        assertEquals(4, result.alerts().size());
        assertEquals(3, result.incidents().size());
        assertEquals(22, events.count());
        assertEquals(4, alerts.stored.size());
        assertEquals(3, incidents.stored.size());
    }

    @Test
    void theBruteForceAndCompromiseAlertsFromOneAddressShareAnIncident() {
        PipelineResult result = pipeline(null).importFile(Path.of("data/sample/auth_sample.log"), new AuthLogParser());

        Incident merged = result.incidents().stream()
                .filter(i -> i.alerts().size() == 2).findFirst().orElseThrow();

        assertEquals("BRUTE_FORCE + FAIL_THEN_SUCCESS on 203.0.113.5 (2 alerts)", merged.title());
    }

    @Test
    void anOptionalRankerFillsInRootCausesBeforeSaving() {
        RootCauseRanker ranker = incident -> List.of(new RootCauseCandidate("LOGIN_FAILED", "x", 0.8, "first"));

        PipelineResult result = pipeline(ranker).importFile(Path.of("data/sample/auth_sample.log"), new AuthLogParser());

        assertTrue(result.incidents().stream().allMatch(i -> i.rootCauses().size() == 1));
        assertTrue(incidents.stored.values().stream().allMatch(i -> i.rootCauses().size() == 1));
    }

    @Test
    void aRankerThatFailsDoesNotStopTheImport() {
        RootCauseRanker broken = incident -> {
            throw new IllegalStateException("boom");
        };

        PipelineResult result = pipeline(broken).importFile(Path.of("data/sample/auth_sample.log"), new AuthLogParser());

        assertEquals(3, result.incidents().size());
        assertTrue(result.incidents().stream().allMatch(i -> i.rootCauses().isEmpty()));
    }

    @Test
    void aFileWithNoValidEventsGivesAnEmptyResult() {
        ImportResult empty = new LogImportService().importLines("x.log", List.of("garbage"), new AuthLogParser());

        PipelineResult result = pipeline(null).process(empty);

        assertTrue(result.alerts().isEmpty());
        assertTrue(result.incidents().isEmpty());
        assertEquals(0, events.count());
    }
}
