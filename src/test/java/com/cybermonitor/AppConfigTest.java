package com.cybermonitor;

import com.cybermonitor.anomaly.RollingZScoreAnomalyDetector;
import com.cybermonitor.config.AppConfig;
import com.cybermonitor.correlation.PrecedenceRootCauseRanker;
import com.cybermonitor.correlation.PrecedenceStatistics;
import com.cybermonitor.correlation.RootCauseRanker;
import com.cybermonitor.detection.TelemetryThresholdRule;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.repository.sqlite.SqliteRootCauseCandidateStore;
import com.cybermonitor.service.StartupCheckService;
import com.cybermonitor.model.ThreatAlert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import java.time.Instant;
import java.time.Duration;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppConfigTest {

    @Test
    void springContextLoadsAndSqliteConnects(@TempDir Path tempDir) {
        Map<String, Object> testProperties =
                Map.of(AppConfig.DB_PATH_PROPERTY, tempDir.resolve("test.db").toString());

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", testProperties));
            context.register(AppConfig.class);
            context.refresh();

            assertTrue(context.getBean(StartupCheckService.class).checkDatabase());
        }
    }

    @Test
    void telemetryThresholdRuleUsesSpringConfiguration(@TempDir Path tempDir) {
        Map<String, Object> testProperties = Map.of(
                AppConfig.DB_PATH_PROPERTY, tempDir.resolve("test.db").toString(),
                AppConfig.TELEMETRY_THRESHOLD_PROPERTY, "10.0",
                AppConfig.TELEMETRY_COMPARISON_PROPERTY, "greater_than",
                AppConfig.TELEMETRY_SEVERITY_PROPERTY, "critical");

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", testProperties));
            context.register(AppConfig.class);
            context.refresh();

            LogEvent event = new LogEvent("e1", Instant.parse("2026-10-18T10:00:00Z"),
                    "Pump-1", "PRESSURE", null, 10.1,
                    "pressure reading", "raw");
            assertEquals(1, context.getBean(TelemetryThresholdRule.class).evaluate(List.of(event)).size());
        }
    }

    @Test
    void rollingZScoreDetectorUsesSpringConfiguration(@TempDir Path tempDir) {
        Map<String, Object> testProperties = Map.of(
                AppConfig.DB_PATH_PROPERTY, tempDir.resolve("test.db").toString(),
                AppConfig.ANOMALY_WINDOW_SIZE_PROPERTY, "4",
                AppConfig.ANOMALY_Z_SCORE_THRESHOLD_PROPERTY, "2.5",
                AppConfig.ANOMALY_SEVERITY_PROPERTY, "medium");

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", testProperties));
            context.register(AppConfig.class);
            context.refresh();

            assertEquals(1, context.getBean(RollingZScoreAnomalyDetector.class)
                    .detect(List.of(
                            new LogEvent("e1", Instant.parse("2026-10-18T10:00:00Z"), "Pump-1",
                                    "PRESSURE", null, 10.0, "reading", "raw"),
                            new LogEvent("e2", Instant.parse("2026-10-18T10:00:01Z"), "Pump-1",
                                    "PRESSURE", null, 10.0, "reading", "raw"),
                            new LogEvent("e3", Instant.parse("2026-10-18T10:00:02Z"), "Pump-1",
                                    "PRESSURE", null, 10.0, "reading", "raw"),
                            new LogEvent("e4", Instant.parse("2026-10-18T10:00:03Z"), "Pump-1",
                                    "PRESSURE", null, 10.0, "reading", "raw"),
                            new LogEvent("e5", Instant.parse("2026-10-18T10:00:04Z"), "Pump-1",
                                    "PRESSURE", null, 20.0, "reading", "raw"))).size());
        }
    }

    @Test
    void precedenceStatisticsUsesSpringSkewConfiguration(@TempDir Path tempDir) {
        Map<String, Object> testProperties = Map.of(
                AppConfig.DB_PATH_PROPERTY, tempDir.resolve("test.db").toString(),
                AppConfig.ROOT_CAUSE_SKEW_TOLERANCE_SECONDS_PROPERTY, "2");

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", testProperties));
            context.register(AppConfig.class);
            context.refresh();

            assertEquals(Duration.ofSeconds(2), context.getBean(PrecedenceStatistics.class).skewTolerance());
            assertTrue(context.getBean(RootCauseRanker.class) instanceof PrecedenceRootCauseRanker);
        }
    }

    @Test
    void springConfiguredSkewTrainingFeedsTheWiredRanker(@TempDir Path tempDir) {
        Map<String, Object> testProperties = Map.of(
                AppConfig.DB_PATH_PROPERTY, tempDir.resolve("test.db").toString(),
                AppConfig.ROOT_CAUSE_SKEW_TOLERANCE_SECONDS_PROPERTY, "2");

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", testProperties));
            context.register(AppConfig.class);
            context.refresh();

            PrecedenceStatistics statistics = context.getBean(PrecedenceStatistics.class);
            statistics.train(List.of(
                    precedenceIncident("within-skew",
                            precedenceEvent("a1", "A", 0),
                            precedenceEvent("b1", "B", 1)),
                    precedenceIncident("at-boundary",
                            precedenceEvent("a2", "A", 10),
                            precedenceEvent("b2", "B", 12))));

            assertEquals(0.75, statistics.probabilityBefore("A", "B").orElseThrow());
            List<RootCauseCandidate> candidates =
                    context.getBean(RootCauseRanker.class).rank(precedenceIncident("query",
                            precedenceEvent("query-a", "A", 20),
                            precedenceEvent("query-b", "B", 21)));
            assertEquals(List.of("A", "B"),
                    candidates.stream().map(RootCauseCandidate::eventType).toList());
            assertEquals(0.75, candidates.getFirst().score());
            assertEquals(0.25, candidates.getLast().score());
        }
    }

    @Test
    void rootCauseCandidateStoreIsAvailableFromSpring(@TempDir Path tempDir) {
        Map<String, Object> testProperties =
                Map.of(AppConfig.DB_PATH_PROPERTY, tempDir.resolve("test.db").toString());

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("test", testProperties));
            context.register(AppConfig.class);
            context.refresh();

            assertTrue(context.getBean(SqliteRootCauseCandidateStore.class)
                    .findByIncidentId("not-yet-persisted").isEmpty());
        }
    }

    private static Incident precedenceIncident(String id, LogEvent... events) {
        List<ThreatAlert> alerts = new ArrayList<>();
        for (int index = 0; index < events.length; index++) {
            LogEvent event = events[index];
            alerts.add(new ThreatAlert(id + "-alert-" + index, "TEST", Severity.LOW,
                    event.timestamp(), event.source(), "test evidence", List.of(event)));
        }
        return new Incident(id, "test incident", Severity.LOW, IncidentStatus.OPEN, alerts, List.of(), "");
    }

    private static LogEvent precedenceEvent(String id, String eventType, long secondsAfterBase) {
        return new LogEvent(id, Instant.parse("2026-10-18T10:00:00Z").plusSeconds(secondsAfterBase),
                "source-" + eventType, eventType, null, null, "test event", "raw");
    }
}
