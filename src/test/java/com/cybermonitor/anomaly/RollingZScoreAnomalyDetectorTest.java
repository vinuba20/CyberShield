package com.cybermonitor.anomaly;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RollingZScoreAnomalyDetectorTest {

    private static final Instant BASE_TIME = Instant.parse("2026-10-18T10:00:00Z");

    @Test
    void normalReadingsDoNotProduceAnomalyAlerts() {
        RollingZScoreAnomalyDetector detector = detector(3, 2.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("a", 1, 10.0),
                event("b", 2, 11.0),
                event("c", 3, 9.0),
                event("d", 4, 10.5)));

        assertTrue(alerts.isEmpty());
    }

    @Test
    void anomalousReadingExplainsObservedValueBaselineAndZScore() {
        LogEvent spike = event("spike", 4, 20.0);
        RollingZScoreAnomalyDetector detector = detector(3, 2.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("a", 1, 10.0),
                event("b", 2, 10.0),
                event("c", 3, 10.0),
                spike));

        assertEquals(1, alerts.size());
        ThreatAlert alert = alerts.getFirst();
        assertEquals(RollingZScoreAnomalyDetector.DETECTOR_NAME, alert.ruleName());
        assertEquals(Severity.HIGH, alert.severity());
        assertEquals(spike.timestamp(), alert.timestamp());
        assertEquals(spike.source(), alert.source());
        assertEquals(List.of(spike), alert.evidence());
        assertTrue(alert.explanation().contains("Observed value 20.0"));
        assertTrue(alert.explanation().contains("rolling mean 10.0"));
        assertTrue(alert.explanation().contains("standard deviation 0.0"));
        assertTrue(alert.explanation().contains("z-score Infinity"));
        assertTrue(alert.explanation().contains("threshold 2.0"));
    }

    @Test
    void doesNotEvaluateUntilFullPriorWindowExists() {
        RollingZScoreAnomalyDetector detector = detector(3, 1.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("a", 1, 10.0),
                event("b", 2, 10.0),
                event("c", 3, 20.0)));

        assertTrue(alerts.isEmpty());
    }

    @Test
    void ignoresEventsWithoutNumericValues() {
        RollingZScoreAnomalyDetector detector = detector(2, 2.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("missing", 1, null),
                event("a", 2, 10.0),
                event("b", 3, 10.0),
                event("spike", 4, 20.0)));

        assertEquals(1, alerts.size());
        assertEquals("spike", alerts.getFirst().evidence().getFirst().id());
    }

    @Test
    void zeroStandardDeviationFlagsDifferentReadingButNotEqualReading() {
        RollingZScoreAnomalyDetector detector = detector(2, 1.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("a", 1, 5.0),
                event("b", 2, 5.0),
                event("equal", 3, 5.0),
                event("different", 4, 6.0)));

        assertEquals(1, alerts.size());
        assertEquals("different", alerts.getFirst().evidence().getFirst().id());
    }

    @Test
    void usesOnlyPreviousReadingsAndOrdersUnsortedInputChronologically() {
        RollingZScoreAnomalyDetector detector = detector(2, 1.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("future", 4, 100.0),
                event("middle", 2, 10.0),
                event("late", 3, 10.0),
                event("early", 1, 10.0)));

        assertEquals(1, alerts.size());
        assertEquals("future", alerts.getFirst().evidence().getFirst().id());
    }

    @Test
    void rollsOutValuesOlderThanTheConfiguredWindow() {
        RollingZScoreAnomalyDetector detector = detector(2, 1.1);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("old", 1, 0.0),
                event("a", 2, 10.0),
                event("b", 3, 10.0),
                event("equal", 4, 10.0),
                event("spike", 5, 20.0)));

        assertEquals(1, alerts.size());
        assertEquals("spike", alerts.getFirst().evidence().getFirst().id());
        assertTrue(alerts.getFirst().explanation().contains("rolling mean 10.0"));
    }

    @Test
    void eventsWithSameTimestampDoNotUseEachOtherAsHistory() {
        RollingZScoreAnomalyDetector detector = detector(2, 2.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("a", 1, 10.0),
                event("b", 2, 10.0),
                event("same-time-spike-a", 3, 20.0),
                event("same-time-spike-b", 3, 20.0)));

        assertEquals(2, alerts.size());
        assertTrue(alerts.stream().allMatch(alert -> alert.timestamp().equals(event("x", 3, 0.0).timestamp())));
    }

    @Test
    void separatesHistoriesBySourceAndEventType() {
        RollingZScoreAnomalyDetector detector = detector(2, 1.0);

        List<ThreatAlert> alerts = detector.detect(List.of(
                event("pump-a-1", 1, 10.0, "Pump-A", "PRESSURE"),
                event("pump-a-2", 2, 10.0, "Pump-A", "PRESSURE"),
                event("pump-b-spike", 3, 20.0, "Pump-B", "PRESSURE"),
                event("temperature", 4, 20.0, "Pump-A", "TEMPERATURE")));

        assertTrue(alerts.isEmpty());
    }

    @Test
    void rejectsInvalidSettingsAndInputs() {
        assertThrows(IllegalArgumentException.class, () -> detector(0, 2.0));
        assertThrows(IllegalArgumentException.class, () -> detector(2, 0.0));
        assertThrows(IllegalArgumentException.class, () -> detector(2, Double.NaN));
        assertThrows(NullPointerException.class,
                () -> new RollingZScoreAnomalyDetector(2, 2.0, null));
        assertThrows(NullPointerException.class, () -> detector(2, 2.0).detect(null));
        assertThrows(NullPointerException.class,
                () -> detector(2, 2.0).detect(java.util.Arrays.asList((LogEvent) null)));
        assertThrows(IllegalArgumentException.class,
                () -> detector(2, 2.0).detect(List.of(event("invalid", 1, Double.POSITIVE_INFINITY))));
    }

    private static RollingZScoreAnomalyDetector detector(int windowSize, double zScoreThreshold) {
        return new RollingZScoreAnomalyDetector(windowSize, zScoreThreshold, Severity.HIGH);
    }

    private static LogEvent event(String id, int secondsAfterBase, Double value) {
        return event(id, secondsAfterBase, value, "Pump-1", "PRESSURE");
    }

    private static LogEvent event(
            String id, int secondsAfterBase, Double value, String source, String eventType) {
        return new LogEvent(id, BASE_TIME.plusSeconds(secondsAfterBase), source, eventType, null, value,
                "reading", "raw");
    }
}
