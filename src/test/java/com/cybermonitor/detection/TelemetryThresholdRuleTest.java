package com.cybermonitor.detection;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TelemetryThresholdRuleTest {

    private static final Instant TIMESTAMP = Instant.parse("2026-10-18T10:00:00Z");

    @Test
    void normalReadingDoesNotRaiseAlert() {
        TelemetryThresholdRule rule = rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN);

        assertTrue(rule.evaluate(List.of(event("normal", 9.9))).isEmpty());
    }

    @Test
    void readingAboveThresholdRaisesExplainableAlert() {
        LogEvent event = event("high", 10.1);
        TelemetryThresholdRule rule = rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN);

        List<ThreatAlert> alerts = rule.evaluate(List.of(event));

        assertEquals(1, alerts.size());
        ThreatAlert alert = alerts.getFirst();
        assertEquals(TelemetryThresholdRule.RULE_NAME, alert.ruleName());
        assertEquals(Severity.HIGH, alert.severity());
        assertEquals(TIMESTAMP, alert.timestamp());
        assertEquals("Pump-1", alert.source());
        assertTrue(alert.explanation().contains("10.1"));
        assertTrue(alert.explanation().contains("10.0"));
        assertTrue(alert.explanation().contains("greater than"));
        assertEquals(List.of(event), alert.evidence());
    }

    @Test
    void supportsInclusiveAndExclusiveBoundaryConfiguration() {
        LogEvent boundary = event("boundary", 10.0);
        TelemetryThresholdRule exclusive = rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN);
        TelemetryThresholdRule inclusive = rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN_OR_EQUAL);

        assertTrue(exclusive.evaluate(List.of(boundary)).isEmpty());
        assertEquals(1, inclusive.evaluate(List.of(boundary)).size());
    }

    @Test
    void supportsLowThresholdsAsConfigured() {
        TelemetryThresholdRule rule = rule(2.0, TelemetryThresholdRule.Comparison.LESS_THAN_OR_EQUAL);

        assertEquals(1, rule.evaluate(List.of(event("low", 2.0))).size());
        assertTrue(rule.evaluate(List.of(event("normal", 2.1))).isEmpty());
    }

    @Test
    void ignoresEventsWithoutNumericValues() {
        TelemetryThresholdRule rule = rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN);

        assertTrue(rule.evaluate(List.of(event("alarm", null))).isEmpty());
    }

    @Test
    void rejectsInvalidThresholdsValuesAndBatches() {
        assertThrows(IllegalArgumentException.class,
                () -> rule(Double.NaN, TelemetryThresholdRule.Comparison.GREATER_THAN));
        assertThrows(IllegalArgumentException.class,
                () -> rule(Double.POSITIVE_INFINITY, TelemetryThresholdRule.Comparison.GREATER_THAN));
        assertThrows(IllegalArgumentException.class,
                () -> rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN)
                        .evaluate(List.of(event("invalid", Double.NaN))));
        assertThrows(IllegalArgumentException.class,
                () -> rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN)
                        .evaluate(List.of(event("invalid", Double.NEGATIVE_INFINITY))));
        assertThrows(NullPointerException.class,
                () -> rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN).evaluate(null));
        assertThrows(NullPointerException.class,
                () -> rule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN)
                        .evaluate(java.util.Arrays.asList((LogEvent) null)));
    }

    @Test
    void requiresComparisonAndSeverityConfiguration() {
        assertThrows(NullPointerException.class,
                () -> new TelemetryThresholdRule(10.0, null, Severity.HIGH));
        assertThrows(NullPointerException.class,
                () -> new TelemetryThresholdRule(10.0, TelemetryThresholdRule.Comparison.GREATER_THAN, null));
    }

    private static TelemetryThresholdRule rule(double threshold, TelemetryThresholdRule.Comparison comparison) {
        return new TelemetryThresholdRule(threshold, comparison, Severity.HIGH);
    }

    private static LogEvent event(String id, Double value) {
        return new LogEvent(id, TIMESTAMP, "Pump-1", "PRESSURE", null, value, "reading", "raw");
    }
}
