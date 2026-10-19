package com.cybermonitor.detection;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BruteForceRuleTest {

    private final BruteForceRule rule = new BruteForceRule(5, Duration.ofSeconds(10));

    private List<LogEvent> failures(String source, int count, long firstSecond, long gapSeconds) {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            events.add(Fixtures.failed(source, "admin", firstSecond + i * gapSeconds));
        }
        return events;
    }

    @Test
    void exactlyThresholdFailuresInsideTheWindowRaiseOneAlert() {
        List<ThreatAlert> alerts = rule.evaluate(failures("10.0.0.5", 5, 0, 2)); // spans 8 s

        assertEquals(1, alerts.size());
        ThreatAlert alert = alerts.get(0);
        assertEquals("BRUTE_FORCE", alert.ruleName());
        assertEquals("10.0.0.5", alert.source());
        assertEquals(5, alert.evidence().size());
        assertEquals(Severity.HIGH, alert.severity());
        assertEquals(Fixtures.T0.plusSeconds(8), alert.timestamp());
    }

    @Test
    void oneFailureLessThanTheThresholdRaisesNothing() {
        assertTrue(rule.evaluate(failures("10.0.0.5", 4, 0, 1)).isEmpty());
    }

    @Test
    void failuresSpreadOverMoreThanTheWindowRaiseNothing() {
        assertTrue(rule.evaluate(failures("10.0.0.5", 8, 0, 3)).isEmpty()); // only 4 fit in any 10 s
    }

    @Test
    void windowEdgeIsInclusive() {
        // first at 0 s, fifth at exactly 10 s
        List<LogEvent> events = List.of(
                Fixtures.failed("a", "u", 0), Fixtures.failed("a", "u", 2), Fixtures.failed("a", "u", 4),
                Fixtures.failed("a", "u", 6), Fixtures.failed("a", "u", 10));

        assertEquals(1, rule.evaluate(events).size());
    }

    @Test
    void justOutsideTheWindowIsNotCounted() {
        List<LogEvent> events = List.of(
                Fixtures.failed("a", "u", 0), Fixtures.failed("a", "u", 2), Fixtures.failed("a", "u", 4),
                Fixtures.failed("a", "u", 6), Fixtures.failed("a", "u", 11));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void aLongBurstIsReportedOnceWithAllItsFailures() {
        List<ThreatAlert> alerts = rule.evaluate(failures("10.0.0.5", 9, 0, 1)); // 9 failures in 8 s

        assertEquals(1, alerts.size());
        assertEquals(9, alerts.get(0).evidence().size());
    }

    @Test
    void doubleTheThresholdIsCritical() {
        List<ThreatAlert> alerts = rule.evaluate(failures("10.0.0.5", 10, 0, 1));

        assertEquals(Severity.CRITICAL, alerts.get(0).severity());
    }

    @Test
    void differentSourcesAreCountedSeparately() {
        List<LogEvent> events = new ArrayList<>();
        events.addAll(failures("10.0.0.5", 3, 0, 1));
        events.addAll(failures("10.0.0.6", 3, 0, 1)); // 6 failures in total, but only 3 per source

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void twoSourcesAttackingAtOnceGiveTwoAlerts() {
        List<LogEvent> events = new ArrayList<>();
        events.addAll(failures("10.0.0.5", 6, 0, 1));
        events.addAll(failures("10.0.0.6", 6, 0, 1));

        assertEquals(2, rule.evaluate(events).size());
    }

    @Test
    void twoSeparateBurstsFromOneSourceGiveTwoAlerts() {
        List<LogEvent> events = new ArrayList<>();
        events.addAll(failures("10.0.0.5", 5, 0, 1));
        events.addAll(failures("10.0.0.5", 5, 600, 1));

        assertEquals(2, rule.evaluate(events).size());
    }

    @Test
    void inputOrderDoesNotMatter() {
        List<LogEvent> events = failures("10.0.0.5", 6, 0, 1);
        Collections.reverse(events);

        assertEquals(1, rule.evaluate(events).size());
    }

    @Test
    void successfulLoginsAreNotCounted() {
        List<LogEvent> events = new ArrayList<>(failures("10.0.0.5", 4, 0, 1));
        events.add(Fixtures.ok("10.0.0.5", "admin", 5));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void explanationStatesObservedValueThresholdAndUsers() {
        String text = rule.evaluate(failures("10.0.0.5", 6, 0, 1)).get(0).explanation();

        assertTrue(text.contains("6 failed logins"));
        assertTrue(text.contains("10.0.0.5"));
        assertTrue(text.contains("at least 5"));
        assertTrue(text.contains("10 s"));
        assertTrue(text.contains("admin"));
    }

    @Test
    void emptyInputGivesNoAlerts() {
        assertTrue(rule.evaluate(List.of()).isEmpty());
    }

    @Test
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class, () -> new BruteForceRule(1, Duration.ofSeconds(10)));
        assertThrows(IllegalArgumentException.class, () -> new BruteForceRule(5, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new BruteForceRule(5, Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> new BruteForceRule(5, null));
    }

    @Test
    void ruleNameIsStable() {
        assertEquals("BRUTE_FORCE", rule.name());
    }
}
