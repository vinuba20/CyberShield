package com.cybermonitor.detection;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FailThenSuccessRuleTest {

    private final FailThenSuccessRule rule = new FailThenSuccessRule(3, Duration.ofSeconds(60));

    @Test
    void threeFailuresThenASuccessRaiseACriticalAlert() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 5),
                Fixtures.failed("1.1.1.1", "root", 10), Fixtures.ok("1.1.1.1", "root", 20));

        List<ThreatAlert> alerts = rule.evaluate(events);

        assertEquals(1, alerts.size());
        ThreatAlert alert = alerts.get(0);
        assertEquals("FAIL_THEN_SUCCESS", alert.ruleName());
        assertEquals(Severity.CRITICAL, alert.severity());
        assertEquals("1.1.1.1", alert.source());
        assertEquals(4, alert.evidence().size());
        assertEquals(Fixtures.T0.plusSeconds(20), alert.timestamp());
    }

    @Test
    void tooFewFailuresRaiseNothing() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 5),
                Fixtures.ok("1.1.1.1", "root", 20));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void failuresOlderThanTheWindowDoNotCount() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 1),
                Fixtures.failed("1.1.1.1", "root", 2), Fixtures.ok("1.1.1.1", "root", 100));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void successFromAnotherSourceDoesNotCount() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 1),
                Fixtures.failed("1.1.1.1", "root", 2), Fixtures.ok("2.2.2.2", "root", 5));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void successForAnotherUserDoesNotCount() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 1),
                Fixtures.failed("1.1.1.1", "root", 2), Fixtures.ok("1.1.1.1", "alice", 5));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void failuresAfterTheSuccessDoNotCount() {
        List<LogEvent> events = List.of(
                Fixtures.ok("1.1.1.1", "root", 0),
                Fixtures.failed("1.1.1.1", "root", 1), Fixtures.failed("1.1.1.1", "root", 2),
                Fixtures.failed("1.1.1.1", "root", 3));

        assertTrue(rule.evaluate(events).isEmpty());
    }

    @Test
    void aSecondSuccessIsNotReportedAgain() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 1),
                Fixtures.failed("1.1.1.1", "root", 2), Fixtures.ok("1.1.1.1", "root", 5),
                Fixtures.ok("1.1.1.1", "root", 9));

        assertEquals(1, rule.evaluate(events).size());
    }

    @Test
    void unsortedInputIsHandled() {
        List<LogEvent> events = List.of(
                Fixtures.ok("1.1.1.1", "root", 20), Fixtures.failed("1.1.1.1", "root", 10),
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 5));

        assertEquals(1, rule.evaluate(events).size());
    }

    @Test
    void explanationStatesTheNumbers() {
        List<LogEvent> events = List.of(
                Fixtures.failed("1.1.1.1", "root", 0), Fixtures.failed("1.1.1.1", "root", 5),
                Fixtures.failed("1.1.1.1", "root", 10), Fixtures.ok("1.1.1.1", "root", 20));

        String text = rule.evaluate(events).get(0).explanation();

        assertTrue(text.contains("3 failed logins for user root"));
        assertTrue(text.contains("20 s"));
        assertTrue(text.contains("at least 3"));
        assertTrue(text.contains("60 s"));
    }

    @Test
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class, () -> new FailThenSuccessRule(0, Duration.ofSeconds(60)));
        assertThrows(IllegalArgumentException.class, () -> new FailThenSuccessRule(3, Duration.ZERO));
    }
}
