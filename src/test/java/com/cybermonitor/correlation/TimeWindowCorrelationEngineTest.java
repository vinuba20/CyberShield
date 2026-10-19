package com.cybermonitor.correlation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimeWindowCorrelationEngineTest {

    private final TimeWindowCorrelationEngine engine =
            new TimeWindowCorrelationEngine(Duration.ofSeconds(300), true, false, false);

    @Test
    void noAlertsGiveNoIncidents() {
        assertTrue(engine.correlate(List.of()).isEmpty());
    }

    @Test
    void aSingleAlertBecomesAnOpenIncident() {
        Incident incident = engine.correlate(List.of(Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 0))).get(0);

        assertEquals(IncidentStatus.OPEN, incident.status());
        assertEquals(1, incident.alerts().size());
        assertEquals("BRUTE_FORCE on 1.1.1.1", incident.title());
        assertTrue(incident.rootCauses().isEmpty());
        assertEquals("", incident.notes());
    }

    @Test
    void alertsFromTheSameSourceInsideTheWindowAreGrouped() {
        List<Incident> incidents = engine.correlate(List.of(
                Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 0),
                Fixtures.alert("FAIL_THEN_SUCCESS", "1.1.1.1", 120)));

        assertEquals(1, incidents.size());
        assertEquals(2, incidents.get(0).alerts().size());
        assertEquals("BRUTE_FORCE + FAIL_THEN_SUCCESS on 1.1.1.1 (2 alerts)", incidents.get(0).title());
    }

    @Test
    void alertsFurtherApartThanTheWindowStaySeparate() {
        assertEquals(2, engine.correlate(List.of(
                Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 0),
                Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 301))).size());
    }

    @Test
    void aGapExactlyEqualToTheWindowIsStillGrouped() {
        assertEquals(1, engine.correlate(List.of(
                Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 0),
                Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 300))).size());
    }

    @Test
    void differentSourcesAreNotGroupedWhenOnlySourceMatches() {
        assertEquals(2, engine.correlate(List.of(
                Fixtures.alert("BRUTE_FORCE", "1.1.1.1", 0),
                Fixtures.alert("BRUTE_FORCE", "2.2.2.2", 1))).size());
    }

    @Test
    void aChainOfAlertsEachCloseToTheNextBecomesOneIncident() {
        List<ThreatAlert> chain = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            chain.add(Fixtures.alert("BRUTE_FORCE", "1.1.1.1", i * 200L)); // spans 1000 s, each gap 200 s
        }

        List<Incident> incidents = engine.correlate(chain);

        assertEquals(1, incidents.size());
        assertEquals(6, incidents.get(0).alerts().size());
    }

    @Test
    void aLateAlertCanBridgeTwoEarlierGroupsIntoOne() {
        // two groups from different sources, then an alert that matches... only one source, so use rule matching
        TimeWindowCorrelationEngine byRule = new TimeWindowCorrelationEngine(Duration.ofSeconds(100), true, true, false);
        List<Incident> incidents = byRule.correlate(List.of(
                Fixtures.alert("X", "A", 0),
                Fixtures.alert("Y", "B", 10),
                Fixtures.alert("X", "B", 50))); // matches A's X by rule, and B's Y by source

        assertEquals(1, incidents.size());
        assertEquals(3, incidents.get(0).alerts().size());
    }

    @Test
    void ruleMatchingGroupsDifferentSourcesWithTheSameRule() {
        TimeWindowCorrelationEngine byRule = new TimeWindowCorrelationEngine(Duration.ofSeconds(100), false, true, false);

        assertEquals(1, byRule.correlate(List.of(
                Fixtures.alert("X", "A", 0), Fixtures.alert("X", "B", 10))).size());
        assertEquals(2, byRule.correlate(List.of(
                Fixtures.alert("X", "A", 0), Fixtures.alert("Y", "A", 10))).size());
    }

    @Test
    void eventTypeMatchingUsesTheEvidenceEvents() {
        TimeWindowCorrelationEngine byType = new TimeWindowCorrelationEngine(Duration.ofSeconds(100), false, false, true);
        ThreatAlert a = Fixtures.alert("X", Severity.LOW, "A", 0, List.of(Fixtures.failed("A", "u", 0)));
        ThreatAlert b = Fixtures.alert("Y", Severity.LOW, "B", 10, List.of(Fixtures.failed("B", "u", 10)));
        ThreatAlert c = Fixtures.alert("Z", Severity.LOW, "C", 20, List.of(Fixtures.ok("C", "u", 20)));

        assertEquals(2, byType.correlate(List.of(a, b, c)).size()); // a+b share LOGIN_FAILED, c is alone
    }

    @Test
    void theIncidentTakesTheHighestSeverityOfItsAlerts() {
        List<Incident> incidents = engine.correlate(List.of(
                Fixtures.alert("A", Severity.LOW, "s", 0, List.of()),
                Fixtures.alert("B", Severity.CRITICAL, "s", 10, List.of()),
                Fixtures.alert("C", Severity.MEDIUM, "s", 20, List.of())));

        assertEquals(Severity.CRITICAL, incidents.get(0).severity());
    }

    @Test
    void everyInputAlertAppearsInExactlyOneIncident() {
        List<ThreatAlert> alerts = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            alerts.add(Fixtures.alert("BRUTE_FORCE", "10.0.0." + (i % 7), i * 97L));
        }

        List<Incident> incidents = engine.correlate(alerts);

        Set<String> seen = new HashSet<>();
        int total = 0;
        for (Incident incident : incidents) {
            for (ThreatAlert alert : incident.alerts()) {
                assertTrue(seen.add(alert.id()), "alert appears twice");
                total++;
            }
        }
        assertEquals(alerts.size(), total);
    }

    @Test
    void unsortedInputGivesTheSameGroupingAndAlertsInTimeOrder() {
        List<Incident> incidents = engine.correlate(List.of(
                Fixtures.alert("B", "s", 100), Fixtures.alert("A", "s", 0), Fixtures.alert("C", "s", 50)));

        assertEquals(1, incidents.size());
        List<ThreatAlert> inOrder = incidents.get(0).alerts();
        assertEquals("A", inOrder.get(0).ruleName());
        assertEquals("C", inOrder.get(1).ruleName());
        assertEquals("B", inOrder.get(2).ruleName());
    }

    @Test
    void incidentsComeOutOldestFirst() {
        List<Incident> incidents = engine.correlate(List.of(
                Fixtures.alert("A", "late", 5000), Fixtures.alert("A", "early", 0)));

        assertEquals("early", incidents.get(0).alerts().get(0).source());
    }

    @Test
    void severalSourcesAreNamedByCount() {
        TimeWindowCorrelationEngine byRule = new TimeWindowCorrelationEngine(Duration.ofSeconds(100), false, true, false);

        Incident incident = byRule.correlate(List.of(
                Fixtures.alert("X", "A", 0), Fixtures.alert("X", "B", 10))).get(0);

        assertEquals("X on 2 sources (2 alerts)", incident.title());
    }

    @Test
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class,
                () -> new TimeWindowCorrelationEngine(Duration.ofSeconds(-1), true, false, false));
        assertThrows(IllegalArgumentException.class,
                () -> new TimeWindowCorrelationEngine(Duration.ofSeconds(10), false, false, false));
        assertThrows(IllegalArgumentException.class,
                () -> new TimeWindowCorrelationEngine(null, true, false, false));
    }
}
