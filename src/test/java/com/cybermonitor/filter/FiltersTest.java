package com.cybermonitor.filter;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FiltersTest {

    private final ThreatAlert high = Fixtures.alert("BRUTE_FORCE", Severity.HIGH, "10.0.0.5", 100,
            List.of(Fixtures.failed("10.0.0.5", "root", 100)));
    private final ThreatAlert critical = Fixtures.alert("FAIL_THEN_SUCCESS", Severity.CRITICAL, "192.168.1.9", 500,
            List.of(Fixtures.failed("192.168.1.9", "root", 490), Fixtures.ok("192.168.1.9", "root", 500)));
    private final List<ThreatAlert> alerts = List.of(high, critical);

    private AlertFilter filter(Set<Severity> severities, java.time.Instant from, java.time.Instant to,
                               String eventType, String source, String rule) {
        return new AlertFilter(severities, from, to, eventType, source, rule);
    }

    @Test
    void anyFilterKeepsEverything() {
        assertEquals(alerts, AlertFilter.ANY.apply(alerts));
    }

    @Test
    void filtersBySeverity() {
        assertEquals(List.of(critical), filter(Set.of(Severity.CRITICAL), null, null, null, null, null).apply(alerts));
        assertEquals(alerts, filter(Set.of(Severity.HIGH, Severity.CRITICAL), null, null, null, null, null).apply(alerts));
        assertTrue(filter(Set.of(Severity.LOW), null, null, null, null, null).apply(alerts).isEmpty());
    }

    @Test
    void sourceMatchIsPartialAndIgnoresCase() {
        assertEquals(List.of(high), filter(null, null, null, null, "10.0.", null).apply(alerts));
        assertEquals(List.of(critical), filter(null, null, null, null, " 192.168 ", null).apply(alerts));
    }

    @Test
    void ruleNameMustMatchIgnoringCase() {
        assertEquals(List.of(high), filter(null, null, null, null, null, "brute_force").apply(alerts));
        assertTrue(filter(null, null, null, null, null, "BRUTE").apply(alerts).isEmpty());
    }

    @Test
    void eventTypeLooksAtTheEvidence() {
        assertEquals(List.of(critical), filter(null, null, null, "LOGIN_OK", null, null).apply(alerts));
        assertEquals(alerts, filter(null, null, null, "login_failed", null, null).apply(alerts));
    }

    @Test
    void timeRangeIsInclusiveAtBothEnds() {
        var t100 = Fixtures.T0.plusSeconds(100);
        var t500 = Fixtures.T0.plusSeconds(500);

        assertEquals(alerts, filter(null, t100, t500, null, null, null).apply(alerts));
        assertEquals(List.of(critical), filter(null, t100.plusMillis(1), null, null, null, null).apply(alerts));
        assertEquals(List.of(high), filter(null, null, t500.minusMillis(1), null, null, null).apply(alerts));
    }

    @Test
    void criteriaAreCombinedWithAnd() {
        assertTrue(filter(Set.of(Severity.CRITICAL), null, null, null, "10.0.", null).apply(alerts).isEmpty());
    }

    @Test
    void fromAfterToIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> filter(null,
                Fixtures.T0.plusSeconds(10), Fixtures.T0, null, null, null));
    }

    private Incident incident(Severity severity, IncidentStatus status, ThreatAlert... members) {
        return new Incident(UUID.randomUUID().toString(), "title", severity, status, List.of(members), List.of(), "");
    }

    @Test
    void incidentFilterByStatusAndSeverity() {
        Incident open = incident(Severity.HIGH, IncidentStatus.OPEN, high);
        Incident resolved = incident(Severity.CRITICAL, IncidentStatus.RESOLVED, critical);
        List<Incident> all = List.of(open, resolved);

        assertEquals(List.of(resolved), new IncidentFilter(Set.of(IncidentStatus.RESOLVED), null, null).apply(all));
        assertEquals(List.of(open), new IncidentFilter(null, Set.of(Severity.HIGH), null).apply(all));
        assertEquals(all, IncidentFilter.ANY.apply(all));
    }

    @Test
    void incidentFilterByAlertCriteriaNeedsOneAlertThatMatchesAll() {
        Incident mixed = incident(Severity.CRITICAL, IncidentStatus.OPEN, high, critical);
        AlertFilter wantsHighSourceAndCriticalRule =
                filter(null, null, null, null, "10.0.", "FAIL_THEN_SUCCESS");

        assertFalse(new IncidentFilter(null, null, wantsHighSourceAndCriticalRule).matches(mixed));
        assertTrue(new IncidentFilter(null, null, filter(null, null, null, null, "10.0.", null)).matches(mixed));
    }

    @Test
    void incidentFilterIgnoresTheSeveritySetInsideTheAlertCriteria() {
        Incident incident = incident(Severity.CRITICAL, IncidentStatus.OPEN, high);
        AlertFilter inner = filter(Set.of(Severity.CRITICAL), null, null, null, "10.0.", null);

        assertTrue(new IncidentFilter(null, null, inner).matches(incident)); // alert is HIGH, but only incident severity counts
    }
}
