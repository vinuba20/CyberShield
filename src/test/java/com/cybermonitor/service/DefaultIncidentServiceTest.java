package com.cybermonitor.service;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.Severity;
import com.cybermonitor.testutil.Fixtures;
import com.cybermonitor.testutil.InMemoryRepositories;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultIncidentServiceTest {

    private final InMemoryRepositories.Incidents repository = new InMemoryRepositories.Incidents();
    private final Clock clock = Clock.fixed(Instant.parse("2026-02-03T04:05:06Z"), ZoneOffset.UTC);
    private final DefaultIncidentService service = new DefaultIncidentService(repository, clock);

    private Incident stored(String id, Severity severity, long alertSecond) {
        Incident incident = new Incident(id, "title " + id, severity, IncidentStatus.OPEN,
                List.of(Fixtures.alert("R", "s", alertSecond)), List.of(), "");
        repository.save(incident);
        return incident;
    }

    @Test
    void listsMostSevereFirstThenNewestFirst() {
        stored("low-new", Severity.LOW, 500);
        stored("crit-old", Severity.CRITICAL, 10);
        stored("high-old", Severity.HIGH, 10);
        stored("high-new", Severity.HIGH, 900);

        List<String> order = service.listIncidents().stream().map(Incident::id).toList();

        assertEquals(List.of("crit-old", "high-new", "high-old", "low-new"), order);
    }

    @Test
    void changeStatusSavesAndReturnsTheUpdatedIncident() {
        stored("i1", Severity.HIGH, 0);

        Incident updated = service.changeStatus("i1", IncidentStatus.INVESTIGATING);

        assertEquals(IncidentStatus.INVESTIGATING, updated.status());
        assertEquals(IncidentStatus.INVESTIGATING, repository.findById("i1").orElseThrow().status());
    }

    @Test
    void anyStatusCanFollowAnyStatus() {
        stored("i1", Severity.HIGH, 0);

        service.changeStatus("i1", IncidentStatus.RESOLVED);
        Incident reopened = service.changeStatus("i1", IncidentStatus.OPEN);

        assertEquals(IncidentStatus.OPEN, reopened.status());
    }

    @Test
    void notesAreStampedAndAppended() {
        stored("i1", Severity.HIGH, 0);

        service.addNote("i1", "  Checked the firewall  ");
        Incident updated = service.addNote("i1", "Blocked 203.0.113.5");

        assertEquals("[2026-02-03 04:05 UTC] Checked the firewall\n[2026-02-03 04:05 UTC] Blocked 203.0.113.5",
                updated.notes());
    }

    @Test
    void blankNotesAreRejected() {
        stored("i1", Severity.HIGH, 0);

        assertThrows(IllegalArgumentException.class, () -> service.addNote("i1", "   "));
        assertThrows(IllegalArgumentException.class, () -> service.addNote("i1", null));
        assertEquals("", repository.findById("i1").orElseThrow().notes());
    }

    @Test
    void unknownIdsGiveACyberShieldException() {
        assertThrows(CyberShieldException.class, () -> service.changeStatus("nope", IncidentStatus.RESOLVED));
        assertThrows(CyberShieldException.class, () -> service.addNote("nope", "hello"));
        assertTrue(service.findIncident("nope").isEmpty());
    }

    @Test
    void changingStatusKeepsAlertsAndNotes() {
        stored("i1", Severity.HIGH, 0);
        service.addNote("i1", "note");

        Incident updated = service.changeStatus("i1", IncidentStatus.RESOLVED);

        assertEquals(1, updated.alerts().size());
        assertTrue(updated.notes().contains("note"));
    }
}
