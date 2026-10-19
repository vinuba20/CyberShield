package com.cybermonitor.service;

import com.cybermonitor.filter.AlertFilter;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import com.cybermonitor.testutil.InMemoryRepositories;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertServiceTest {

    private final InMemoryRepositories.Alerts repository = new InMemoryRepositories.Alerts();
    private final AlertService service = new AlertService(repository);

    @Test
    void searchAppliesTheFilterAndSortsMostSevereThenNewest() {
        ThreatAlert lowNew = Fixtures.alert("A", Severity.LOW, "s", 900, List.of());
        ThreatAlert highOld = Fixtures.alert("B", Severity.HIGH, "s", 10, List.of());
        ThreatAlert highNew = Fixtures.alert("C", Severity.HIGH, "s", 500, List.of());
        repository.saveAll(List.of(lowNew, highOld, highNew));

        assertEquals(List.of(highNew, highOld, lowNew), service.listAlerts());
        assertEquals(List.of(highNew, highOld), service.search(
                new AlertFilter(Set.of(Severity.HIGH), null, null, null, null, null)));
    }

    @Test
    void findAlertReturnsEmptyForUnknownIds() {
        assertTrue(service.findAlert("nope").isEmpty());
    }
}
