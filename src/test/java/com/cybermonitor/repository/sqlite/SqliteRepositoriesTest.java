package com.cybermonitor.repository.sqlite;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Needs the real SQLite JDBC driver, so it runs under Maven (not in the stand-in runner). */
class SqliteRepositoriesTest {

    private SqliteConnectionFactory database(Path folder) {
        SqliteConnectionFactory connections = new SqliteConnectionFactory(folder.resolve("test.db"));
        new SchemaInitializer(connections).initialize();
        return connections;
    }

    @Test
    void schemaCanBeCreatedTwice(@TempDir Path folder) {
        SqliteConnectionFactory connections = database(folder);

        new SchemaInitializer(connections).initialize(); // must not fail
    }

    @Test
    void eventsRoundTripIncludingNullsAndValues(@TempDir Path folder) {
        SqliteEventRepository repository = new SqliteEventRepository(database(folder));
        LogEvent plain = Fixtures.failed("1.1.1.1", "root", 0);
        LogEvent reading = new LogEvent("e-reading", Instant.parse("2026-01-01T10:00:00.250Z"), "Pump-1",
                "THRESHOLD_HIGH", null, 7.25, "pressure, high", "raw,line \"quoted\"");

        repository.saveAll(List.of(plain, reading));

        assertEquals(2, repository.count());
        List<LogEvent> loaded = repository.findAll();
        assertTrue(loaded.contains(plain));
        assertTrue(loaded.contains(reading));
        LogEvent back = loaded.stream().filter(e -> e.id().equals("e-reading")).findFirst().orElseThrow();
        assertNull(back.user());
        assertEquals(7.25, back.value(), 0.0);
        assertEquals(Instant.parse("2026-01-01T10:00:00.250Z"), back.timestamp());
    }

    @Test
    void savingTheSameEventIdReplacesIt(@TempDir Path folder) {
        SqliteEventRepository repository = new SqliteEventRepository(database(folder));
        LogEvent event = Fixtures.failed("1.1.1.1", "root", 0);

        repository.saveAll(List.of(event));
        repository.saveAll(List.of(event));

        assertEquals(1, repository.count());
    }

    @Test
    void aFailedBatchRollsBackCompletely(@TempDir Path folder) {
        SqliteEventRepository repository = new SqliteEventRepository(database(folder));
        LogEvent good = Fixtures.failed("1.1.1.1", "root", 0);
        // two different events with a null id are impossible to build, so break the batch another way:
        // use a table that does not exist to make the second step of a transaction fail.
        assertThrows(RuntimeException.class, () -> Transactions.inTransaction(
                new SqliteConnectionFactory(folder.resolve("test.db")), "test", connection -> {
                    SqliteEventRepository.insertEvents(connection, List.of(good));
                    connection.createStatement().execute("INSERT INTO no_such_table VALUES (1)");
                }));

        assertEquals(0, repository.count());
    }

    @Test
    void alertsRoundTripWithTheirEvidence(@TempDir Path folder) {
        SqliteAlertRepository repository = new SqliteAlertRepository(database(folder));
        LogEvent f1 = Fixtures.failed("1.1.1.1", "root", 0);
        LogEvent f2 = Fixtures.failed("1.1.1.1", "root", 3);
        ThreatAlert alert = Fixtures.alert("BRUTE_FORCE", Severity.HIGH, "1.1.1.1", 3, List.of(f1, f2));

        repository.saveAll(List.of(alert));

        ThreatAlert loaded = repository.findById(alert.id()).orElseThrow();
        assertEquals(alert, loaded);
        assertEquals(List.of(f1, f2), loaded.evidence());
        assertEquals(1, repository.findAll().size());
        assertTrue(repository.findById("nope").isEmpty());
    }

    @Test
    void savingAnAlertAgainReplacesItsEvidence(@TempDir Path folder) {
        SqliteAlertRepository repository = new SqliteAlertRepository(database(folder));
        LogEvent f1 = Fixtures.failed("1.1.1.1", "root", 0);
        LogEvent f2 = Fixtures.failed("1.1.1.1", "root", 3);
        ThreatAlert alert = Fixtures.alert("BRUTE_FORCE", Severity.HIGH, "1.1.1.1", 3, List.of(f1, f2));
        repository.saveAll(List.of(alert));

        ThreatAlert smaller = new ThreatAlert(alert.id(), alert.ruleName(), alert.severity(), alert.timestamp(),
                alert.source(), alert.explanation(), List.of(f1));
        repository.saveAll(List.of(smaller));

        assertEquals(1, repository.findAll().size());
        assertEquals(1, repository.findById(alert.id()).orElseThrow().evidence().size());
    }

    @Test
    void incidentsRoundTripWithAlertsRootCausesStatusAndNotes(@TempDir Path folder) {
        SqliteConnectionFactory connections = database(folder);
        SqliteAlertRepository alerts = new SqliteAlertRepository(connections);
        SqliteIncidentRepository repository = new SqliteIncidentRepository(connections, alerts);
        ThreatAlert first = Fixtures.alert("A", Severity.HIGH, "s", 0, List.of(Fixtures.failed("s", "u", 0)));
        ThreatAlert second = Fixtures.alert("B", Severity.CRITICAL, "s", 50, List.of());
        Incident incident = new Incident("i1", "A + B on s", Severity.CRITICAL, IncidentStatus.INVESTIGATING,
                List.of(first, second),
                List.of(new RootCauseCandidate("PUMP_FAULT", "Pump-1", 0.9, "first"),
                        new RootCauseCandidate("VALVE_STUCK", "Valve-2", 0.4, "second")),
                "multi\nline note, with comma");

        repository.save(incident);

        Incident loaded = repository.findById("i1").orElseThrow();
        assertEquals(incident, loaded);
        assertEquals(List.of(first, second), loaded.alerts());      // order kept
        assertEquals("PUMP_FAULT", loaded.rootCauses().get(0).eventType()); // rank kept
    }

    @Test
    void savingAnIncidentAgainUpdatesStatusAndNotesWithoutDuplicates(@TempDir Path folder) {
        SqliteConnectionFactory connections = database(folder);
        SqliteIncidentRepository repository = new SqliteIncidentRepository(connections,
                new SqliteAlertRepository(connections));
        Incident incident = new Incident("i1", "t", Severity.HIGH, IncidentStatus.OPEN,
                List.of(Fixtures.alert("A", Severity.HIGH, "s", 0, List.of())), List.of(), "");
        repository.save(incident);

        repository.save(incident.withStatus(IncidentStatus.RESOLVED).withNotes("done"));

        List<Incident> all = repository.findAll();
        assertEquals(1, all.size());
        assertEquals(IncidentStatus.RESOLVED, all.get(0).status());
        assertEquals("done", all.get(0).notes());
        assertEquals(1, all.get(0).alerts().size());
    }

    @Test
    void dataSurvivesReopeningTheDatabaseFile(@TempDir Path folder) {
        SqliteConnectionFactory first = database(folder);
        SqliteAlertRepository alerts = new SqliteAlertRepository(first);
        new SqliteIncidentRepository(first, alerts).save(new Incident("i1", "t", Severity.LOW, IncidentStatus.OPEN,
                List.of(Fixtures.alert("A", Severity.LOW, "s", 0, List.of(Fixtures.failed("s", "u", 0)))),
                List.of(), "kept"));

        SqliteConnectionFactory second = database(folder); // a "restart"
        List<Incident> reloaded = new SqliteIncidentRepository(second, new SqliteAlertRepository(second)).findAll();

        assertEquals(1, reloaded.size());
        assertEquals("kept", reloaded.get(0).notes());
        assertEquals(1, reloaded.get(0).alerts().get(0).evidence().size());
    }

    @Test
    void hostileTextIsStoredAsDataNotExecuted(@TempDir Path folder) {
        SqliteConnectionFactory connections = database(folder);
        SqliteEventRepository repository = new SqliteEventRepository(connections);
        String attack = "x'); DROP TABLE events; --";
        LogEvent event = new LogEvent("e1", Fixtures.T0, attack, "LOGIN_FAILED", attack, null, attack, attack);

        repository.saveAll(List.of(event));

        assertEquals(List.of(event), repository.findAll());
    }
}
