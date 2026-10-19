package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.RootCauseCandidate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqliteRootCauseCandidateStoreTest {

    @Test
    void savesAndReloadsCandidateFieldsAcrossStoreInstances(@TempDir Path tempDir) {
        Path database = tempDir.resolve("candidate-store.db");
        SqliteRootCauseCandidateStore firstStore =
                new SqliteRootCauseCandidateStore(new SqliteConnectionFactory(database));
        List<RootCauseCandidate> candidates = List.of(
                candidate("PUMP_FAULT", "Pump-1", 0.95, "Precedes pressure alarms"),
                candidate("PRESSURE_HIGH", "Pump-1", 0.65, "Follows pump fault"));
        firstStore.saveAll("incident-1", candidates);

        SqliteRootCauseCandidateStore reopenedStore =
                new SqliteRootCauseCandidateStore(new SqliteConnectionFactory(database));

        assertEquals(candidates, reopenedStore.findByIncidentId("incident-1"));
    }

    @Test
    void savesMultipleCandidateRanksInProvidedOrder(@TempDir Path tempDir) {
        SqliteRootCauseCandidateStore store = store(tempDir);
        List<RootCauseCandidate> candidates = List.of(
                candidate("ROOT", "Pump-1", 0.9, "first"),
                candidate("NEXT", "Pump-1", 0.7, "second"),
                candidate("LAST", "Recipe-1", 0.4, "third"));

        store.saveAll("incident-2", candidates);

        assertEquals(candidates, store.findByIncidentId("incident-2"));
    }

    @Test
    void returnsEmptyForUnknownIncidentAndClearsWhenSavedWithNoCandidates(@TempDir Path tempDir) {
        SqliteRootCauseCandidateStore store = store(tempDir);

        assertTrue(store.findByIncidentId("missing").isEmpty());
        store.saveAll("incident-3", List.of(candidate("ROOT", "Pump-1", 1.0, "cause")));
        store.saveAll("incident-3", List.of());

        assertTrue(store.findByIncidentId("incident-3").isEmpty());
    }

    @Test
    void isolatesCandidatesByIncidentId(@TempDir Path tempDir) {
        SqliteRootCauseCandidateStore store = store(tempDir);
        List<RootCauseCandidate> candidate = List.of(candidate("ROOT", "Pump-1", 1.0, "cause"));

        store.saveAll("incident-a", candidate);

        assertEquals(candidate, store.findByIncidentId("incident-a"));
        assertTrue(store.findByIncidentId("incident-b").isEmpty());
    }

    @Test
    void rejectsInvalidInput(@TempDir Path tempDir) {
        SqliteRootCauseCandidateStore store = store(tempDir);

        assertThrows(NullPointerException.class, () -> store.saveAll(null, List.of()));
        assertThrows(IllegalArgumentException.class, () -> store.saveAll(" ", List.of()));
        assertThrows(NullPointerException.class, () -> store.saveAll("incident", null));
        assertThrows(NullPointerException.class,
                () -> store.saveAll("incident", java.util.Arrays.asList((RootCauseCandidate) null)));
        assertThrows(NullPointerException.class, () -> store.findByIncidentId(null));
        assertThrows(IllegalArgumentException.class, () -> store.findByIncidentId(""));
        assertThrows(IllegalArgumentException.class,
                () -> candidate("ROOT", "Pump-1", 1.1, "invalid score"));
    }

    @Test
    void wrapsDatabaseInitializationFailuresInProjectException(@TempDir Path tempDir) {
        assertThrows(CyberShieldException.class,
                () -> new SqliteRootCauseCandidateStore(new SqliteConnectionFactory(tempDir)));
    }

    private static SqliteRootCauseCandidateStore store(Path tempDir) {
        return new SqliteRootCauseCandidateStore(
                new SqliteConnectionFactory(tempDir.resolve("candidate-store.db")));
    }

    private static RootCauseCandidate candidate(String eventType, String source, double score, String explanation) {
        return new RootCauseCandidate(eventType, source, score, explanation);
    }
}
