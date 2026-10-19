package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.RootCauseCandidate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Stores ranked root-cause candidates separately, keyed by the owning incident id.
 *
 * <p>The candidate rows retain list order as rank and preserve all fields from
 * {@link RootCauseCandidate}. Incident records are owned by the incident persistence
 * implementation; this focused store does not assume an incident-table schema.
 */
public final class SqliteRootCauseCandidateStore {

    private static final Logger log = LoggerFactory.getLogger(SqliteRootCauseCandidateStore.class);

    private static final String CREATE_TABLE = """
            CREATE TABLE IF NOT EXISTS root_cause_candidates (
                incident_id TEXT NOT NULL,
                rank INTEGER NOT NULL CHECK (rank >= 0),
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                score REAL NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
                explanation TEXT NOT NULL,
                PRIMARY KEY (incident_id, rank)
            )
            """;

    private final SqliteConnectionFactory connections;

    public SqliteRootCauseCandidateStore(SqliteConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections must not be null");
        initializeSchema();
    }

    /**
     * Replaces all candidates for an incident atomically. Candidate list order is
     * persisted as rank; an empty list clears any previously stored candidates.
     */
    public void saveAll(String incidentId, List<RootCauseCandidate> candidates) {
        requireIncidentId(incidentId);
        List<RootCauseCandidate> safeCandidates =
                List.copyOf(Objects.requireNonNull(candidates, "candidates must not be null"));
        if (safeCandidates.stream().anyMatch(Objects::isNull)) {
            throw new NullPointerException("candidates must not contain null");
        }

        try (Connection connection = connections.openConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement delete = connection.prepareStatement(
                        "DELETE FROM root_cause_candidates WHERE incident_id = ?")) {
                    delete.setString(1, incidentId);
                    delete.executeUpdate();
                }

                try (PreparedStatement insert = connection.prepareStatement("""
                        INSERT INTO root_cause_candidates
                            (incident_id, rank, event_type, source, score, explanation)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """)) {
                    for (int index = 0; index < safeCandidates.size(); index++) {
                        RootCauseCandidate candidate = safeCandidates.get(index);
                        insert.setString(1, incidentId);
                        insert.setInt(2, index);
                        insert.setString(3, candidate.eventType());
                        insert.setString(4, candidate.source());
                        insert.setDouble(5, candidate.score());
                        insert.setString(6, candidate.explanation());
                        insert.addBatch();
                    }
                    insert.executeBatch();
                }
                connection.commit();
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            log.error("Cannot save root-cause candidates for incident {}", incidentId, exception);
            throw new CyberShieldException(
                    "Cannot save root-cause candidates for incident " + incidentId, exception);
        }
    }

    /** Returns candidates in their persisted best-first rank order, or an empty list. */
    public List<RootCauseCandidate> findByIncidentId(String incidentId) {
        requireIncidentId(incidentId);
        try (Connection connection = connections.openConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT event_type, source, score, explanation
                     FROM root_cause_candidates
                     WHERE incident_id = ?
                     ORDER BY rank
                     """)) {
            statement.setString(1, incidentId);
            try (ResultSet results = statement.executeQuery()) {
                List<RootCauseCandidate> candidates = new ArrayList<>();
                while (results.next()) {
                    candidates.add(new RootCauseCandidate(
                            results.getString("event_type"),
                            results.getString("source"),
                            results.getDouble("score"),
                            results.getString("explanation")));
                }
                return List.copyOf(candidates);
            }
        } catch (SQLException exception) {
            log.error("Cannot load root-cause candidates for incident {}", incidentId, exception);
            throw new CyberShieldException(
                    "Cannot load root-cause candidates for incident " + incidentId, exception);
        }
    }

    private void initializeSchema() {
        try (Connection connection = connections.openConnection();
             PreparedStatement statement = connection.prepareStatement(CREATE_TABLE)) {
            statement.executeUpdate();
        } catch (SQLException exception) {
            log.error("Cannot initialize root-cause candidate storage", exception);
            throw new CyberShieldException("Cannot initialize root-cause candidate storage", exception);
        }
    }

    private static void rollback(Connection connection, SQLException originalException) {
        try {
            connection.rollback();
        } catch (SQLException rollbackException) {
            originalException.addSuppressed(rollbackException);
            log.error("Cannot roll back root-cause candidate transaction", rollbackException);
        }
    }

    private static void requireIncidentId(String incidentId) {
        Objects.requireNonNull(incidentId, "incidentId must not be null");
        if (incidentId.isBlank()) {
            throw new IllegalArgumentException("incidentId must not be blank");
        }
    }
}
