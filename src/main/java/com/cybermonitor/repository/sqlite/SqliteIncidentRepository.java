package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.repository.AlertRepository;
import com.cybermonitor.repository.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class SqliteIncidentRepository implements IncidentRepository {

    private static final Logger log = LoggerFactory.getLogger(SqliteIncidentRepository.class);

    private static final String UPSERT = "INSERT INTO incidents (id, title, severity, status, notes) "
            + "VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            + "title = excluded.title, severity = excluded.severity, status = excluded.status, notes = excluded.notes";

    private final SqliteConnectionFactory connections;
    private final AlertRepository alerts;

    public SqliteIncidentRepository(SqliteConnectionFactory connections, AlertRepository alerts) {
        this.connections = Objects.requireNonNull(connections, "connections must not be null");
        this.alerts = Objects.requireNonNull(alerts, "alerts must not be null");
    }

    @Override
    public void save(Incident incident) {
        saveAll(List.of(incident));
    }

    @Override
    public void saveAll(List<Incident> incidents) {
        if (incidents.isEmpty()) {
            return;
        }
        // Alerts are saved first (with their evidence), in their own transaction, so the links below never dangle.
        List<ThreatAlert> allAlerts = new ArrayList<>();
        for (Incident incident : incidents) {
            allAlerts.addAll(incident.alerts());
        }
        alerts.saveAll(allAlerts);

        Transactions.inTransaction(connections, "saving incidents", connection -> {
            try (PreparedStatement upsert = connection.prepareStatement(UPSERT);
                 PreparedStatement deleteAlerts = connection.prepareStatement(
                         "DELETE FROM incident_alerts WHERE incident_id = ?");
                 PreparedStatement deleteCauses = connection.prepareStatement(
                         "DELETE FROM incident_root_causes WHERE incident_id = ?");
                 PreparedStatement insertAlert = connection.prepareStatement(
                         "INSERT INTO incident_alerts (incident_id, alert_id, position) VALUES (?, ?, ?)");
                 PreparedStatement insertCause = connection.prepareStatement(
                         "INSERT INTO incident_root_causes (incident_id, rank, event_type, source, score, explanation) "
                                 + "VALUES (?, ?, ?, ?, ?, ?)")) {
                for (Incident incident : incidents) {
                    upsert.setString(1, incident.id());
                    upsert.setString(2, incident.title());
                    upsert.setString(3, incident.severity().name());
                    upsert.setString(4, incident.status().name());
                    upsert.setString(5, incident.notes());
                    upsert.addBatch();

                    deleteAlerts.setString(1, incident.id());
                    deleteAlerts.addBatch();
                    deleteCauses.setString(1, incident.id());
                    deleteCauses.addBatch();
                }
                upsert.executeBatch();
                deleteAlerts.executeBatch();
                deleteCauses.executeBatch();

                for (Incident incident : incidents) {
                    int position = 0;
                    for (ThreatAlert alert : incident.alerts()) {
                        insertAlert.setString(1, incident.id());
                        insertAlert.setString(2, alert.id());
                        insertAlert.setInt(3, position++);
                        insertAlert.addBatch();
                    }
                    int rank = 0;
                    for (RootCauseCandidate cause : incident.rootCauses()) {
                        insertCause.setString(1, incident.id());
                        insertCause.setInt(2, rank++);
                        insertCause.setString(3, cause.eventType());
                        insertCause.setString(4, cause.source());
                        insertCause.setDouble(5, cause.score());
                        insertCause.setString(6, cause.explanation());
                        insertCause.addBatch();
                    }
                }
                insertAlert.executeBatch();
                insertCause.executeBatch();
            }
        });
    }

    @Override
    public List<Incident> findAll() {
        return query("", null);
    }

    @Override
    public Optional<Incident> findById(String incidentId) {
        return query(" WHERE i.id = ?", incidentId).stream().findFirst();
    }

    private List<Incident> query(String where, String parameter) {
        Map<String, ThreatAlert> alertsById = new HashMap<>();
        for (ThreatAlert alert : alerts.findAll()) {
            alertsById.put(alert.id(), alert);
        }
        String incidentSql = "SELECT i.id, i.title, i.severity, i.status, i.notes FROM incidents i" + where
                + " ORDER BY i.id";
        String linkSql = "SELECT ia.incident_id, ia.alert_id FROM incident_alerts ia"
                + (where.isEmpty() ? "" : " WHERE ia.incident_id = ?") + " ORDER BY ia.incident_id, ia.position";
        String causeSql = "SELECT c.incident_id, c.event_type, c.source, c.score, c.explanation "
                + "FROM incident_root_causes c" + (where.isEmpty() ? "" : " WHERE c.incident_id = ?")
                + " ORDER BY c.incident_id, c.rank";
        try (Connection connection = connections.openConnection();
             PreparedStatement incidentStatement = connection.prepareStatement(incidentSql);
             PreparedStatement linkStatement = connection.prepareStatement(linkSql);
             PreparedStatement causeStatement = connection.prepareStatement(causeSql)) {
            if (parameter != null) {
                incidentStatement.setString(1, parameter);
                linkStatement.setString(1, parameter);
                causeStatement.setString(1, parameter);
            }
            Map<String, List<ThreatAlert>> alertsByIncident = new HashMap<>();
            try (ResultSet rows = linkStatement.executeQuery()) {
                while (rows.next()) {
                    ThreatAlert alert = alertsById.get(rows.getString(2));
                    if (alert == null) {
                        log.warn("Incident {} refers to missing alert {}", rows.getString(1), rows.getString(2));
                        continue;
                    }
                    alertsByIncident.computeIfAbsent(rows.getString(1), key -> new ArrayList<>()).add(alert);
                }
            }
            Map<String, List<RootCauseCandidate>> causesByIncident = new HashMap<>();
            try (ResultSet rows = causeStatement.executeQuery()) {
                while (rows.next()) {
                    causesByIncident.computeIfAbsent(rows.getString(1), key -> new ArrayList<>())
                            .add(new RootCauseCandidate(rows.getString(2), rows.getString(3),
                                    rows.getDouble(4), rows.getString(5)));
                }
            }
            List<Incident> incidents = new ArrayList<>();
            try (ResultSet rows = incidentStatement.executeQuery()) {
                while (rows.next()) {
                    String id = rows.getString(1);
                    incidents.add(new Incident(id, rows.getString(2), Severity.valueOf(rows.getString(3)),
                            IncidentStatus.valueOf(rows.getString(4)), alertsByIncident.get(id),
                            causesByIncident.get(id), rows.getString(5)));
                }
            }
            return incidents;
        } catch (SQLException e) {
            throw new CyberShieldException("Database error while reading incidents", e);
        }
    }
}
