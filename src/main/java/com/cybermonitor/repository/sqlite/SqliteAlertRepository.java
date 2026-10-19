package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.repository.AlertRepository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class SqliteAlertRepository implements AlertRepository {

    private static final String INSERT_ALERT = "INSERT OR REPLACE INTO alerts "
            + "(id, rule_name, severity, ts, source, explanation) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String DELETE_EVIDENCE = "DELETE FROM alert_evidence WHERE alert_id = ?";
    private static final String INSERT_EVIDENCE =
            "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?, ?)";

    private final SqliteConnectionFactory connections;

    public SqliteAlertRepository(SqliteConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections must not be null");
    }

    @Override
    public void saveAll(List<ThreatAlert> alerts) {
        if (alerts.isEmpty()) {
            return;
        }
        Transactions.inTransaction(connections, "saving alerts", connection -> {
            // Evidence events are saved too, so an alert can never point at a missing event.
            List<LogEvent> evidenceEvents = new ArrayList<>();
            for (ThreatAlert alert : alerts) {
                evidenceEvents.addAll(alert.evidence());
            }
            SqliteEventRepository.insertEvents(connection, evidenceEvents);

            try (PreparedStatement alertStatement = connection.prepareStatement(INSERT_ALERT);
                 PreparedStatement deleteStatement = connection.prepareStatement(DELETE_EVIDENCE);
                 PreparedStatement evidenceStatement = connection.prepareStatement(INSERT_EVIDENCE)) {
                for (ThreatAlert alert : alerts) {
                    alertStatement.setString(1, alert.id());
                    alertStatement.setString(2, alert.ruleName());
                    alertStatement.setString(3, alert.severity().name());
                    alertStatement.setLong(4, alert.timestamp().toEpochMilli());
                    alertStatement.setString(5, alert.source());
                    alertStatement.setString(6, alert.explanation());
                    alertStatement.addBatch();

                    deleteStatement.setString(1, alert.id());
                    deleteStatement.addBatch();
                }
                alertStatement.executeBatch();
                deleteStatement.executeBatch();
                for (ThreatAlert alert : alerts) {
                    for (LogEvent event : alert.evidence()) {
                        evidenceStatement.setString(1, alert.id());
                        evidenceStatement.setString(2, event.id());
                        evidenceStatement.addBatch();
                    }
                }
                evidenceStatement.executeBatch();
            }
        });
    }

    @Override
    public List<ThreatAlert> findAll() {
        return query("", null);
    }

    @Override
    public Optional<ThreatAlert> findById(String alertId) {
        return query(" WHERE a.id = ?", alertId).stream().findFirst();
    }

    private List<ThreatAlert> query(String where, String parameter) {
        String alertSql = "SELECT a.id, a.rule_name, a.severity, a.ts, a.source, a.explanation FROM alerts a"
                + where + " ORDER BY a.ts, a.id";
        String evidenceSql = "SELECT ae.alert_id, " + SqliteEventRepository.SELECT_COLUMNS
                + " FROM alert_evidence ae JOIN events e ON e.id = ae.event_id"
                + (where.isEmpty() ? "" : " WHERE ae.alert_id = ?") + " ORDER BY e.ts, e.id";
        try (Connection connection = connections.openConnection();
             PreparedStatement alertStatement = connection.prepareStatement(alertSql);
             PreparedStatement evidenceStatement = connection.prepareStatement(evidenceSql)) {
            if (parameter != null) {
                alertStatement.setString(1, parameter);
                evidenceStatement.setString(1, parameter);
            }
            Map<String, List<LogEvent>> evidenceByAlert = new HashMap<>();
            try (ResultSet rows = evidenceStatement.executeQuery()) {
                while (rows.next()) {
                    evidenceByAlert.computeIfAbsent(rows.getString(1), key -> new ArrayList<>())
                            .add(SqliteEventRepository.readEvent(rows, 2));
                }
            }
            List<ThreatAlert> alerts = new ArrayList<>();
            try (ResultSet rows = alertStatement.executeQuery()) {
                while (rows.next()) {
                    String id = rows.getString(1);
                    alerts.add(new ThreatAlert(id, rows.getString(2), Severity.valueOf(rows.getString(3)),
                            Instant.ofEpochMilli(rows.getLong(4)), rows.getString(5), rows.getString(6),
                            evidenceByAlert.get(id)));
                }
            }
            return alerts;
        } catch (SQLException e) {
            throw new CyberShieldException("Database error while reading alerts", e);
        }
    }
}
