package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.repository.EventRepository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class SqliteEventRepository implements EventRepository {

    private static final String INSERT = "INSERT OR REPLACE INTO events "
            + "(id, ts, source, event_type, user_name, value, message, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    static final String SELECT_COLUMNS = "e.id, e.ts, e.source, e.event_type, e.user_name, e.value, e.message, e.raw_line";

    private final SqliteConnectionFactory connections;

    public SqliteEventRepository(SqliteConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections must not be null");
    }

    @Override
    public void saveAll(List<LogEvent> events) {
        if (events.isEmpty()) {
            return;
        }
        Transactions.inTransaction(connections, "saving events", connection -> insertEvents(connection, events));
    }

    /** Inserts events using an existing connection, so other repositories can share a transaction. */
    static void insertEvents(Connection connection, List<LogEvent> events) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
            for (LogEvent event : events) {
                statement.setString(1, event.id());
                statement.setLong(2, event.timestamp().toEpochMilli());
                statement.setString(3, event.source());
                statement.setString(4, event.eventType());
                statement.setString(5, event.user());
                if (event.value() == null) {
                    statement.setNull(6, java.sql.Types.REAL);
                } else {
                    statement.setDouble(6, event.value());
                }
                statement.setString(7, event.message());
                statement.setString(8, event.rawLine());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    @Override
    public List<LogEvent> findAll() {
        String sql = "SELECT " + SELECT_COLUMNS + " FROM events e ORDER BY e.ts, e.id";
        try (Connection connection = connections.openConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet rows = statement.executeQuery()) {
            List<LogEvent> events = new ArrayList<>();
            while (rows.next()) {
                events.add(readEvent(rows, 1));
            }
            return events;
        } catch (SQLException e) {
            throw new CyberShieldException("Database error while reading events", e);
        }
    }

    @Override
    public long count() {
        try (Connection connection = connections.openConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM events");
             ResultSet rows = statement.executeQuery()) {
            return rows.next() ? rows.getLong(1) : 0L;
        } catch (SQLException e) {
            throw new CyberShieldException("Database error while counting events", e);
        }
    }

    /** Reads an event from 8 consecutive columns starting at {@code first}, in {@link #SELECT_COLUMNS} order. */
    static LogEvent readEvent(ResultSet rows, int first) throws SQLException {
        double value = rows.getDouble(first + 5);
        Double boxed = rows.wasNull() ? null : value;
        return new LogEvent(rows.getString(first), Instant.ofEpochMilli(rows.getLong(first + 1)),
                rows.getString(first + 2), rows.getString(first + 3), rows.getString(first + 4),
                boxed, rows.getString(first + 6), rows.getString(first + 7));
    }
}
