package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;

import java.sql.Connection;
import java.sql.SQLException;

/** Runs JDBC work in one transaction: commit on success, roll back on any failure. */
final class Transactions {

    @FunctionalInterface
    interface Work {
        void run(Connection connection) throws SQLException;
    }

    private Transactions() {
    }

    static void inTransaction(SqliteConnectionFactory connections, String what, Work work) {
        try (Connection connection = connections.openConnection()) {
            connection.setAutoCommit(false);
            try {
                work.run(connection);
                connection.commit();
            } catch (SQLException | RuntimeException e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new CyberShieldException("Database error while " + what, e);
        }
    }
}
