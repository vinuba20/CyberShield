package com.cybermonitor.repository.sqlite;

import com.cybermonitor.exception.CyberShieldException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Creates the tables from {@code schema.sql} if they do not exist yet. */
public class SchemaInitializer {

    private static final Logger log = LoggerFactory.getLogger(SchemaInitializer.class);
    static final String SCHEMA_RESOURCE = "/schema.sql";

    private final SqliteConnectionFactory connections;

    public SchemaInitializer(SqliteConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections must not be null");
    }

    /** Called by Spring as the init method. Safe to call more than once. */
    public void initialize() {
        List<String> statements = readStatements();
        try (Connection connection = connections.openConnection();
             Statement statement = connection.createStatement()) {
            for (String sql : statements) {
                statement.execute(sql);
            }
            log.info("Database schema ready ({} statements)", statements.size());
        } catch (SQLException e) {
            throw new CyberShieldException("Cannot create database schema", e);
        }
    }

    static List<String> readStatements() {
        try (InputStream in = SchemaInitializer.class.getResourceAsStream(SCHEMA_RESOURCE)) {
            if (in == null) {
                throw new CyberShieldException("Missing resource " + SCHEMA_RESOURCE);
            }
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return splitStatements(text);
        } catch (IOException e) {
            throw new CyberShieldException("Cannot read " + SCHEMA_RESOURCE, e);
        }
    }

    /** Drops {@code --} comment lines and splits on semicolons. */
    static List<String> splitStatements(String script) {
        StringBuilder withoutComments = new StringBuilder();
        for (String line : script.split("\\R")) {
            if (!line.strip().startsWith("--")) {
                withoutComments.append(line).append('\n');
            }
        }
        List<String> statements = new ArrayList<>();
        for (String part : withoutComments.toString().split(";")) {
            if (!part.isBlank()) {
                statements.add(part.strip());
            }
        }
        return statements;
    }
}
