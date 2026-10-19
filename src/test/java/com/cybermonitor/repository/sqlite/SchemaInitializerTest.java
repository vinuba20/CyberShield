package com.cybermonitor.repository.sqlite;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SchemaInitializerTest {

    @Test
    void splitsOnSemicolonsAndDropsCommentLines() {
        List<String> statements = SchemaInitializer.splitStatements(
                "-- comment\nCREATE TABLE a (x INTEGER);\n\n-- another\nCREATE INDEX i ON a (x);\n");

        assertEquals(List.of("CREATE TABLE a (x INTEGER)", "CREATE INDEX i ON a (x)"), statements);
    }

    @Test
    void theBundledSchemaCreatesAllTablesAndIsIdempotent() {
        List<String> statements = SchemaInitializer.readStatements();

        for (String table : List.of("events", "alerts", "alert_evidence", "incidents", "incident_alerts",
                "incident_root_causes")) {
            assertTrue(statements.stream().anyMatch(s -> s.contains("CREATE TABLE IF NOT EXISTS " + table + " ")),
                    "missing table " + table);
        }
        assertTrue(statements.stream().allMatch(s -> s.contains("IF NOT EXISTS")));
        assertFalse(statements.stream().anyMatch(s -> s.contains("--")));
    }
}
