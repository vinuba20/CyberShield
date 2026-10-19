package com.cybermonitor.parser;

import com.cybermonitor.exception.MalformedLineException;
import com.cybermonitor.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EquipmentAlarmCsvParserTest {

    private final EquipmentAlarmCsvParser parser = new EquipmentAlarmCsvParser();

    @Test
    void parsesAlarmRowAndPreservesOriginalLine() throws MalformedLineException {
        String line = "2026-10-18T10:00:00Z,Etcher-1,Chamber-2,TEMP_HIGH,CRITICAL";

        LogEvent event = parser.parseLine(line);

        assertNotNull(event.id());
        assertEquals(Instant.parse("2026-10-18T10:00:00Z"), event.timestamp());
        assertEquals("Etcher-1", event.source());
        assertEquals("TEMP_HIGH", event.eventType());
        assertEquals("component=Chamber-2, severity=CRITICAL", event.message());
        assertEquals(line, event.rawLine());
    }

    @Test
    void parsesQuotedFieldsContainingCommasAndEscapedQuotes() throws MalformedLineException {
        String line = "2026-10-18T10:00:00Z,\"Etcher, West\",\"Chamber \"\"A\"\", 2\",TEMP_HIGH,HIGH";

        LogEvent event = parser.parseLine(line);

        assertEquals("Etcher, West", event.source());
        assertEquals("component=Chamber \"A\", 2, severity=HIGH", event.message());
        assertEquals(line, event.rawLine());
    }

    @Test
    void skipsBlankCommentAndHeaderLines() {
        assertTrue(parser.isIgnorable(""));
        assertTrue(parser.isIgnorable("   "));
        assertTrue(parser.isIgnorable("  # generated sample"));
        assertTrue(parser.isIgnorable("timestamp,tool,component,code,severity"));
        assertTrue(parser.isIgnorable(" Timestamp , TOOL , Component , Code , Severity "));
        assertFalse(parser.isIgnorable(null));
        assertFalse(parser.isIgnorable("2026-10-18T10:00:00Z,Etcher-1,Chamber-2,TEMP_HIGH,HIGH"));
    }

    @Test
    void rejectsRowsWithWrongFieldCount() {
        assertMalformed("2026-10-18T10:00:00Z,Etcher-1,Chamber-2,TEMP_HIGH");
        assertMalformed("2026-10-18T10:00:00Z,Etcher-1,Chamber-2,TEMP_HIGH,HIGH,extra");
    }

    @Test
    void rejectsRowsWithMissingRequiredFields() {
        assertMalformed(",Etcher-1,Chamber-2,TEMP_HIGH,HIGH");
        assertMalformed("2026-10-18T10:00:00Z,,Chamber-2,TEMP_HIGH,HIGH");
        assertMalformed("2026-10-18T10:00:00Z,Etcher-1, ,TEMP_HIGH,HIGH");
        assertMalformed("2026-10-18T10:00:00Z,Etcher-1,Chamber-2,,HIGH");
        assertMalformed("2026-10-18T10:00:00Z,Etcher-1,Chamber-2,TEMP_HIGH, ");
    }

    @Test
    void rejectsInvalidTimestampsAndMalformedCsv() {
        assertMalformed("not-a-timestamp,Etcher-1,Chamber-2,TEMP_HIGH,HIGH");
        assertMalformed("2026-10-18T10:00:00Z,Etcher-1,\"Chamber-2,TEMP_HIGH,HIGH");
        assertMalformed("2026-10-18T10:00:00Z,Etcher\"1,Chamber-2,TEMP_HIGH,HIGH");
    }

    private void assertMalformed(String line) {
        MalformedLineException exception =
                assertThrows(MalformedLineException.class, () -> parser.parseLine(line));
        assertEquals(line, exception.line());
    }
}
