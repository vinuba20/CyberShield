package com.cybermonitor.parser;

import com.cybermonitor.exception.MalformedLineException;
import com.cybermonitor.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthLogParserTest {

    private final AuthLogParser parser = new AuthLogParser();

    @Test
    void parsesAFailedLoginIntoAllFields() throws Exception {
        String line = "2026-01-01 10:00:01 sshd user=admin src=10.0.0.5 LOGIN_FAILED Invalid password";

        LogEvent event = parser.parseLine(line);

        assertEquals(Instant.parse("2026-01-01T10:00:01Z"), event.timestamp());
        assertEquals("10.0.0.5", event.source());
        assertEquals("LOGIN_FAILED", event.eventType());
        assertEquals("admin", event.user());
        assertNull(event.value());
        assertEquals("sshd: Invalid password", event.message());
        assertEquals(line, event.rawLine());
        assertFalse(event.id().isBlank());
    }

    @Test
    void textAfterTheEventTypeIsOptional() throws Exception {
        LogEvent event = parser.parseLine("2026-01-01 10:00:01 sshd user=bob src=10.0.0.6 LOGIN_OK");

        assertEquals("LOGIN_OK", event.eventType());
        assertEquals("sshd", event.message());
    }

    @Test
    void everyParsedEventGetsItsOwnId() throws Exception {
        String line = "2026-01-01 10:00:01 sshd user=bob src=10.0.0.6 LOGIN_OK";

        assertTrue(!parser.parseLine(line).id().equals(parser.parseLine(line).id()));
    }

    @Test
    void blankLinesAndCommentsAreIgnorable() {
        assertTrue(parser.isIgnorable(""));
        assertTrue(parser.isIgnorable("   "));
        assertTrue(parser.isIgnorable("# a comment"));
        assertTrue(parser.isIgnorable("   # indented comment"));
        assertFalse(parser.isIgnorable("2026-01-01 10:00:01 sshd user=a src=b LOGIN_OK"));
    }

    @Test
    void rejectsLinesThatDoNotMatchTheFormat() {
        String[] bad = {
                "hello world",
                "2026-01-01 10:00:01 sshd user=admin LOGIN_FAILED",                 // no src
                "2026-01-01 10:00:01 sshd src=10.0.0.5 user=admin LOGIN_FAILED",    // wrong order
                "10:00:01 sshd user=admin src=10.0.0.5 LOGIN_FAILED",               // no date
                "2026-01-01 10:00:01 sshd user=admin src=10.0.0.5",                 // no event type
                "2026-01-01 10:00:01 sshd user=admin src=10.0.0.5 login_failed",    // lower case type
        };
        for (String line : bad) {
            MalformedLineException e = assertThrows(MalformedLineException.class, () -> parser.parseLine(line));
            assertEquals(line, e.line());
        }
    }

    @Test
    void rejectsUnknownEventTypes() {
        MalformedLineException e = assertThrows(MalformedLineException.class,
                () -> parser.parseLine("2026-01-01 10:00:01 sshd user=a src=b LOGOUT"));

        assertTrue(e.getMessage().contains("LOGOUT"));
    }

    @Test
    void rejectsImpossibleDatesAndTimes() {
        assertThrows(MalformedLineException.class,
                () -> parser.parseLine("2026-13-45 10:00:01 sshd user=a src=b LOGIN_OK"));
        assertThrows(MalformedLineException.class,
                () -> parser.parseLine("2026-01-01 25:61:61 sshd user=a src=b LOGIN_OK"));
    }

    @Test
    void rejectsVeryLongLines() {
        String line = "2026-01-01 10:00:01 sshd user=a src=b LOGIN_OK " + "x".repeat(AuthLogParser.MAX_LINE_LENGTH);

        assertThrows(MalformedLineException.class, () -> parser.parseLine(line));
    }

    @Test
    void nullLineIsMalformedNotACrash() {
        assertThrows(MalformedLineException.class, () -> parser.parseLine(null));
    }

    @Test
    void formatNameIsShownInTheUi() {
        assertEquals("Auth log", parser.formatName());
    }
}
