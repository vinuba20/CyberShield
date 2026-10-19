package com.cybermonitor.testutil;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Builds valid sample objects so each test only spells out what it is testing. */
public final class Fixtures {

    public static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private Fixtures() {
    }

    /** A failed login {@code seconds} after T0. */
    public static LogEvent failed(String source, String user, long seconds) {
        return event("LOGIN_FAILED", source, user, seconds);
    }

    /** A successful login {@code seconds} after T0. */
    public static LogEvent ok(String source, String user, long seconds) {
        return event("LOGIN_OK", source, user, seconds);
    }

    public static LogEvent event(String type, String source, String user, long seconds) {
        return new LogEvent(UUID.randomUUID().toString(), T0.plusSeconds(seconds), source, type, user, null,
                "sshd", "raw " + type + " " + seconds);
    }

    public static ThreatAlert alert(String rule, Severity severity, String source, long seconds,
                                    List<LogEvent> evidence) {
        return new ThreatAlert(UUID.randomUUID().toString(), rule, severity, T0.plusSeconds(seconds), source,
                "explanation of " + rule, evidence);
    }

    public static ThreatAlert alert(String rule, String source, long seconds) {
        return alert(rule, Severity.HIGH, source, seconds, List.of());
    }
}
