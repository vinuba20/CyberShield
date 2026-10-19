package com.cybermonitor.parser;

import com.cybermonitor.exception.MalformedLineException;
import com.cybermonitor.model.LogEvent;

import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the synthetic authentication log (see docs/data-formats.md).
 *
 * <pre>
 * 2026-01-01 10:00:01 sshd user=admin src=10.0.0.5 LOGIN_FAILED Invalid password
 * </pre>
 *
 * <p>Mapping to {@link LogEvent}: the {@code src} address becomes {@code source} (rules group
 * by it), the service name ({@code sshd}) is kept at the start of the message. Times are UTC.
 */
public class AuthLogParser implements EventParser {

    static final int MAX_LINE_LENGTH = 2000;

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Pattern LINE = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+user=(\\S+)\\s+src=(\\S+)\\s+([A-Z_]+)(?:\\s+(.*))?$");

    /** The event types this format may contain. */
    public static final Set<String> EVENT_TYPES = Set.of("LOGIN_FAILED", "LOGIN_OK");

    @Override
    public String formatName() {
        return "Auth log";
    }

    @Override
    public boolean isIgnorable(String line) {
        String trimmed = line.strip();
        return trimmed.isEmpty() || trimmed.startsWith("#");
    }

    @Override
    public LogEvent parseLine(String line) throws MalformedLineException {
        if (line == null) {
            throw new MalformedLineException("Line is null", "");
        }
        if (line.length() > MAX_LINE_LENGTH) {
            throw new MalformedLineException("Line is longer than " + MAX_LINE_LENGTH + " characters", line);
        }
        Matcher matcher = LINE.matcher(line.strip());
        if (!matcher.matches()) {
            throw new MalformedLineException(
                    "Expected: yyyy-MM-dd HH:mm:ss <service> user=<name> src=<address> <EVENT_TYPE> [text]", line);
        }
        String eventType = matcher.group(5);
        if (!EVENT_TYPES.contains(eventType)) {
            throw new MalformedLineException("Unknown event type " + eventType, line);
        }
        try {
            var timestamp = LocalDateTime.parse(matcher.group(1), TIME).toInstant(ZoneOffset.UTC);
            String service = matcher.group(2);
            String text = matcher.group(6) == null ? "" : matcher.group(6);
            String message = text.isEmpty() ? service : service + ": " + text;
            return new LogEvent(UUID.randomUUID().toString(), timestamp, matcher.group(4), eventType,
                    matcher.group(3), null, message, line);
        } catch (DateTimeException e) {
            throw new MalformedLineException("Invalid date or time: " + matcher.group(1), line, e);
        }
    }
}
