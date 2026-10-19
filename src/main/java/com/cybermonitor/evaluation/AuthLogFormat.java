package com.cybermonitor.evaluation;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** Writes events in the auth-log text format, so a generated dataset can be saved and re-imported. */
final class AuthLogFormat {

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    private AuthLogFormat() {
    }

    static String format(Instant time, String service, String user, String ip, String type, String text) {
        return TIME.format(time) + " " + service + " user=" + user + " src=" + ip + " " + type + " " + text;
    }
}
