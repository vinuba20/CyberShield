package com.cybermonitor.export;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.ThreatAlert;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Writes alerts and incidents as CSV (RFC 4180 style: comma separated, CRLF line ends, fields
 * with commas, quotes or line breaks are quoted).
 *
 * <p>Text that starts with {@code = + - @}, a tab or a carriage return would be run as a formula by
 * a spreadsheet, so a single quote is put in front of it ("CSV injection" protection).
 */
public class CsvExporter {

    private static final String EOL = "\r\n";

    public String alertsToCsv(List<ThreatAlert> alerts) {
        StringBuilder out = new StringBuilder();
        row(out, "alert_id", "timestamp_utc", "rule", "severity", "source", "explanation", "evidence_count");
        for (ThreatAlert alert : alerts) {
            row(out, alert.id(), alert.timestamp().toString(), alert.ruleName(), alert.severity().name(),
                    alert.source(), alert.explanation(), String.valueOf(alert.evidence().size()));
        }
        return out.toString();
    }

    public String incidentsToCsv(List<Incident> incidents) {
        StringBuilder out = new StringBuilder();
        row(out, "incident_id", "title", "severity", "status", "alert_count", "first_alert_utc",
                "last_alert_utc", "top_root_cause", "notes");
        for (Incident incident : incidents) {
            String first = incident.alerts().isEmpty() ? "" : incident.alerts().get(0).timestamp().toString();
            String last = incident.alerts().isEmpty() ? ""
                    : incident.alerts().get(incident.alerts().size() - 1).timestamp().toString();
            String root = incident.rootCauses().isEmpty() ? ""
                    : incident.rootCauses().get(0).eventType() + " @ " + incident.rootCauses().get(0).source();
            row(out, incident.id(), incident.title(), incident.severity().name(), incident.status().name(),
                    String.valueOf(incident.alerts().size()), first, last, root, incident.notes());
        }
        return out.toString();
    }

    public void exportAlerts(List<ThreatAlert> alerts, Path file) {
        write(file, alertsToCsv(alerts));
    }

    public void exportIncidents(List<Incident> incidents, Path file) {
        write(file, incidentsToCsv(incidents));
    }

    private void write(Path file, String content) {
        try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
            writer.write(content);
        } catch (IOException e) {
            throw new CyberShieldException("Cannot write " + file, e);
        }
    }

    private static void row(StringBuilder out, String... fields) {
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append(escape(fields[i]));
        }
        out.append(EOL);
    }

    /** Public so the rule is easy to unit test. */
    public static String escape(String field) {
        String text = field == null ? "" : field;
        if (!text.isEmpty()) {
            char first = text.charAt(0);
            if (first == '=' || first == '+' || first == '-' || first == '@' || first == '\t' || first == '\r') {
                text = "'" + text;
            }
        }
        if (text.contains(",") || text.contains("\"") || text.contains("\n") || text.contains("\r")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }
}
