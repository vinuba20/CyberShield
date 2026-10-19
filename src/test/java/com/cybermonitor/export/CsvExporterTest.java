package com.cybermonitor.export;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsvExporterTest {

    private final CsvExporter exporter = new CsvExporter();

    @Test
    void plainTextIsLeftAlone() {
        assertEquals("hello world", CsvExporter.escape("hello world"));
        assertEquals("", CsvExporter.escape(null));
        assertEquals("", CsvExporter.escape(""));
    }

    @Test
    void commasQuotesAndLineBreaksAreQuoted() {
        assertEquals("\"a,b\"", CsvExporter.escape("a,b"));
        assertEquals("\"say \"\"hi\"\"\"", CsvExporter.escape("say \"hi\""));
        assertEquals("\"line1\nline2\"", CsvExporter.escape("line1\nline2"));
    }

    @Test
    void formulaStartsAreNeutralised() {
        assertEquals("'=SUM(A1:A2)", CsvExporter.escape("=SUM(A1:A2)"));
        assertEquals("'+1", CsvExporter.escape("+1"));
        assertEquals("'-1", CsvExporter.escape("-1"));
        assertEquals("'@cmd", CsvExporter.escape("@cmd"));
        assertEquals("'\tx", CsvExporter.escape("\tx"));
    }

    @Test
    void neutralisedFormulaWithACommaIsAlsoQuoted() {
        assertEquals("\"'=A1,B1\"", CsvExporter.escape("=A1,B1"));
    }

    @Test
    void alertsCsvHasHeaderAndOneRowPerAlertWithCrLf() {
        ThreatAlert alert = Fixtures.alert("BRUTE_FORCE", Severity.HIGH, "10.0.0.5", 0,
                List.of(Fixtures.failed("10.0.0.5", "root", 0)));

        String csv = exporter.alertsToCsv(List.of(alert));

        String[] lines = csv.split("\r\n");
        assertEquals("alert_id,timestamp_utc,rule,severity,source,explanation,evidence_count", lines[0]);
        assertEquals(2, lines.length);
        assertTrue(lines[1].contains("BRUTE_FORCE,HIGH,10.0.0.5"));
        assertTrue(lines[1].endsWith(",1"));
        assertTrue(csv.endsWith("\r\n"));
    }

    @Test
    void hostileExplanationTextCannotBecomeAFormula() {
        ThreatAlert alert = new ThreatAlert("a1", "R", Severity.LOW, Fixtures.T0, "s", "=HYPERLINK(\"http://x\")", List.of());

        assertTrue(exporter.alertsToCsv(List.of(alert)).contains("\"'=HYPERLINK(\"\"http://x\"\")\""));
    }

    @Test
    void incidentsCsvIncludesStatusNotesAndTopRootCause() {
        ThreatAlert first = Fixtures.alert("A", "s", 0);
        ThreatAlert last = Fixtures.alert("B", "s", 60);
        Incident incident = new Incident("i1", "A + B on s", Severity.HIGH, IncidentStatus.INVESTIGATING,
                List.of(first, last), List.of(new RootCauseCandidate("PUMP_FAULT", "Pump-1", 0.9, "precedes most")),
                "checked, ok");

        String[] lines = exporter.incidentsToCsv(List.of(incident)).split("\r\n");

        assertEquals("incident_id,title,severity,status,alert_count,first_alert_utc,last_alert_utc,top_root_cause,notes", lines[0]);
        assertTrue(lines[1].contains("INVESTIGATING,2,2026-01-01T10:00:00Z,2026-01-01T10:01:00Z,PUMP_FAULT @ Pump-1,"));
        assertTrue(lines[1].endsWith("\"checked, ok\""));
    }

    @Test
    void incidentWithoutAlertsOrRootCausesExportsEmptyFields() {
        Incident empty = new Incident("i1", "t", Severity.LOW, IncidentStatus.OPEN, List.of(), List.of(), "");

        assertEquals("i1,t,LOW,OPEN,0,,,,", exporter.incidentsToCsv(List.of(empty)).split("\r\n")[1]);
    }

    @Test
    void writesAFileInUtf8(@TempDir Path folder) throws Exception {
        Path file = folder.resolve("alerts.csv");

        exporter.exportAlerts(List.of(Fixtures.alert("R", "s", 0)), file);

        String content = Files.readString(file);
        assertTrue(content.startsWith("alert_id,"));
    }
}
