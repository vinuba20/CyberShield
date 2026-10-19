package com.cybermonitor.parser;

import com.cybermonitor.exception.MalformedLineException;
import com.cybermonitor.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EquipmentAlarmCsvSampleTest {

    @Test
    void sampleDatasetContainsParserValidSyntheticCascadeRows() throws IOException {
        EquipmentAlarmCsvParser parser = new EquipmentAlarmCsvParser();
        List<LogEvent> events = Files.readAllLines(Path.of("data", "sample", "equipment-alarms.csv"))
                .stream()
                .filter(line -> !parser.isIgnorable(line))
                .map(this::parse)
                .toList();

        assertEquals(List.of("PUMP_FAULT", "PRESSURE_HIGH", "HANDLER_ALARM", "RECIPE_ABORT"),
                events.stream().map(LogEvent::eventType).toList());
        assertEquals("2026-10-18T10:00:00Z,Pump-1,Motor,PUMP_FAULT,CRITICAL",
                events.getFirst().rawLine());
        assertTrue(events.stream().allMatch(event -> event.rawLine().equals(
                event.timestamp() + "," + event.source() + "," + component(event) + ","
                        + event.eventType() + "," + severity(event))));
    }

    private LogEvent parse(String line) {
        try {
            return new EquipmentAlarmCsvParser().parseLine(line);
        } catch (MalformedLineException exception) {
            throw new AssertionError("Invalid equipment alarm sample row: " + line, exception);
        }
    }

    private static String component(LogEvent event) {
        return event.message().substring("component=".length(), event.message().indexOf(", severity="));
    }

    private static String severity(LogEvent event) {
        return event.message().substring(event.message().indexOf(", severity=") + ", severity=".length());
    }
}
