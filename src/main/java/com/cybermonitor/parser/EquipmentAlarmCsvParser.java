package com.cybermonitor.parser;

import com.cybermonitor.exception.MalformedLineException;
import com.cybermonitor.model.LogEvent;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Parses equipment-alarm rows with columns timestamp, tool, component, code and severity. */
public class EquipmentAlarmCsvParser implements EventParser {

    private static final List<String> HEADER =
            List.of("timestamp", "tool", "component", "code", "severity");

    @Override
    public String formatName() {
        return "Equipment alarm CSV";
    }

    @Override
    public boolean isIgnorable(String line) {
        if (line == null) {
            return false;
        }
        if (line.isBlank() || line.stripLeading().startsWith("#")) {
            return true;
        }

        try {
            return isHeader(parseCsv(line));
        } catch (CsvFormatException exception) {
            return false;
        }
    }

    @Override
    public LogEvent parseLine(String line) throws MalformedLineException {
        if (line == null) {
            throw new MalformedLineException("Line must not be null", null);
        }

        List<String> fields;
        try {
            fields = parseCsv(line);
        } catch (CsvFormatException exception) {
            throw new MalformedLineException(exception.getMessage(), line, exception);
        }

        if (fields.size() != HEADER.size()) {
            throw new MalformedLineException("Expected 5 CSV fields but found " + fields.size(), line);
        }
        if (isHeader(fields)) {
            throw new MalformedLineException("CSV header is not an event row", line);
        }
        for (int index = 0; index < fields.size(); index++) {
            if (fields.get(index).isBlank()) {
                throw new MalformedLineException("Required field '" + HEADER.get(index) + "' is blank", line);
            }
        }

        Instant timestamp;
        try {
            timestamp = Instant.parse(fields.get(0));
        } catch (DateTimeParseException exception) {
            throw new MalformedLineException("Invalid ISO-8601 timestamp", line, exception);
        }

        String message = "component=" + fields.get(2) + ", severity=" + fields.get(4);
        return new LogEvent(UUID.randomUUID().toString(), timestamp, fields.get(1), fields.get(3),
                null, null, message, line);
    }

    private static boolean isHeader(List<String> fields) {
        if (fields.size() != HEADER.size()) {
            return false;
        }
        for (int index = 0; index < HEADER.size(); index++) {
            if (!HEADER.get(index).equalsIgnoreCase(fields.get(index))) {
                return false;
            }
        }
        return true;
    }

    private static List<String> parseCsv(String line) throws CsvFormatException {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        boolean afterQuote = false;

        for (int index = 0; index < line.length(); index++) {
            char character = line.charAt(index);
            if (inQuotes) {
                if (character == '"') {
                    if (index + 1 < line.length() && line.charAt(index + 1) == '"') {
                        field.append('"');
                        index++;
                    } else {
                        inQuotes = false;
                        afterQuote = true;
                    }
                } else {
                    field.append(character);
                }
            } else if (afterQuote) {
                if (character == ',') {
                    fields.add(field.toString().trim());
                    field.setLength(0);
                    afterQuote = false;
                } else if (!Character.isWhitespace(character)) {
                    throw new CsvFormatException("Unexpected character after quoted CSV field");
                }
            } else if (character == ',') {
                fields.add(field.toString().trim());
                field.setLength(0);
            } else if (character == '"') {
                if (field.length() != 0) {
                    throw new CsvFormatException("Quote found inside an unquoted CSV field");
                }
                inQuotes = true;
            } else {
                field.append(character);
            }
        }

        if (inQuotes) {
            throw new CsvFormatException("Unterminated quoted CSV field");
        }
        fields.add(field.toString().trim());
        return fields;
    }

    private static final class CsvFormatException extends Exception {

        private static final long serialVersionUID = 1L;

        private CsvFormatException(String message) {
            super(message);
        }
    }
}
