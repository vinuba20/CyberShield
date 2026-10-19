package com.cybermonitor.service;

import com.cybermonitor.model.LogEvent;

import java.util.List;

/**
 * Outcome of importing one file.
 *
 * @param fileName         name of the imported file
 * @param totalLines       all lines read
 * @param ignoredLines     blank, comment and header lines (not events)
 * @param malformedLines   lines that did not match the format (skipped, never silently dropped)
 * @param events           the parsed events
 * @param malformedSamples the first few bad lines as "line N: reason", for the UI
 */
public record ImportResult(
        String fileName,
        int totalLines,
        int ignoredLines,
        int malformedLines,
        List<LogEvent> events,
        List<String> malformedSamples) {

    public ImportResult {
        events = List.copyOf(events);
        malformedSamples = List.copyOf(malformedSamples);
    }

    public int importedLines() {
        return events.size();
    }

    public String summary() {
        return fileName + ": " + totalLines + " lines, " + events.size() + " imported, "
                + malformedLines + " malformed, " + ignoredLines + " ignored";
    }
}
