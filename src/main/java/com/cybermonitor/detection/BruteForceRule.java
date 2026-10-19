package com.cybermonitor.detection;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Raises an alert when one source produces at least {@code threshold} failed logins within
 * {@code window}. A burst is reported once, with all failures that fall in the window that
 * starts at its first failure.
 */
public class BruteForceRule implements DetectionRule {

    public static final String NAME = "BRUTE_FORCE";
    public static final String FAILED = "LOGIN_FAILED";

    private final int threshold;
    private final Duration window;

    public BruteForceRule(int threshold, Duration window) {
        if (threshold < 2) {
            throw new IllegalArgumentException("threshold must be at least 2, was " + threshold);
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        this.threshold = threshold;
        this.window = window;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<ThreatAlert> evaluate(List<LogEvent> events) {
        Map<String, List<LogEvent>> failuresBySource = new LinkedHashMap<>();
        for (LogEvent event : events) {
            if (FAILED.equals(event.eventType())) {
                failuresBySource.computeIfAbsent(event.source(), key -> new ArrayList<>()).add(event);
            }
        }
        List<ThreatAlert> alerts = new ArrayList<>();
        for (var entry : failuresBySource.entrySet()) {
            List<LogEvent> failures = new ArrayList<>(entry.getValue());
            failures.sort(Comparator.comparing(LogEvent::timestamp));
            findBursts(entry.getKey(), failures, alerts);
        }
        alerts.sort(Comparator.comparing(ThreatAlert::timestamp));
        return alerts;
    }

    private void findBursts(String source, List<LogEvent> failures, List<ThreatAlert> alerts) {
        int start = 0;
        while (start < failures.size()) {
            var windowEnd = failures.get(start).timestamp().plus(window);
            int end = start;
            while (end + 1 < failures.size() && !failures.get(end + 1).timestamp().isAfter(windowEnd)) {
                end++;
            }
            int count = end - start + 1;
            if (count >= threshold) {
                alerts.add(buildAlert(source, failures.subList(start, end + 1)));
                start = end + 1;
            } else {
                start++;
            }
        }
    }

    private ThreatAlert buildAlert(String source, List<LogEvent> burst) {
        int count = burst.size();
        long spanSeconds = Duration.between(burst.get(0).timestamp(), burst.get(count - 1).timestamp()).getSeconds();
        var users = new TreeSet<String>();
        for (LogEvent event : burst) {
            if (event.user() != null) {
                users.add(event.user());
            }
        }
        Severity severity = count >= 2 * threshold ? Severity.CRITICAL : Severity.HIGH;
        String explanation = count + " failed logins from " + source + " within " + spanSeconds
                + " s (rule: at least " + threshold + " failures within " + window.getSeconds() + " s). Users tried: "
                + String.join(", ", users) + ".";
        return new ThreatAlert(UUID.randomUUID().toString(), NAME, severity,
                burst.get(count - 1).timestamp(), source, explanation, burst);
    }
}
