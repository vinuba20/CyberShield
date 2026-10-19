package com.cybermonitor.filter;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Criteria for narrowing a list of alerts. Every null or empty criterion means "any".
 *
 * @param severities accepted severities (empty = any)
 * @param from       earliest alert time, inclusive (null = no limit)
 * @param to         latest alert time, inclusive (null = no limit)
 * @param eventType  an evidence event must have exactly this type (null/blank = any)
 * @param source     alert source must contain this text, ignoring case (null/blank = any)
 * @param ruleName   alert rule must equal this name, ignoring case (null/blank = any)
 */
public record AlertFilter(Set<Severity> severities, Instant from, Instant to,
                          String eventType, String source, String ruleName) {

    public static final AlertFilter ANY = new AlertFilter(Set.of(), null, null, null, null, null);

    public AlertFilter {
        severities = severities == null ? Set.of() : Set.copyOf(severities);
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("from must not be after to");
        }
    }

    public boolean matches(ThreatAlert alert) {
        if (!severities.isEmpty() && !severities.contains(alert.severity())) {
            return false;
        }
        if (from != null && alert.timestamp().isBefore(from)) {
            return false;
        }
        if (to != null && alert.timestamp().isAfter(to)) {
            return false;
        }
        if (!isBlank(source) && !alert.source().toLowerCase().contains(source.strip().toLowerCase())) {
            return false;
        }
        if (!isBlank(ruleName) && !alert.ruleName().equalsIgnoreCase(ruleName.strip())) {
            return false;
        }
        if (!isBlank(eventType)) {
            boolean found = false;
            for (LogEvent event : alert.evidence()) {
                if (event.eventType().equalsIgnoreCase(eventType.strip())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    public List<ThreatAlert> apply(List<ThreatAlert> alerts) {
        return alerts.stream().filter(this::matches).toList();
    }

    private static boolean isBlank(String text) {
        return text == null || text.isBlank();
    }
}
