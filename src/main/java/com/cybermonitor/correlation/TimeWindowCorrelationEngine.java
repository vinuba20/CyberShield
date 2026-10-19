package com.cybermonitor.correlation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Groups alerts into incidents. Two alerts are related when they are at most {@code window}
 * apart in time and match on at least one enabled criterion: same source, same triggering rule,
 * or a shared evidence event type. Relatedness is transitive, so a chain of related alerts
 * becomes one incident, and groups bridged by a new alert are merged.
 */
public class TimeWindowCorrelationEngine implements CorrelationEngine {

    private final Duration window;
    private final boolean matchSource;
    private final boolean matchRule;
    private final boolean matchEventType;

    public TimeWindowCorrelationEngine(Duration window, boolean matchSource, boolean matchRule,
                                       boolean matchEventType) {
        if (window == null || window.isNegative()) {
            throw new IllegalArgumentException("window must not be negative");
        }
        if (!matchSource && !matchRule && !matchEventType) {
            throw new IllegalArgumentException("at least one match criterion must be enabled");
        }
        this.window = window;
        this.matchSource = matchSource;
        this.matchRule = matchRule;
        this.matchEventType = matchEventType;
    }

    @Override
    public List<Incident> correlate(List<ThreatAlert> alerts) {
        List<ThreatAlert> sorted = new ArrayList<>(alerts);
        sorted.sort(Comparator.comparing(ThreatAlert::timestamp));

        List<List<ThreatAlert>> groups = new ArrayList<>();
        for (ThreatAlert alert : sorted) {
            List<ThreatAlert> target = null;
            for (var iterator = groups.iterator(); iterator.hasNext(); ) {
                List<ThreatAlert> group = iterator.next();
                if (!isRelated(alert, group)) {
                    continue;
                }
                if (target == null) {
                    target = group;
                } else {
                    target.addAll(group);
                    iterator.remove();
                }
            }
            if (target == null) {
                target = new ArrayList<>();
                groups.add(target);
            }
            target.add(alert);
        }

        List<Incident> incidents = new ArrayList<>();
        for (List<ThreatAlert> group : groups) {
            group.sort(Comparator.comparing(ThreatAlert::timestamp));
            incidents.add(toIncident(group));
        }
        incidents.sort(Comparator.comparing((Incident i) -> i.alerts().get(0).timestamp()));
        return incidents;
    }

    private boolean isRelated(ThreatAlert alert, List<ThreatAlert> group) {
        for (ThreatAlert other : group) {
            Duration gap = Duration.between(alert.timestamp(), other.timestamp()).abs();
            if (gap.compareTo(window) > 0) {
                continue;
            }
            if (matchSource && alert.source().equals(other.source())) {
                return true;
            }
            if (matchRule && alert.ruleName().equals(other.ruleName())) {
                return true;
            }
            if (matchEventType && sharesEventType(alert, other)) {
                return true;
            }
        }
        return false;
    }

    private boolean sharesEventType(ThreatAlert a, ThreatAlert b) {
        Set<String> typesA = eventTypes(a);
        for (String type : eventTypes(b)) {
            if (typesA.contains(type)) {
                return true;
            }
        }
        return false;
    }

    private Set<String> eventTypes(ThreatAlert alert) {
        Set<String> types = new LinkedHashSet<>();
        for (LogEvent event : alert.evidence()) {
            types.add(event.eventType());
        }
        return types;
    }

    private Incident toIncident(List<ThreatAlert> group) {
        Severity severity = Severity.LOW;
        Set<String> rules = new LinkedHashSet<>();
        Set<String> sources = new LinkedHashSet<>();
        for (ThreatAlert alert : group) {
            if (alert.severity().compareTo(severity) > 0) {
                severity = alert.severity();
            }
            rules.add(alert.ruleName());
            sources.add(alert.source());
        }
        String where = sources.size() == 1 ? sources.iterator().next() : sources.size() + " sources";
        String title = String.join(" + ", rules) + " on " + where
                + (group.size() > 1 ? " (" + group.size() + " alerts)" : "");
        return new Incident(UUID.randomUUID().toString(), title, severity, IncidentStatus.OPEN,
                group, List.of(), "");
    }
}
