package com.cybermonitor.filter;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.Severity;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Criteria for narrowing a list of incidents. Every null or empty criterion means "any".
 * Time range, event type, source and rule are applied to the incident's alerts: the incident
 * matches when at least one alert satisfies all of those together.
 *
 * @param statuses   accepted statuses (empty = any)
 * @param severities accepted incident severities (empty = any)
 * @param alertCriteria the alert-level criteria (time, event type, source, rule); its own
 *                      severity set is ignored here, use {@code severities} for the incident
 */
public record IncidentFilter(Set<IncidentStatus> statuses, Set<Severity> severities, AlertFilter alertCriteria) {

    public static final IncidentFilter ANY = new IncidentFilter(Set.of(), Set.of(), AlertFilter.ANY);

    public IncidentFilter {
        statuses = statuses == null ? Set.of() : Set.copyOf(statuses);
        severities = severities == null ? Set.of() : Set.copyOf(severities);
        alertCriteria = alertCriteria == null ? AlertFilter.ANY : alertCriteria;
    }

    public boolean matches(Incident incident) {
        if (!statuses.isEmpty() && !statuses.contains(incident.status())) {
            return false;
        }
        if (!severities.isEmpty() && !severities.contains(incident.severity())) {
            return false;
        }
        AlertFilter alertsOnly = new AlertFilter(Set.of(), alertCriteria.from(), alertCriteria.to(),
                alertCriteria.eventType(), alertCriteria.source(), alertCriteria.ruleName());
        if (alertsOnly.equals(AlertFilter.ANY)) {
            return true;
        }
        return incident.alerts().stream().anyMatch(alertsOnly::matches);
    }

    public List<Incident> apply(List<Incident> incidents) {
        return incidents.stream().filter(this::matches).toList();
    }
}
