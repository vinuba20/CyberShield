package com.cybermonitor.evaluation;

import com.cybermonitor.correlation.CorrelationEngine;
import com.cybermonitor.detection.DetectionEngine;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.ThreatAlert;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Runs detection and correlation on a labeled dataset and scores the result against the ground truth.
 *
 * <p>An alert is a true positive when at least one of its evidence events belongs to an injected attack.
 * An attack counts as detected when at least one true-positive alert cites its events.
 */
public class AlertsVsIncidentsEvaluator {

    private final DetectionEngine detection;
    private final CorrelationEngine correlation;

    public AlertsVsIncidentsEvaluator(DetectionEngine detection, CorrelationEngine correlation) {
        this.detection = detection;
        this.correlation = correlation;
    }

    public EvaluationReport evaluate(LabeledDataset dataset) {
        List<LogEvent> events = dataset.events();

        detection.detect(events); // warm-up, so the timing is not dominated by class loading
        long begin = System.nanoTime();
        List<ThreatAlert> alerts = detection.detect(events);
        List<Incident> incidents = correlation.correlate(alerts);
        double elapsedMillis = (System.nanoTime() - begin) / 1_000_000.0;

        Map<String, String> attackOfEvent = new HashMap<>();
        for (LabeledDataset.Attack attack : dataset.attacks()) {
            for (String eventId : attack.eventIds()) {
                attackOfEvent.put(eventId, attack.id());
            }
        }

        Map<String, Set<String>> attackIdsOfAlert = new HashMap<>();
        int truePositive = 0;
        for (ThreatAlert alert : alerts) {
            Set<String> hit = new HashSet<>();
            for (LogEvent event : alert.evidence()) {
                String attackId = attackOfEvent.get(event.id());
                if (attackId != null) {
                    hit.add(attackId);
                }
            }
            attackIdsOfAlert.put(alert.id(), hit);
            if (!hit.isEmpty()) {
                truePositive++;
            }
        }

        Set<String> detected = new HashSet<>();
        Map<String, Set<String>> incidentsOfAttack = new HashMap<>();
        int merged = 0;
        int falseIncidents = 0;
        for (Incident incident : incidents) {
            Set<String> attacksInIncident = new HashSet<>();
            for (ThreatAlert alert : incident.alerts()) {
                attacksInIncident.addAll(attackIdsOfAlert.get(alert.id()));
            }
            if (attacksInIncident.isEmpty()) {
                falseIncidents++;
            }
            if (attacksInIncident.size() > 1) {
                merged++;
            }
            for (String attackId : attacksInIncident) {
                detected.add(attackId);
                incidentsOfAttack.computeIfAbsent(attackId, key -> new HashSet<>()).add(incident.id());
            }
        }
        int fragmented = 0;
        for (Set<String> ids : incidentsOfAttack.values()) {
            if (ids.size() > 1) {
                fragmented++;
            }
        }

        return new EvaluationReport(events.size(), dataset.normalEventCount(), dataset.attacks().size(),
                alerts.size(), truePositive, alerts.size() - truePositive, detected.size(), incidents.size(),
                fragmented, merged, falseIncidents, elapsedMillis);
    }
}
