package com.cybermonitor.detection;

import com.cybermonitor.anomaly.AnomalyDetector;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.ThreatAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Runs every rule and anomaly detector over the events and merges their alerts by time.
 * A rule that throws is logged and skipped, so one faulty rule cannot stop the others.
 */
public class DefaultDetectionEngine implements DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DefaultDetectionEngine.class);

    private final List<DetectionRule> rules;
    private final List<AnomalyDetector> detectors;

    public DefaultDetectionEngine(List<DetectionRule> rules, List<AnomalyDetector> detectors) {
        this.rules = List.copyOf(rules);
        this.detectors = List.copyOf(detectors);
    }

    @Override
    public List<ThreatAlert> detect(List<LogEvent> events) {
        List<ThreatAlert> alerts = new ArrayList<>();
        for (DetectionRule rule : rules) {
            try {
                alerts.addAll(rule.evaluate(events));
            } catch (RuntimeException e) {
                log.error("Rule {} failed and was skipped", rule.name(), e);
            }
        }
        for (AnomalyDetector detector : detectors) {
            try {
                alerts.addAll(detector.detect(events));
            } catch (RuntimeException e) {
                log.error("Anomaly detector {} failed and was skipped", detector.getClass().getSimpleName(), e);
            }
        }
        alerts.sort(Comparator.comparing(ThreatAlert::timestamp));
        log.info("Detection: {} events -> {} alerts", events.size(), alerts.size());
        return alerts;
    }
}
