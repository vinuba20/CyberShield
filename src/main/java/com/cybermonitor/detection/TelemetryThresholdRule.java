package com.cybermonitor.detection;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Raises an explainable alert when a numeric event crosses a configured threshold. */
public final class TelemetryThresholdRule implements DetectionRule {

    public static final String RULE_NAME = "TELEMETRY_THRESHOLD";

    private final double threshold;
    private final Comparison comparison;
    private final Severity severity;

    public TelemetryThresholdRule(double threshold, Comparison comparison, Severity severity) {
        if (!Double.isFinite(threshold)) {
            throw new IllegalArgumentException("threshold must be finite");
        }
        this.threshold = threshold;
        this.comparison = Objects.requireNonNull(comparison, "comparison must not be null");
        this.severity = Objects.requireNonNull(severity, "severity must not be null");
    }

    @Override
    public String name() {
        return RULE_NAME;
    }

    @Override
    public List<ThreatAlert> evaluate(List<LogEvent> events) {
        Objects.requireNonNull(events, "events must not be null");

        List<ThreatAlert> alerts = new ArrayList<>();
        for (LogEvent event : events) {
            Objects.requireNonNull(event, "events must not contain null");
            Double value = event.value();
            if (value == null) {
                continue;
            }
            if (!Double.isFinite(value)) {
                throw new IllegalArgumentException("telemetry value must be finite for event " + event.id());
            }
            if (comparison.isExceeded(value, threshold)) {
                String explanation = "Observed value " + value + " " + comparison.description()
                        + " configured threshold " + threshold;
                alerts.add(new ThreatAlert(UUID.randomUUID().toString(), name(), severity,
                        event.timestamp(), event.source(), explanation, List.of(event)));
            }
        }
        return List.copyOf(alerts);
    }

    public enum Comparison {
        GREATER_THAN("is greater than") {
            @Override
            boolean isExceeded(double value, double threshold) {
                return value > threshold;
            }
        },
        GREATER_THAN_OR_EQUAL("is greater than or equal to") {
            @Override
            boolean isExceeded(double value, double threshold) {
                return value >= threshold;
            }
        },
        LESS_THAN("is less than") {
            @Override
            boolean isExceeded(double value, double threshold) {
                return value < threshold;
            }
        },
        LESS_THAN_OR_EQUAL("is less than or equal to") {
            @Override
            boolean isExceeded(double value, double threshold) {
                return value <= threshold;
            }
        };

        private final String description;

        Comparison(String description) {
            this.description = description;
        }

        abstract boolean isExceeded(double value, double threshold);

        String description() {
            return description;
        }
    }
}
