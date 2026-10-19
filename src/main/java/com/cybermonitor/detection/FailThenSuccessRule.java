package com.cybermonitor.detection;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Raises an alert when the same user logs in successfully from the same source right after
 * at least {@code failures} failed logins, all within {@code window}. This is the typical
 * sign that a guessed password finally worked.
 *
 * <p>Limitation: a real user who mistypes a password several times triggers it too.
 */
public class FailThenSuccessRule implements DetectionRule {

    public static final String NAME = "FAIL_THEN_SUCCESS";

    private final int failures;
    private final Duration window;

    public FailThenSuccessRule(int failures, Duration window) {
        if (failures < 1) {
            throw new IllegalArgumentException("failures must be at least 1, was " + failures);
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        this.failures = failures;
        this.window = window;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<ThreatAlert> evaluate(List<LogEvent> events) {
        List<LogEvent> sorted = new ArrayList<>(events);
        sorted.sort(Comparator.comparing(LogEvent::timestamp));

        Map<String, List<LogEvent>> pending = new HashMap<>();
        List<ThreatAlert> alerts = new ArrayList<>();
        for (LogEvent event : sorted) {
            String key = event.source() + "|" + event.user();
            if (BruteForceRule.FAILED.equals(event.eventType())) {
                pending.computeIfAbsent(key, k -> new ArrayList<>()).add(event);
            } else if ("LOGIN_OK".equals(event.eventType())) {
                List<LogEvent> earlier = pending.remove(key);
                if (earlier == null) {
                    continue;
                }
                List<LogEvent> recent = new ArrayList<>();
                for (LogEvent failure : earlier) {
                    if (!failure.timestamp().plus(window).isBefore(event.timestamp())) {
                        recent.add(failure);
                    }
                }
                if (recent.size() >= failures) {
                    alerts.add(buildAlert(event, recent));
                }
            }
        }
        return alerts;
    }

    private ThreatAlert buildAlert(LogEvent success, List<LogEvent> recentFailures) {
        List<LogEvent> evidence = new ArrayList<>(recentFailures);
        evidence.add(success);
        long seconds = Duration.between(recentFailures.get(0).timestamp(), success.timestamp()).getSeconds();
        String explanation = recentFailures.size() + " failed logins for user " + success.user() + " from "
                + success.source() + " were followed by a successful login " + seconds
                + " s after the first failure (rule: at least " + failures + " failures then a success within "
                + window.getSeconds() + " s). The account may be compromised.";
        return new ThreatAlert(UUID.randomUUID().toString(), NAME, Severity.CRITICAL,
                success.timestamp(), success.source(), explanation, evidence);
    }
}
