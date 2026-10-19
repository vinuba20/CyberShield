package com.cybermonitor.anomaly;

import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Detects telemetry outliers using each reading's preceding numeric observations.
 *
 * <p>Each series is keyed by source and event type. A reading is compared with exactly
 * the previous {@code windowSize} numeric readings in its series; it is not included
 * in its own baseline. A full window is required before detection starts, and the
 * standard deviation is the population standard deviation of that window. Readings are
 * ordered by timestamp. Readings sharing a timestamp are evaluated against the same
 * prior history before any of them are added to it.
 */
public final class RollingZScoreAnomalyDetector implements AnomalyDetector {

    public static final String DETECTOR_NAME = "TELEMETRY_Z_SCORE";

    private final int windowSize;
    private final double zScoreThreshold;
    private final Severity severity;

    public RollingZScoreAnomalyDetector(int windowSize, double zScoreThreshold, Severity severity) {
        if (windowSize < 1) {
            throw new IllegalArgumentException("windowSize must be at least 1");
        }
        if (!Double.isFinite(zScoreThreshold) || zScoreThreshold <= 0.0) {
            throw new IllegalArgumentException("zScoreThreshold must be finite and positive");
        }
        this.windowSize = windowSize;
        this.zScoreThreshold = zScoreThreshold;
        this.severity = Objects.requireNonNull(severity, "severity must not be null");
    }

    @Override
    public List<ThreatAlert> detect(List<LogEvent> events) {
        Objects.requireNonNull(events, "events must not be null");
        List<LogEvent> orderedEvents = new ArrayList<>(events.size());
        for (LogEvent event : events) {
            orderedEvents.add(Objects.requireNonNull(event, "events must not contain null"));
        }
        orderedEvents.sort(Comparator.comparing(LogEvent::timestamp));

        Map<SeriesKey, ArrayDeque<Double>> histories = new HashMap<>();
        List<ThreatAlert> alerts = new ArrayList<>();
        int groupStart = 0;
        while (groupStart < orderedEvents.size()) {
            int groupEnd = groupStart + 1;
            while (groupEnd < orderedEvents.size()
                    && orderedEvents.get(groupStart).timestamp().equals(orderedEvents.get(groupEnd).timestamp())) {
                groupEnd++;
            }

            for (int index = groupStart; index < groupEnd; index++) {
                LogEvent event = orderedEvents.get(index);
                Double value = event.value();
                if (value == null) {
                    continue;
                }
                if (!Double.isFinite(value)) {
                    throw new IllegalArgumentException("telemetry value must be finite for event " + event.id());
                }

                SeriesKey key = new SeriesKey(event.source(), event.eventType());
                ArrayDeque<Double> history = histories.computeIfAbsent(key, ignored -> new ArrayDeque<>());
                if (history.size() == windowSize) {
                    double mean = mean(history);
                    double standardDeviation = populationStandardDeviation(history, mean);
                    double zScore = zScore(value, mean, standardDeviation);
                    if (Math.abs(zScore) >= zScoreThreshold) {
                        String explanation = "Observed value " + value + " has rolling mean " + mean
                                + ", population standard deviation " + standardDeviation + ", and z-score "
                                + zScore + " (absolute z-score meets configured threshold "
                                + zScoreThreshold + "); the reading is anomalous";
                        alerts.add(new ThreatAlert(UUID.randomUUID().toString(), DETECTOR_NAME, severity,
                                event.timestamp(), event.source(), explanation, List.of(event)));
                    }
                }
            }

            for (int index = groupStart; index < groupEnd; index++) {
                LogEvent event = orderedEvents.get(index);
                if (event.value() != null) {
                    SeriesKey key = new SeriesKey(event.source(), event.eventType());
                    ArrayDeque<Double> history = histories.computeIfAbsent(key, ignored -> new ArrayDeque<>());
                    history.addLast(event.value());
                    if (history.size() > windowSize) {
                        history.removeFirst();
                    }
                }
            }
            groupStart = groupEnd;
        }
        return List.copyOf(alerts);
    }

    private static double mean(ArrayDeque<Double> values) {
        double sum = 0.0;
        for (double value : values) {
            sum += value;
        }
        return sum / values.size();
    }

    private static double populationStandardDeviation(ArrayDeque<Double> values, double mean) {
        double squaredDifferences = 0.0;
        for (double value : values) {
            double difference = value - mean;
            squaredDifferences += difference * difference;
        }
        return Math.sqrt(squaredDifferences / values.size());
    }

    private static double zScore(double value, double mean, double standardDeviation) {
        if (standardDeviation == 0.0) {
            return value == mean ? 0.0 : Math.copySign(Double.POSITIVE_INFINITY, value - mean);
        }
        return (value - mean) / standardDeviation;
    }

    private record SeriesKey(String source, String eventType) {
    }
}
