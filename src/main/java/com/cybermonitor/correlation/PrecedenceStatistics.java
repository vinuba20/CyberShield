package com.cybermonitor.correlation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.ThreatAlert;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;
import java.util.TreeMap;

/**
 * Pairwise event-type precedence learned from historical incidents.
 *
 * <p>Each distinct event-type pair contributes once per incident, using the earliest
 * timestamp of each type in that incident. Pairs tied in time or strictly closer than
 * the configured skew tolerance are counted as undecided. A pair exactly at the
 * tolerance boundary is ordered by timestamp.
 */
public final class PrecedenceStatistics {

    private final Duration skewTolerance;
    private volatile Map<EventTypePair, PairCounts> counts = Map.of();

    public PrecedenceStatistics(Duration skewTolerance) {
        this.skewTolerance = Objects.requireNonNull(skewTolerance, "skewTolerance must not be null");
        if (skewTolerance.isNegative()) {
            throw new IllegalArgumentException("skewTolerance must not be negative");
        }
    }

    public Duration skewTolerance() {
        return skewTolerance;
    }

    /**
     * Replaces the learned statistics with counts from the supplied training incidents.
     */
    public synchronized void train(List<Incident> trainingIncidents) {
        Objects.requireNonNull(trainingIncidents, "trainingIncidents must not be null");
        Map<EventTypePair, MutablePairCounts> trainedCounts = new HashMap<>();
        for (Incident incident : trainingIncidents) {
            Objects.requireNonNull(incident, "trainingIncidents must not contain null");
            Map<String, Instant> earliestByType = earliestTimestampByEventType(incident);
            List<String> eventTypes = earliestByType.keySet().stream().sorted().toList();

            for (int firstIndex = 0; firstIndex < eventTypes.size(); firstIndex++) {
                String firstType = eventTypes.get(firstIndex);
                for (int secondIndex = firstIndex + 1; secondIndex < eventTypes.size(); secondIndex++) {
                    String secondType = eventTypes.get(secondIndex);
                    Instant firstTime = earliestByType.get(firstType);
                    Instant secondTime = earliestByType.get(secondType);
                    MutablePairCounts pairCounts = trainedCounts.computeIfAbsent(
                            new EventTypePair(firstType, secondType), ignored -> new MutablePairCounts());

                    Duration distance = Duration.between(firstTime, secondTime).abs();
                    if (distance.isZero() || distance.compareTo(skewTolerance) < 0) {
                        pairCounts.undecided++;
                    } else if (firstTime.isBefore(secondTime)) {
                        pairCounts.firstBeforeSecond++;
                    } else {
                        pairCounts.secondBeforeFirst++;
                    }
                }
            }
        }

        Map<EventTypePair, PairCounts> immutableCounts = new HashMap<>();
        trainedCounts.forEach((pair, pairCounts) -> immutableCounts.put(pair,
                new PairCounts(pairCounts.firstBeforeSecond, pairCounts.secondBeforeFirst, pairCounts.undecided)));
        counts = Map.copyOf(immutableCounts);
    }

    /**
     * Returns the learned probability that {@code firstEventType} preceded
     * {@code secondEventType}, or empty if the pair has no training observations.
     */
    public OptionalDouble probabilityBefore(String firstEventType, String secondEventType) {
        Objects.requireNonNull(firstEventType, "firstEventType must not be null");
        Objects.requireNonNull(secondEventType, "secondEventType must not be null");
        if (firstEventType.equals(secondEventType)) {
            throw new IllegalArgumentException("event types must be different");
        }
        EventTypePair pair = EventTypePair.of(firstEventType, secondEventType);
        PairCounts pairCounts = counts.get(pair);
        if (pairCounts == null) {
            return OptionalDouble.empty();
        }
        double total = pairCounts.total();
        double firstBeforeSecond = pair.first().equals(firstEventType)
                ? pairCounts.firstBeforeSecond() : pairCounts.secondBeforeFirst();
        return OptionalDouble.of((firstBeforeSecond + 0.5 * pairCounts.undecided()) / total);
    }

    /** Returns immutable training counts in the supplied argument order. */
    public PairCounts countsFor(String firstEventType, String secondEventType) {
        Objects.requireNonNull(firstEventType, "firstEventType must not be null");
        Objects.requireNonNull(secondEventType, "secondEventType must not be null");
        if (firstEventType.equals(secondEventType)) {
            throw new IllegalArgumentException("event types must be different");
        }
        EventTypePair pair = EventTypePair.of(firstEventType, secondEventType);
        PairCounts pairCounts = counts.getOrDefault(pair, PairCounts.EMPTY);
        if (pair.first().equals(firstEventType)) {
            return pairCounts;
        }
        return new PairCounts(pairCounts.secondBeforeFirst(), pairCounts.firstBeforeSecond(), pairCounts.undecided());
    }

    private static Map<String, Instant> earliestTimestampByEventType(Incident incident) {
        Map<String, Instant> earliestByType = new TreeMap<>();
        for (ThreatAlert alert : incident.alerts()) {
            for (LogEvent event : alert.evidence()) {
                earliestByType.merge(event.eventType(), event.timestamp(),
                        (current, candidate) -> current.isBefore(candidate) ? current : candidate);
            }
        }
        return earliestByType;
    }

    public record PairCounts(long firstBeforeSecond, long secondBeforeFirst, long undecided) {

        private static final PairCounts EMPTY = new PairCounts(0, 0, 0);

        public PairCounts {
            if (firstBeforeSecond < 0 || secondBeforeFirst < 0 || undecided < 0) {
                throw new IllegalArgumentException("pair counts must not be negative");
            }
        }

        public long total() {
            return firstBeforeSecond + secondBeforeFirst + undecided;
        }
    }

    private record EventTypePair(String first, String second) {

        private static EventTypePair of(String first, String second) {
            return first.compareTo(second) < 0
                    ? new EventTypePair(first, second)
                    : new EventTypePair(second, first);
        }
    }

    private static final class MutablePairCounts {

        private long firstBeforeSecond;
        private long secondBeforeFirst;
        private long undecided;
    }
}
