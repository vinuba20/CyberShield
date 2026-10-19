package com.cybermonitor.correlation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.ThreatAlert;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;

/** Ranks incident event types by their learned probability of preceding other types. */
public final class PrecedenceRootCauseRanker implements RootCauseRanker {

    private final PrecedenceStatistics statistics;

    public PrecedenceRootCauseRanker(PrecedenceStatistics statistics) {
        this.statistics = Objects.requireNonNull(statistics, "statistics must not be null");
    }

    @Override
    public List<RootCauseCandidate> rank(Incident incident) {
        Objects.requireNonNull(incident, "incident must not be null");

        Map<String, LogEvent> earliestEventByType = earliestEventByType(incident);
        if (earliestEventByType.size() < 2) {
            return List.of();
        }

        List<String> eventTypes = earliestEventByType.keySet().stream().sorted().toList();
        Map<String, List<PairEvidence>> evidenceByType = new HashMap<>();
        for (String eventType : eventTypes) {
            evidenceByType.put(eventType, new ArrayList<>());
        }

        for (int firstIndex = 0; firstIndex < eventTypes.size(); firstIndex++) {
            String firstType = eventTypes.get(firstIndex);
            for (int secondIndex = firstIndex + 1; secondIndex < eventTypes.size(); secondIndex++) {
                String secondType = eventTypes.get(secondIndex);
                OptionalDouble firstBeforeSecond =
                        statistics.probabilityBefore(firstType, secondType);
                if (firstBeforeSecond.isEmpty()) {
                    return List.of();
                }
                double probability = firstBeforeSecond.getAsDouble();
                evidenceByType.get(firstType).add(new PairEvidence(secondType, probability));
                evidenceByType.get(secondType).add(new PairEvidence(firstType, 1.0 - probability));
            }
        }

        List<ScoredCandidate> scoredCandidates = new ArrayList<>();
        for (String eventType : eventTypes) {
            List<PairEvidence> pairEvidence = evidenceByType.get(eventType);
            double score = pairEvidence.stream().mapToDouble(PairEvidence::probability).average().orElseThrow();
            String explanation = explanation(eventType, score, pairEvidence);
            LogEvent representative = earliestEventByType.get(eventType);
            scoredCandidates.add(new ScoredCandidate(
                    new RootCauseCandidate(eventType, representative.source(), score, explanation),
                    representative.timestamp()));
        }

        scoredCandidates.sort(Comparator
                .comparingDouble((ScoredCandidate candidate) -> candidate.candidate().score()).reversed()
                .thenComparing(ScoredCandidate::earliestTimestamp)
                .thenComparing(candidate -> candidate.candidate().eventType())
                .thenComparing(candidate -> candidate.candidate().source()));

        return scoredCandidates.stream()
                .limit(3)
                .map(ScoredCandidate::candidate)
                .toList();
    }

    private static Map<String, LogEvent> earliestEventByType(Incident incident) {
        Map<String, LogEvent> earliestByType = new HashMap<>();
        for (ThreatAlert alert : incident.alerts()) {
            for (LogEvent event : alert.evidence()) {
                earliestByType.merge(event.eventType(), event,
                        (current, candidate) -> {
                            int timeOrder = current.timestamp().compareTo(candidate.timestamp());
                            return timeOrder < 0 || (timeOrder == 0
                                    && current.source().compareTo(candidate.source()) <= 0) ? current : candidate;
                        });
            }
        }
        return earliestByType;
    }

    private static String explanation(String eventType, double score, List<PairEvidence> pairEvidence) {
        StringBuilder explanation = new StringBuilder()
                .append("Score ")
                .append(format(score))
                .append(" is the average probability that ")
                .append(eventType)
                .append(" precedes the other event types: ");
        for (int index = 0; index < pairEvidence.size(); index++) {
            if (index > 0) {
                explanation.append("; ");
            }
            PairEvidence pair = pairEvidence.get(index);
            explanation.append(eventType)
                    .append(" before ")
                    .append(pair.otherEventType())
                    .append(" = ")
                    .append(format(pair.probability()));
        }
        return explanation.toString();
    }

    private static String format(double value) {
        return String.format(Locale.ROOT, "%.4f", value);
    }

    private record PairEvidence(String otherEventType, double probability) {
    }

    private record ScoredCandidate(RootCauseCandidate candidate, java.time.Instant earliestTimestamp) {
    }
}
