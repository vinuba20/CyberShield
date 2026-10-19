package com.cybermonitor.evaluation;

import com.cybermonitor.correlation.PrecedenceRootCauseRanker;
import com.cybermonitor.correlation.PrecedenceStatistics;
import com.cybermonitor.correlation.RootCauseRanker;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.ThreatAlert;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Evaluates an earliest-timestamp baseline against a precedence-trained root-cause ranker. */
public final class RootCauseEvaluation {

    public static final List<Long> INJECTED_SKEW_LEVELS_SECONDS = List.of(0L, 1L, 3L);

    private final SyntheticCascadeGenerator generator;

    public RootCauseEvaluation(SyntheticCascadeGenerator generator) {
        this.generator = Objects.requireNonNull(generator, "generator must not be null");
    }

    /**
     * Runs each PRD-required skew level with independent, reproducible training and test
     * datasets. Statistics for each ranker are trained only on that level's training split.
     */
    public EvaluationReport evaluate(
            long trainingSeed, long testSeed, int cascadesPerDataset, Duration skewTolerance) {
        Objects.requireNonNull(skewTolerance, "skewTolerance must not be null");
        if (skewTolerance.isNegative()) {
            throw new IllegalArgumentException("skewTolerance must not be negative");
        }
        if (trainingSeed == testSeed) {
            throw new IllegalArgumentException("trainingSeed and testSeed must be different");
        }
        if (cascadesPerDataset < 1) {
            throw new IllegalArgumentException("cascadesPerDataset must be at least 1");
        }

        List<SkewResult> results = new ArrayList<>(INJECTED_SKEW_LEVELS_SECONDS.size());
        for (long skewSeconds : INJECTED_SKEW_LEVELS_SECONDS) {
            SyntheticCascadeGenerator.DatasetSplit split = generator.generateTrainTestSplit(
                    trainingSeed, testSeed, cascadesPerDataset, skewSeconds);
            PrecedenceStatistics statistics = new PrecedenceStatistics(skewTolerance);
            statistics.train(split.training().cascades().stream()
                    .map(SyntheticCascadeGenerator.GeneratedCascade::incident)
                    .toList());
            RootCauseRanker ranker = new PrecedenceRootCauseRanker(statistics);
            results.add(evaluateSkew(split, ranker, skewTolerance, skewSeconds));
        }

        return new EvaluationReport(trainingSeed, testSeed, cascadesPerDataset,
                skewTolerance, results);
    }

    private static SkewResult evaluateSkew(
            SyntheticCascadeGenerator.DatasetSplit split,
            RootCauseRanker ranker,
            Duration skewTolerance,
            long injectedSkewSeconds) {
        int baselineTop1 = 0;
        int baselineTop3 = 0;
        int rankerTop1 = 0;
        int rankerTop3 = 0;

        for (SyntheticCascadeGenerator.GeneratedCascade cascade : split.test().cascades()) {
            List<String> baselineRanking = earliestTimestampRanking(cascade.incident());
            List<RootCauseCandidate> rankedCandidates = ranker.rank(cascade.incident());
            List<String> rankerRanking = rankedCandidates.stream()
                    .map(RootCauseCandidate::eventType)
                    .toList();
            String expectedRoot = cascade.rootCauseEventType();

            if (!baselineRanking.isEmpty() && baselineRanking.getFirst().equals(expectedRoot)) {
                baselineTop1++;
            }
            if (baselineRanking.stream().limit(3).anyMatch(expectedRoot::equals)) {
                baselineTop3++;
            }
            if (!rankerRanking.isEmpty() && rankerRanking.getFirst().equals(expectedRoot)) {
                rankerTop1++;
            }
            if (rankerRanking.stream().limit(3).anyMatch(expectedRoot::equals)) {
                rankerTop3++;
            }
        }

        int testCaseCount = split.test().cascades().size();
        return new SkewResult(injectedSkewSeconds, split.training().seed(), split.test().seed(),
                split.training().cascadeCount(), testCaseCount, skewTolerance,
                Accuracy.fromCounts(baselineTop1, baselineTop3, testCaseCount),
                Accuracy.fromCounts(rankerTop1, rankerTop3, testCaseCount));
    }

    private static List<String> earliestTimestampRanking(Incident incident) {
        Map<String, LogEvent> earliestByType = new HashMap<>();
        for (ThreatAlert alert : incident.alerts()) {
            for (LogEvent event : alert.evidence()) {
                earliestByType.merge(event.eventType(), event,
                        (current, candidate) -> {
                            int timestampOrder = current.timestamp().compareTo(candidate.timestamp());
                            if (timestampOrder != 0) {
                                return timestampOrder < 0 ? current : candidate;
                            }
                            return current.source().compareTo(candidate.source()) <= 0 ? current : candidate;
                        });
            }
        }
        return earliestByType.values().stream()
                .sorted(Comparator.comparing(LogEvent::timestamp)
                        .thenComparing(LogEvent::eventType)
                        .thenComparing(LogEvent::source))
                .map(LogEvent::eventType)
                .toList();
    }

    public record EvaluationReport(
            long trainingSeed,
            long testSeed,
            int cascadesPerDataset,
            Duration skewTolerance,
            List<SkewResult> results) {

        public EvaluationReport {
            if (trainingSeed == testSeed) {
                throw new IllegalArgumentException("training and test seeds must be different");
            }
            if (cascadesPerDataset < 1) {
                throw new IllegalArgumentException("cascadesPerDataset must be at least 1");
            }
            Objects.requireNonNull(skewTolerance, "skewTolerance must not be null");
            if (skewTolerance.isNegative()) {
                throw new IllegalArgumentException("skewTolerance must not be negative");
            }
            results = List.copyOf(Objects.requireNonNull(results, "results must not be null"));
            if (!results.stream().map(SkewResult::injectedSkewSeconds).toList()
                    .equals(INJECTED_SKEW_LEVELS_SECONDS)) {
                throw new IllegalArgumentException("results must contain the required skew levels in order");
            }
        }

        /** Renders recorded configuration and both methods' measured top-1/top-3 accuracy. */
        public String toTable() {
            StringBuilder output = new StringBuilder()
                    .append("Synthetic root-cause evaluation")
                    .append(System.lineSeparator())
                    .append("trainingSeed=").append(trainingSeed)
                    .append(", testSeed=").append(testSeed)
                    .append(", cascadesPerDataset=").append(cascadesPerDataset)
                    .append(", rankerSkewToleranceSeconds=").append(skewTolerance.toSeconds())
                    .append(System.lineSeparator())
                    .append("Injected skew | Test cases | Baseline top-1 | Baseline top-3 | Ranker top-1 | Ranker top-3")
                    .append(System.lineSeparator());
            for (SkewResult result : results) {
                output.append(result.injectedSkewSeconds()).append(" s")
                        .append(" | ").append(result.testCaseCount())
                        .append(" | ").append(result.baselineAccuracy().formatTop1())
                        .append(" (").append(result.baselineAccuracy().top1Correct()).append("/")
                        .append(result.testCaseCount()).append(")")
                        .append(" | ").append(result.baselineAccuracy().formatTop3())
                        .append(" (").append(result.baselineAccuracy().top3Correct()).append("/")
                        .append(result.testCaseCount()).append(")")
                        .append(" | ").append(result.rankerAccuracy().formatTop1())
                        .append(" (").append(result.rankerAccuracy().top1Correct()).append("/")
                        .append(result.testCaseCount()).append(")")
                        .append(" | ").append(result.rankerAccuracy().formatTop3())
                        .append(" (").append(result.rankerAccuracy().top3Correct()).append("/")
                        .append(result.testCaseCount()).append(")")
                        .append(System.lineSeparator());
            }
            output.append("Results are from synthetic data and do not establish real-world accuracy.");
            return output.toString();
        }
    }

    public record SkewResult(
            long injectedSkewSeconds,
            long trainingSeed,
            long testSeed,
            int trainingCaseCount,
            int testCaseCount,
            Duration skewTolerance,
            Accuracy baselineAccuracy,
            Accuracy rankerAccuracy) {

        public SkewResult {
            if (!INJECTED_SKEW_LEVELS_SECONDS.contains(injectedSkewSeconds)) {
                throw new IllegalArgumentException("unsupported injected skew level: " + injectedSkewSeconds);
            }
            if (trainingSeed == testSeed) {
                throw new IllegalArgumentException("training and test seeds must be different");
            }
            if (trainingCaseCount < 1 || testCaseCount < 1) {
                throw new IllegalArgumentException("training and test case counts must be positive");
            }
            Objects.requireNonNull(skewTolerance, "skewTolerance must not be null");
            if (skewTolerance.isNegative()) {
                throw new IllegalArgumentException("skewTolerance must not be negative");
            }
            Objects.requireNonNull(baselineAccuracy, "baselineAccuracy must not be null");
            Objects.requireNonNull(rankerAccuracy, "rankerAccuracy must not be null");
            if (baselineAccuracy.testCaseCount() != testCaseCount
                    || rankerAccuracy.testCaseCount() != testCaseCount) {
                throw new IllegalArgumentException("accuracy denominators must match testCaseCount");
            }
        }
    }

    public record Accuracy(int top1Correct, int top3Correct, int testCaseCount) {

        public Accuracy {
            if (testCaseCount < 1) {
                throw new IllegalArgumentException("testCaseCount must be positive");
            }
            if (top1Correct < 0 || top1Correct > testCaseCount
                    || top3Correct < 0 || top3Correct > testCaseCount
                    || top1Correct > top3Correct) {
                throw new IllegalArgumentException("correct counts must satisfy 0 <= top1 <= top3 <= test cases");
            }
        }

        public static Accuracy fromCounts(int top1Correct, int top3Correct, int testCaseCount) {
            return new Accuracy(top1Correct, top3Correct, testCaseCount);
        }

        public double top1Accuracy() {
            return (double) top1Correct / testCaseCount;
        }

        public double top3Accuracy() {
            return (double) top3Correct / testCaseCount;
        }

        public String formatTop1() {
            return formatPercentage(top1Accuracy());
        }

        public String formatTop3() {
            return formatPercentage(top3Accuracy());
        }

        private static String formatPercentage(double accuracy) {
            return String.format(Locale.ROOT, "%.2f%%", accuracy * 100.0);
        }
    }
}
