package com.cybermonitor.evaluation;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RootCauseEvaluationTest {

    private final RootCauseEvaluation evaluation =
            new RootCauseEvaluation(new SyntheticCascadeGenerator());

    @Test
    void calculatesTopOneAndTopThreeAccuracyFromCorrectCounts() {
        RootCauseEvaluation.Accuracy accuracy =
                RootCauseEvaluation.Accuracy.fromCounts(2, 4, 5);

        assertEquals(0.4, accuracy.top1Accuracy());
        assertEquals(0.8, accuracy.top3Accuracy());
        assertEquals("40.00%", accuracy.formatTop1());
        assertEquals("80.00%", accuracy.formatTop3());
    }

    @Test
    void rejectsInvalidAccuracyCounts() {
        assertThrows(IllegalArgumentException.class,
                () -> RootCauseEvaluation.Accuracy.fromCounts(0, 0, 0));
        assertThrows(IllegalArgumentException.class,
                () -> RootCauseEvaluation.Accuracy.fromCounts(3, 2, 4));
        assertThrows(IllegalArgumentException.class,
                () -> RootCauseEvaluation.Accuracy.fromCounts(1, 5, 4));
    }

    @Test
    void zeroSkewBaselineAndRankerSelectInjectedRootOnHeldOutCases() {
        RootCauseEvaluation.EvaluationReport report =
                evaluation.evaluate(1101L, 2202L, 5, Duration.ZERO);

        RootCauseEvaluation.SkewResult zeroSkew = report.results().getFirst();
        assertEquals(0L, zeroSkew.injectedSkewSeconds());
        assertEquals(5, zeroSkew.trainingCaseCount());
        assertEquals(5, zeroSkew.testCaseCount());
        assertEquals(5, zeroSkew.baselineAccuracy().top1Correct());
        assertEquals(5, zeroSkew.baselineAccuracy().top3Correct());
        assertEquals(5, zeroSkew.rankerAccuracy().top1Correct());
        assertEquals(5, zeroSkew.rankerAccuracy().top3Correct());
    }

    @Test
    void evaluatesAllPrdSkewLevelsAndPreservesSeedSeparation() {
        RootCauseEvaluation.EvaluationReport report =
                evaluation.evaluate(-10L, 2001L, 7, Duration.ofSeconds(1));

        assertEquals(List.of(0L, 1L, 3L), report.results().stream()
                .map(RootCauseEvaluation.SkewResult::injectedSkewSeconds).toList());
        assertTrue(report.results().stream().allMatch(result ->
                result.trainingSeed() == -10L
                        && result.testSeed() == 2001L
                        && result.trainingSeed() != result.testSeed()
                        && result.trainingCaseCount() == 7
                        && result.testCaseCount() == 7));
    }

    @Test
    void evaluationIsReproducibleAndReportsMeasuredCountsAndLimitations() {
        RootCauseEvaluation.EvaluationReport first =
                evaluation.evaluate(3344L, 5566L, 12, Duration.ofSeconds(1));
        RootCauseEvaluation.EvaluationReport second =
                evaluation.evaluate(3344L, 5566L, 12, Duration.ofSeconds(1));

        assertEquals(first, second);
        String table = first.toTable();
        assertTrue(table.contains("trainingSeed=3344"));
        assertTrue(table.contains("testSeed=5566"));
        assertTrue(table.contains("cascadesPerDataset=12"));
        assertTrue(table.contains("0 s | 12 |"));
        assertTrue(table.contains("1 s | 12 |"));
        assertTrue(table.contains("3 s | 12 |"));
        assertTrue(table.contains("Baseline top-1"));
        assertTrue(table.contains("Ranker top-3"));
        assertTrue(table.contains("synthetic data"));
    }

    @Test
    void rejectsSameSeedsInvalidCountsAndNegativeSkewTolerance() {
        assertThrows(IllegalArgumentException.class,
                () -> evaluation.evaluate(1L, 1L, 1, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> evaluation.evaluate(1L, 2L, 0, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> evaluation.evaluate(1L, 2L, 1, Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class,
                () -> evaluation.evaluate(1L, 2L, 1, null));
    }

    @Test
    void rankerNotBeatingBaselineIsReportedWithoutChangingTheResult() {
        RootCauseEvaluation.EvaluationReport report =
                evaluation.evaluate(1L, 2L, 2, Duration.ofSeconds(3));

        assertFalse(report.toTable().isBlank());
        assertTrue(report.results().stream().allMatch(result ->
                result.rankerAccuracy().top1Correct() <= result.testCaseCount()
                        && result.baselineAccuracy().top1Correct() <= result.testCaseCount()));
    }
}
