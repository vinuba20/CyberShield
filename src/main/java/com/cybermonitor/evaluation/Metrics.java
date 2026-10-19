package com.cybermonitor.evaluation;

/**
 * Shared evaluation formulas, used by both members' evaluations so every number is computed
 * the same way. A ratio with a zero denominator is 0.0 (never NaN), and the report says so.
 */
public final class Metrics {

    private Metrics() {
    }

    /** Share of positive predictions that were right: tp / (tp + fp). */
    public static double precision(long truePositives, long falsePositives) {
        return ratio(truePositives, truePositives + falsePositives);
    }

    /** Share of real positives that were found: tp / (tp + fn). */
    public static double recall(long truePositives, long falseNegatives) {
        return ratio(truePositives, truePositives + falseNegatives);
    }

    /** Harmonic mean of precision and recall. */
    public static double f1(double precision, double recall) {
        return precision + recall == 0.0 ? 0.0 : 2.0 * precision * recall / (precision + recall);
    }

    /** numerator / denominator, or 0.0 when the denominator is zero. */
    public static double ratio(long numerator, long denominator) {
        return denominator == 0 ? 0.0 : (double) numerator / denominator;
    }
}
