package com.cybermonitor.evaluation;

/**
 * Measured results of one evaluation run. Every field is computed from the run, never typed in.
 *
 * @param events              events in the dataset
 * @param normalEvents        events that are not part of an injected attack
 * @param attacks             injected attacks
 * @param alerts              raw alerts raised
 * @param truePositiveAlerts  alerts whose evidence includes at least one attack event
 * @param falsePositiveAlerts alerts with no attack event in their evidence
 * @param attacksDetected     attacks that have at least one true-positive alert
 * @param incidents           incidents after correlation
 * @param attacksFragmented   detected attacks whose alerts ended up in more than one incident
 * @param mergedIncidents     incidents containing alerts of more than one attack
 * @param falseIncidents      incidents with no true-positive alert at all
 * @param elapsedMillis       time for detection plus correlation (after one warm-up run)
 */
public record EvaluationReport(
        long events, long normalEvents, int attacks,
        int alerts, int truePositiveAlerts, int falsePositiveAlerts,
        int attacksDetected, int incidents, int attacksFragmented, int mergedIncidents, int falseIncidents,
        double elapsedMillis) {

    /** Share of alerts that point at a real attack. */
    public double precision() {
        return Metrics.precision(truePositiveAlerts, falsePositiveAlerts);
    }

    /** Share of injected attacks found by at least one alert. */
    public double recall() {
        return Metrics.recall(attacksDetected, attacks - attacksDetected);
    }

    public double f1() {
        return Metrics.f1(precision(), recall());
    }

    /** False alerts divided by normal events (the definition used in the PRD). */
    public double falsePositiveRate() {
        return Metrics.ratio(falsePositiveAlerts, normalEvents);
    }

    /** 1 - incidents / alerts: how much shorter the analyst's list gets. */
    public double alertReduction() {
        return alerts == 0 ? 0.0 : 1.0 - (double) incidents / alerts;
    }

    public double eventsPerSecond() {
        return elapsedMillis <= 0.0 ? 0.0 : events / (elapsedMillis / 1000.0);
    }

    public String toMarkdown() {
        return String.join("\n",
                "| Measure | Value |",
                "|---|---|",
                "| Events (normal) | " + events + " (" + normalEvents + ") |",
                "| Injected attacks | " + attacks + " |",
                "| Raw alerts (true / false) | " + alerts + " (" + truePositiveAlerts + " / " + falsePositiveAlerts + ") |",
                "| Alert precision | " + pct(precision()) + " |",
                "| Attack recall | " + pct(recall()) + " (" + attacksDetected + " of " + attacks + ") |",
                "| F1 | " + String.format("%.3f", f1()) + " |",
                "| False-positive rate (false alerts / normal events) | " + pct(falsePositiveRate()) + " |",
                "| Incidents after correlation | " + incidents + " |",
                "| Alert reduction (1 - incidents / alerts) | " + pct(alertReduction()) + " |",
                "| Attacks split over several incidents | " + attacksFragmented + " |",
                "| Incidents mixing several attacks | " + mergedIncidents + " |",
                "| Incidents with no real attack | " + falseIncidents + " |",
                "| Detection + correlation time | " + String.format("%.1f ms (%.0f events/s)", elapsedMillis, eventsPerSecond()) + " |",
                "");
    }

    static String pct(double value) {
        return String.format("%.1f%%", value * 100.0);
    }
}
