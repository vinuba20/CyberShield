package com.cybermonitor.evaluation;

import com.cybermonitor.correlation.TimeWindowCorrelationEngine;
import com.cybermonitor.detection.BruteForceRule;
import com.cybermonitor.detection.DefaultDetectionEngine;
import com.cybermonitor.detection.DetectionRule;
import com.cybermonitor.detection.FailThenSuccessRule;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line evaluation: generates seeded datasets, runs the rules and correlation, and prints a
 * Markdown report. Run it with
 * {@code mvn -q compile exec:java -Dexec.mainClass=com.cybermonitor.evaluation.EvaluationRunner -Dexec.args="42 docs/evaluation-report.md"}
 * or directly from IntelliJ. Arguments: [seed] [output file].
 */
public final class EvaluationRunner {

    private static final long[] SEEDS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    private EvaluationRunner() {
    }

    public static void main(String[] args) throws IOException {
        long seed = args.length > 0 ? Long.parseLong(args[0]) : 42L;
        String report = buildReport(seed);
        System.out.println(report);
        if (args.length > 1) {
            Files.writeString(Path.of(args[1]), report, StandardCharsets.UTF_8);
            System.out.println("Report written to " + args[1]);
        }
    }

    public static String buildReport(long seed) {
        StringBuilder out = new StringBuilder();
        LabeledDataset dataset = DatasetGenerator.standard(seed).generate();
        out.append("# Evaluation: alerts vs incidents\n\n");
        out.append("All numbers below were measured by running `EvaluationRunner` on seeded synthetic data; ")
                .append("nothing is typed in by hand. Re-run it to reproduce them (timings depend on the machine).\n\n");

        out.append("## 1. Main run (seed ").append(seed).append(", default settings)\n\n");
        out.append("Settings: brute force = 5 failures within 10 s; fail-then-success = 3 failures then a success ")
                .append("within 60 s; correlation window = 300 s, matched by source.\n\n");
        out.append(evaluator(5, 3, 300).evaluate(dataset).toMarkdown()).append('\n');

        out.append("## 2. Which rule finds what (seed ").append(seed).append(")\n\n");
        out.append("| Rules | Alerts | Precision | Recall | F1 | FP rate |\n|---|---|---|---|---|---|\n");
        out.append(ruleRow("Brute force only", evaluator(5, 0, 300).evaluate(dataset)));
        out.append(ruleRow("Fail-then-success only", evaluator(0, 3, 300).evaluate(dataset)));
        out.append(ruleRow("Both", evaluator(5, 3, 300).evaluate(dataset))).append('\n');

        out.append("## 3. Brute-force threshold sweep (seed ").append(seed).append(", fail-then-success on)\n\n");
        out.append("| Threshold (failures in 10 s) | Alerts | Precision | Recall | F1 | FP rate |\n|---|---|---|---|---|---|\n");
        for (int threshold : new int[]{3, 5, 8, 10}) {
            out.append(ruleRow(String.valueOf(threshold), evaluator(threshold, 3, 300).evaluate(dataset)));
        }
        out.append('\n');

        out.append("## 4. Correlation window sweep (seed ").append(seed).append(")\n\n");
        out.append("| Window | Alerts | Incidents | Reduction | Attacks split | Incidents mixing attacks |\n|---|---|---|---|---|---|\n");
        for (int window : new int[]{0, 60, 300, 900}) {
            EvaluationReport r = evaluator(5, 3, window).evaluate(dataset);
            out.append("| ").append(window).append(" s | ").append(r.alerts()).append(" | ").append(r.incidents())
                    .append(" | ").append(EvaluationReport.pct(r.alertReduction())).append(" | ")
                    .append(r.attacksFragmented()).append(" | ").append(r.mergedIncidents()).append(" |\n");
        }
        out.append('\n');

        out.append("## 5. Stability over 10 seeds (default settings)\n\n");
        List<EvaluationReport> runs = new ArrayList<>();
        for (long s : SEEDS) {
            runs.add(evaluator(5, 3, 300).evaluate(DatasetGenerator.standard(s).generate()));
        }
        out.append("| Measure | Mean | Min | Max |\n|---|---|---|---|\n");
        out.append(statRow("Alert precision", runs, EvaluationReport::precision));
        out.append(statRow("Attack recall", runs, EvaluationReport::recall));
        out.append(statRow("F1", runs, EvaluationReport::f1));
        out.append(statRow("False-positive rate", runs, EvaluationReport::falsePositiveRate));
        out.append(statRow("Alert reduction", runs, EvaluationReport::alertReduction));
        out.append('\n');

        out.append("## 6. How to read this\n\n")
                .append("- Precision = true alerts / all alerts. A true alert cites at least one injected-attack event.\n")
                .append("- Recall = attacks with at least one true alert / all injected attacks.\n")
                .append("- FP rate = false alerts / normal events (the PRD definition, not the textbook one).\n")
                .append("- Alert reduction = 1 - incidents / alerts.\n")
                .append("- The data is synthetic and the attack types are simple, so the results show that the pipeline works ")
                .append("as designed. They are not a claim about real-world accuracy.\n")
                .append("- Known weaknesses the data exposes: forgetful users who fail 3 or more times and then succeed look ")
                .append("like compromises (false alerts), and low-and-slow attacks are missed by the short-window brute-force rule.\n");
        return out.toString();
    }

    private static AlertsVsIncidentsEvaluator evaluator(int bruteForceThreshold, int failThenSuccessFailures,
                                                        int correlationSeconds) {
        List<DetectionRule> rules = new ArrayList<>();
        if (bruteForceThreshold > 0) {
            rules.add(new BruteForceRule(bruteForceThreshold, Duration.ofSeconds(10)));
        }
        if (failThenSuccessFailures > 0) {
            rules.add(new FailThenSuccessRule(failThenSuccessFailures, Duration.ofSeconds(60)));
        }
        return new AlertsVsIncidentsEvaluator(new DefaultDetectionEngine(rules, List.of()),
                new TimeWindowCorrelationEngine(Duration.ofSeconds(correlationSeconds), true, false, false));
    }

    private static String ruleRow(String label, EvaluationReport r) {
        return "| " + label + " | " + r.alerts() + " | " + EvaluationReport.pct(r.precision()) + " | "
                + EvaluationReport.pct(r.recall()) + " | " + String.format("%.3f", r.f1()) + " | "
                + EvaluationReport.pct(r.falsePositiveRate()) + " |\n";
    }

    private static String statRow(String label, List<EvaluationReport> runs,
                                  java.util.function.ToDoubleFunction<EvaluationReport> measure) {
        double sum = 0;
        double min = Double.MAX_VALUE;
        double max = -Double.MAX_VALUE;
        for (EvaluationReport run : runs) {
            double v = measure.applyAsDouble(run);
            sum += v;
            min = Math.min(min, v);
            max = Math.max(max, v);
        }
        return "| " + label + " | " + EvaluationReport.pct(sum / runs.size()) + " | " + EvaluationReport.pct(min)
                + " | " + EvaluationReport.pct(max) + " |\n";
    }
}
