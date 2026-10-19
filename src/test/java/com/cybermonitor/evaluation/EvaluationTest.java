package com.cybermonitor.evaluation;

import com.cybermonitor.correlation.TimeWindowCorrelationEngine;
import com.cybermonitor.detection.BruteForceRule;
import com.cybermonitor.detection.DefaultDetectionEngine;
import com.cybermonitor.detection.FailThenSuccessRule;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.parser.AuthLogParser;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EvaluationTest {

    private AlertsVsIncidentsEvaluator evaluator() {
        return new AlertsVsIncidentsEvaluator(
                new DefaultDetectionEngine(List.of(new BruteForceRule(5, Duration.ofSeconds(10)),
                        new FailThenSuccessRule(3, Duration.ofSeconds(60))), List.of()),
                new TimeWindowCorrelationEngine(Duration.ofSeconds(300), true, false, false));
    }

    // ---- Metrics ----

    @Test
    void metricsFollowTheTextbookFormulas() {
        assertEquals(0.75, Metrics.precision(3, 1), 1e-9);
        assertEquals(0.6, Metrics.recall(3, 2), 1e-9);
        assertEquals(2 * 0.75 * 0.6 / (0.75 + 0.6), Metrics.f1(0.75, 0.6), 1e-9);
        assertEquals(0.25, Metrics.ratio(1, 4), 1e-9);
    }

    @Test
    void zeroDenominatorsGiveZeroNotNaN() {
        assertEquals(0.0, Metrics.precision(0, 0), 0.0);
        assertEquals(0.0, Metrics.recall(0, 0), 0.0);
        assertEquals(0.0, Metrics.f1(0, 0), 0.0);
        assertEquals(0.0, Metrics.ratio(5, 0), 0.0);
    }

    // ---- evaluator on a hand-built dataset with known answers ----

    /** 1 brute-force attack (6 failures), 1 harmless 3-typo user, 10 normal logins. */
    private LabeledDataset handBuilt() {
        List<LogEvent> events = new ArrayList<>();
        Set<String> attackIds = new HashSet<>();
        for (int i = 0; i < 6; i++) {
            LogEvent e = Fixtures.failed("203.0.113.1", "root", i);
            events.add(e);
            attackIds.add(e.id());
        }
        events.add(Fixtures.failed("10.0.0.7", "carol", 1000));
        events.add(Fixtures.failed("10.0.0.7", "carol", 1005));
        events.add(Fixtures.failed("10.0.0.7", "carol", 1010));
        events.add(Fixtures.ok("10.0.0.7", "carol", 1020));
        for (int i = 0; i < 9; i++) {
            events.add(Fixtures.ok("10.0.0." + (20 + i), "user" + i, 2000 + i));
        }
        return new LabeledDataset(0, events, List.of(
                new LabeledDataset.Attack("BRUTE_FORCE-1", "BRUTE_FORCE", "203.0.113.1", attackIds)));
    }

    @Test
    void evaluatorScoresAHandBuiltDatasetExactly() {
        EvaluationReport report = evaluator().evaluate(handBuilt());

        assertEquals(19, report.events());
        assertEquals(13, report.normalEvents());
        assertEquals(1, report.attacks());
        assertEquals(2, report.alerts());              // brute force + carol's fail-then-success
        assertEquals(1, report.truePositiveAlerts());
        assertEquals(1, report.falsePositiveAlerts());
        assertEquals(1, report.attacksDetected());
        assertEquals(0.5, report.precision(), 1e-9);
        assertEquals(1.0, report.recall(), 1e-9);
        assertEquals(1.0 / 13.0, report.falsePositiveRate(), 1e-9);
        assertEquals(2, report.incidents());           // different sources stay apart
        assertEquals(0.0, report.alertReduction(), 1e-9);
        assertEquals(0, report.attacksFragmented());
        assertEquals(0, report.mergedIncidents());
        assertEquals(1, report.falseIncidents());
    }

    @Test
    void anUndetectedAttackLowersRecall() {
        LogEvent slow1 = Fixtures.failed("203.0.113.2", "root", 0);
        LogEvent slow2 = Fixtures.failed("203.0.113.2", "root", 60);
        LabeledDataset dataset = new LabeledDataset(0, List.of(slow1, slow2), List.of(
                new LabeledDataset.Attack("SLOW-1", "LOW_AND_SLOW", "203.0.113.2", Set.of(slow1.id(), slow2.id()))));

        EvaluationReport report = evaluator().evaluate(dataset);

        assertEquals(0, report.alerts());
        assertEquals(0.0, report.recall(), 1e-9);
        assertEquals(0.0, report.alertReduction(), 1e-9);
    }

    @Test
    void alertsFromTheSameSourceAreMergedAndCountAsReduction() {
        List<LogEvent> events = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 6; i++) {
            LogEvent e = Fixtures.failed("203.0.113.3", "root", i);
            events.add(e);
            ids.add(e.id());
        }
        LogEvent success = Fixtures.ok("203.0.113.3", "root", 20);
        events.add(success);
        ids.add(success.id());
        LabeledDataset dataset = new LabeledDataset(0, events, List.of(
                new LabeledDataset.Attack("COMPROMISE-1", "COMPROMISE", "203.0.113.3", ids)));

        EvaluationReport report = evaluator().evaluate(dataset);

        assertEquals(2, report.alerts());     // brute force + fail-then-success
        assertEquals(1, report.incidents());
        assertEquals(0.5, report.alertReduction(), 1e-9);
        assertEquals(1.0, report.precision(), 1e-9);
    }

    @Test
    void reportMarkdownContainsTheMeasuredNumbers() {
        String markdown = evaluator().evaluate(handBuilt()).toMarkdown();

        assertTrue(markdown.contains("| Alert precision | 50.0% |"));
        assertTrue(markdown.contains("| Attack recall | 100.0% (1 of 1) |"));
    }

    // ---- generator ----

    @Test
    void sameSeedGivesIdenticalData() {
        LabeledDataset a = DatasetGenerator.standard(7).generate();
        LabeledDataset b = DatasetGenerator.standard(7).generate();

        assertEquals(a.events(), b.events());
        assertEquals(a.attacks(), b.attacks());
    }

    @Test
    void differentSeedsGiveDifferentData() {
        assertTrue(!DatasetGenerator.standard(1).generate().events()
                .equals(DatasetGenerator.standard(2).generate().events()));
    }

    @Test
    void generatorProducesTheRequestedAttackMixAndSortedEvents() {
        LabeledDataset dataset = DatasetGenerator.standard(3).generate();

        assertEquals(50, dataset.attacks().size());
        assertEquals(25, dataset.attacks().stream().filter(a -> a.type().equals("BRUTE_FORCE")).count());
        assertEquals(15, dataset.attacks().stream().filter(a -> a.type().equals("COMPROMISE")).count());
        assertEquals(10, dataset.attacks().stream().filter(a -> a.type().equals("LOW_AND_SLOW")).count());
        for (int i = 1; i < dataset.events().size(); i++) {
            assertTrue(!dataset.events().get(i).timestamp().isBefore(dataset.events().get(i - 1).timestamp()));
        }
    }

    @Test
    void everyAttackEventExistsAndNoEventBelongsToTwoAttacks() {
        LabeledDataset dataset = DatasetGenerator.standard(4).generate();
        Set<String> allIds = new HashSet<>();
        dataset.events().forEach(e -> allIds.add(e.id()));
        int labelled = 0;
        for (LabeledDataset.Attack attack : dataset.attacks()) {
            assertTrue(allIds.containsAll(attack.eventIds()));
            labelled += attack.eventIds().size();
        }
        assertEquals(labelled, dataset.attackEventIds().size());
        assertEquals(dataset.events().size() - labelled, dataset.normalEventCount());
    }

    @Test
    void generatedRawLinesParseBackToTheSameEvents() throws Exception {
        AuthLogParser parser = new AuthLogParser();
        LabeledDataset dataset = DatasetGenerator.standard(5).generate();

        for (LogEvent event : dataset.events().subList(0, 200)) {
            LogEvent parsed = parser.parseLine(event.rawLine());
            assertEquals(event.timestamp(), parsed.timestamp());
            assertEquals(event.source(), parsed.source());
            assertEquals(event.eventType(), parsed.eventType());
            assertEquals(event.user(), parsed.user());
        }
    }

    @Test
    void runnerReportIsDeterministicExceptForTiming() {
        String a = EvaluationRunner.buildReport(11).replaceAll("\\| Detection \\+ correlation time \\|.*", "");
        String b = EvaluationRunner.buildReport(11).replaceAll("\\| Detection \\+ correlation time \\|.*", "");

        assertEquals(a, b);
        assertTrue(a.contains("## 1. Main run (seed 11"));
    }
}
