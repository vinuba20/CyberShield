package com.cybermonitor.evaluation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.correlation.PrecedenceRootCauseRanker;
import com.cybermonitor.correlation.PrecedenceStatistics;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SyntheticCascadeGeneratorTest {

    private final SyntheticCascadeGenerator generator = new SyntheticCascadeGenerator();

    @Test
    void sameSeedAndConfigurationReproduceDatasetAndLabels() {
        SyntheticCascadeGenerator.Dataset first = generator.generateDataset(42L, 5, 3L);
        SyntheticCascadeGenerator.Dataset second = generator.generateDataset(42L, 5, 3L);

        assertEquals(first, second);
        assertEquals(first.cascades().stream().map(SyntheticCascadeGenerator.GeneratedCascade::rootCauseEventType)
                .toList(), second.cascades().stream()
                .map(SyntheticCascadeGenerator.GeneratedCascade::rootCauseEventType).toList());
    }

    @Test
    void differentSeedsProduceIndependentDatasetContent() {
        SyntheticCascadeGenerator.Dataset first = generator.generateDataset(100L, 5, 3L);
        SyntheticCascadeGenerator.Dataset second = generator.generateDataset(200L, 5, 3L);

        assertNotEquals(first.cascades(), second.cascades());
        assertNotEquals(first.cascades().getFirst().incident().alerts(),
                second.cascades().getFirst().incident().alerts());
    }

    @Test
    void splitUsesDistinctSeedsAndCarriesLabeledTrainingAndTestCascades() {
        SyntheticCascadeGenerator.DatasetSplit split =
                generator.generateTrainTestSplit(101L, 202L, 4, 0L);

        assertEquals(101L, split.training().seed());
        assertEquals(202L, split.test().seed());
        assertNotEquals(split.training().cascades().getFirst().id(), split.test().cascades().getFirst().id());
        assertTrue(split.training().cascades().stream()
                .allMatch(cascade -> cascade.rootCauseEventType().equals("PUMP_FAULT")
                        && cascade.rootCauseSource().equals("Pump-1")));
    }

    @Test
    void cascadeContainsInjectedRootAndDownstreamAlarmsWithSyntheticMarkings() {
        SyntheticCascadeGenerator.GeneratedCascade cascade =
                generator.generateDataset(42L, 1, 0L).cascades().getFirst();
        List<LogEvent> events = cascade.incident().alerts().stream()
                .flatMap(alert -> alert.evidence().stream())
                .toList();

        assertEquals("PUMP_FAULT", cascade.rootCauseEventType());
        assertEquals(List.of("PUMP_FAULT", "PRESSURE_HIGH", "HANDLER_ALARM", "RECIPE_ABORT"),
                events.stream().map(LogEvent::eventType).toList());
        assertEquals(4, cascade.incident().alerts().size());
        assertTrue(cascade.incident().alerts().stream().allMatch(alert ->
                alert.ruleName().equals("SYNTHETIC_CASCADE")
                        && alert.explanation().contains("synthetic=true")));
        assertTrue(events.stream().allMatch(event -> event.rawLine().startsWith("SYNTHETIC,")));
        assertTrue(events.stream().allMatch(event -> event.message().contains("causalOffsetSeconds=")));
        assertTrue(events.getFirst().message().contains("role=ROOT_CAUSE"));
        assertTrue(events.subList(1, events.size()).stream()
                .allMatch(event -> event.message().contains("role=DOWNSTREAM_ALARM")));
    }

    @Test
    void appliesBoundedClockSkewToCausalTimestamps() {
        SyntheticCascadeGenerator.Dataset zeroSkew = generator.generateDataset(42L, 1, 0L);
        SyntheticCascadeGenerator.Dataset skewed = generator.generateDataset(42L, 1, 3L);
        List<LogEvent> zeroSkewEvents = events(zeroSkew.cascades().getFirst().incident());
        List<LogEvent> skewedEvents = events(skewed.cascades().getFirst().incident());

        assertTrue(zeroSkewEvents.stream().allMatch(event -> event.message().contains("clockSkewSeconds=0")));
        assertTrue(skewedEvents.stream().allMatch(event -> {
            long skew = Long.parseLong(event.message().split("clockSkewSeconds=")[1]);
            return Math.abs(skew) <= 3L;
        }));
        assertTrue(skewedEvents.stream().anyMatch(event ->
                Long.parseLong(event.message().split("clockSkewSeconds=")[1]) != 0L));
        assertFalse(zeroSkewEvents.stream().map(LogEvent::timestamp).toList()
                .equals(skewedEvents.stream().map(LogEvent::timestamp).toList()));
    }

    @Test
    void generatedCascadesContainEnoughEvidenceForPrecedenceTraining() {
        SyntheticCascadeGenerator.Dataset dataset = generator.generateDataset(9L, 6, 3L);

        assertTrue(dataset.cascades().stream().allMatch(cascade ->
                cascade.incident().alerts().stream().flatMap(alert -> alert.evidence().stream())
                        .map(LogEvent::eventType).distinct().count() == 4));
    }

    @Test
    void generatedTrainingStatisticsCanRankHeldOutInjectedRoots() {
        SyntheticCascadeGenerator.DatasetSplit split =
                generator.generateTrainTestSplit(13L, 47L, 10, 3L);
        PrecedenceStatistics statistics = new PrecedenceStatistics(Duration.ZERO);
        statistics.train(split.training().cascades().stream()
                .map(SyntheticCascadeGenerator.GeneratedCascade::incident)
                .toList());
        PrecedenceRootCauseRanker ranker = new PrecedenceRootCauseRanker(statistics);

        assertTrue(split.test().cascades().stream().allMatch(cascade ->
                ranker.rank(cascade.incident()).getFirst().eventType().equals(cascade.rootCauseEventType())));
    }

    @Test
    void rejectsInvalidDatasetAndSplitConfigurations() {
        assertThrows(IllegalArgumentException.class, () -> generator.generateDataset(1L, 0, 0L));
        assertThrows(IllegalArgumentException.class, () -> generator.generateDataset(1L, 1, -1L));
        assertThrows(IllegalArgumentException.class,
                () -> generator.generateDataset(1L, 1, Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> generator.generateTrainTestSplit(1L, 1L, 2, 0L));
        assertThrows(IllegalArgumentException.class, () -> generator.generateTrainTestSplit(1L, 2L, 0, 0L));
        assertThrows(IllegalArgumentException.class, () -> generator.generateTrainTestSplit(1L, 2L, 2, -1L));
    }

    private static List<LogEvent> events(Incident incident) {
        return incident.alerts().stream().flatMap(alert -> alert.evidence().stream()).toList();
    }
}
