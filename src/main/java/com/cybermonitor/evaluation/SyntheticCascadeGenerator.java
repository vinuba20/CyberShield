package com.cybermonitor.evaluation;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * Generates labeled synthetic alarm cascades for root-cause experiments.
 *
 * <p>Each cascade contains a pump fault followed by pressure, handler, and recipe alarms.
 * Event intervals are independently selected from 10 through 20 seconds. Each timestamp
 * receives independently sampled integer clock skew in the inclusive range
 * {@code [-maxClockSkewSeconds, maxClockSkewSeconds]}. All generated event messages
 * and raw lines identify the data as synthetic.
 */
public final class SyntheticCascadeGenerator {

    private static final Instant FIRST_CASCADE_START = Instant.parse("2026-10-18T10:00:00Z");
    private static final long CASCADE_START_INTERVAL_SECONDS = 3_600L;
    private static final long MIN_STAGE_INTERVAL_SECONDS = 10L;
    private static final long MAX_STAGE_INTERVAL_SECONDS = 20L;

    private static final List<AlarmStage> CASCADE_STAGES = List.of(
            new AlarmStage("PUMP_FAULT", "Pump-1", "ROOT_CAUSE"),
            new AlarmStage("PRESSURE_HIGH", "Pump-1", "DOWNSTREAM_ALARM"),
            new AlarmStage("HANDLER_ALARM", "Wafer-Handler-1", "DOWNSTREAM_ALARM"),
            new AlarmStage("RECIPE_ABORT", "Recipe-Controller-1", "DOWNSTREAM_ALARM"));

    /**
     * Generates a reproducible dataset. Skew is applied independently per event and can
     * therefore change the observed order while preserving the causal root-cause label.
     */
    public Dataset generateDataset(long seed, int cascadeCount, long maxClockSkewSeconds) {
        validate(cascadeCount, maxClockSkewSeconds);
        Random random = new Random(seed);
        List<GeneratedCascade> cascades = new ArrayList<>(cascadeCount);

        for (int index = 0; index < cascadeCount; index++) {
            cascades.add(generateCascade(seed, index, maxClockSkewSeconds, random));
        }
        return new Dataset(seed, cascadeCount, maxClockSkewSeconds, cascades);
    }

    /**
     * Generates independent training and test datasets from distinct seeds.
     */
    public DatasetSplit generateTrainTestSplit(
            long trainingSeed, long testSeed, int cascadesPerDataset, long maxClockSkewSeconds) {
        if (trainingSeed == testSeed) {
            throw new IllegalArgumentException("trainingSeed and testSeed must be different");
        }
        Dataset training = generateDataset(trainingSeed, cascadesPerDataset, maxClockSkewSeconds);
        Dataset test = generateDataset(testSeed, cascadesPerDataset, maxClockSkewSeconds);
        return new DatasetSplit(training, test);
    }

    private static GeneratedCascade generateCascade(
            long seed, int index, long maxClockSkewSeconds, Random random) {
        String cascadeId = "synthetic-" + seed + "-" + index;
        long startOffset = Math.multiplyExact((long) index, CASCADE_START_INTERVAL_SECONDS);
        Instant cascadeStart = FIRST_CASCADE_START.plusSeconds(startOffset);
        long causalOffsetSeconds = 0L;
        List<LogEvent> events = new ArrayList<>(CASCADE_STAGES.size());

        for (int stageIndex = 0; stageIndex < CASCADE_STAGES.size(); stageIndex++) {
            if (stageIndex > 0) {
                causalOffsetSeconds += random.nextLong(
                        MIN_STAGE_INTERVAL_SECONDS, MAX_STAGE_INTERVAL_SECONDS + 1);
            }

            AlarmStage stage = CASCADE_STAGES.get(stageIndex);
            long clockSkewSeconds = randomSkew(random, maxClockSkewSeconds);
            Instant timestamp;
            try {
                timestamp = cascadeStart.plusSeconds(causalOffsetSeconds).plusSeconds(clockSkewSeconds);
            } catch (DateTimeException exception) {
                throw new IllegalArgumentException("clock skew produced a timestamp outside the supported range",
                        exception);
            }
            String eventId = cascadeId + "-" + stage.eventType();
            String syntheticDetails = "synthetic=true cascade=" + cascadeId
                    + " role=" + stage.role()
                    + " causalOffsetSeconds=" + causalOffsetSeconds
                    + " clockSkewSeconds=" + clockSkewSeconds;
            String rawLine = "SYNTHETIC," + cascadeId + "," + timestamp + ","
                    + stage.source() + "," + stage.eventType() + "," + syntheticDetails;
            events.add(new LogEvent(eventId, timestamp, stage.source(), stage.eventType(),
                    null, null, syntheticDetails, rawLine));
        }

        List<ThreatAlert> alerts = new ArrayList<>(events.size());
        for (LogEvent event : events) {
            alerts.add(new ThreatAlert(cascadeId + "-alert-" + event.eventType(),
                    "SYNTHETIC_CASCADE", Severity.LOW, event.timestamp(), event.source(),
                    "Synthetic cascade event " + event.eventType() + "; " + event.message(),
                    List.of(event)));
        }
        Incident incident = new Incident(cascadeId, "Synthetic alarm cascade", Severity.LOW,
                IncidentStatus.OPEN, alerts, List.of(), "Synthetic generated incident");
        LogEvent rootCause = events.getFirst();
        return new GeneratedCascade(cascadeId, incident, rootCause.eventType(), rootCause.source());
    }

    private static long randomSkew(Random random, long maximumSkewSeconds) {
        if (maximumSkewSeconds == 0L) {
            return 0L;
        }
        long magnitude = random.nextLong(maximumSkewSeconds + 1L);
        return random.nextBoolean() ? magnitude : -magnitude;
    }

    private static void validate(int cascadeCount, long maxClockSkewSeconds) {
        if (cascadeCount < 1) {
            throw new IllegalArgumentException("cascadeCount must be at least 1");
        }
        if (maxClockSkewSeconds < 0 || maxClockSkewSeconds == Long.MAX_VALUE) {
            throw new IllegalArgumentException("maxClockSkewSeconds must be non-negative and less than Long.MAX_VALUE");
        }
    }

    public record Dataset(long seed, int cascadeCount, long maxClockSkewSeconds, List<GeneratedCascade> cascades) {

        public Dataset {
            if (cascadeCount < 1) {
                throw new IllegalArgumentException("cascadeCount must be at least 1");
            }
            if (maxClockSkewSeconds < 0 || maxClockSkewSeconds == Long.MAX_VALUE) {
                throw new IllegalArgumentException("maxClockSkewSeconds must be non-negative and less than Long.MAX_VALUE");
            }
            cascades = List.copyOf(Objects.requireNonNull(cascades, "cascades must not be null"));
            if (cascades.size() != cascadeCount) {
                throw new IllegalArgumentException("cascadeCount must match the number of cascades");
            }
        }
    }

    public record DatasetSplit(Dataset training, Dataset test) {

        public DatasetSplit {
            Objects.requireNonNull(training, "training must not be null");
            Objects.requireNonNull(test, "test must not be null");
            if (training.seed() == test.seed()) {
                throw new IllegalArgumentException("training and test seeds must be different");
            }
        }
    }

    public record GeneratedCascade(
            String id, Incident incident, String rootCauseEventType, String rootCauseSource) {

        public GeneratedCascade {
            Objects.requireNonNull(id, "id must not be null");
            Objects.requireNonNull(incident, "incident must not be null");
            Objects.requireNonNull(rootCauseEventType, "rootCauseEventType must not be null");
            Objects.requireNonNull(rootCauseSource, "rootCauseSource must not be null");
        }
    }

    private record AlarmStage(String eventType, String source, String role) {
    }
}
