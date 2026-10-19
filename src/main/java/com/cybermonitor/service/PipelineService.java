package com.cybermonitor.service;

import com.cybermonitor.correlation.CorrelationEngine;
import com.cybermonitor.correlation.RootCauseRanker;
import com.cybermonitor.detection.DetectionEngine;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.parser.EventParser;
import com.cybermonitor.repository.AlertRepository;
import com.cybermonitor.repository.EventRepository;
import com.cybermonitor.repository.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The whole flow for one import: parse, save events, detect, save alerts, correlate, save incidents.
 *
 * <p>Detection and correlation run on the newly imported batch only. If a {@link RootCauseRanker}
 * is available (the equipment track adds one), each new incident gets its ranked root causes
 * before it is saved.
 */
public class PipelineService {

    private static final Logger log = LoggerFactory.getLogger(PipelineService.class);

    private final LogImportService importService;
    private final EventRepository events;
    private final DetectionEngine detection;
    private final AlertRepository alerts;
    private final CorrelationEngine correlation;
    private final IncidentRepository incidents;
    private final RootCauseRanker rootCauseRanker; // may be null

    public PipelineService(LogImportService importService, EventRepository events, DetectionEngine detection,
                           AlertRepository alerts, CorrelationEngine correlation, IncidentRepository incidents,
                           RootCauseRanker rootCauseRanker) {
        this.importService = Objects.requireNonNull(importService);
        this.events = Objects.requireNonNull(events);
        this.detection = Objects.requireNonNull(detection);
        this.alerts = Objects.requireNonNull(alerts);
        this.correlation = Objects.requireNonNull(correlation);
        this.incidents = Objects.requireNonNull(incidents);
        this.rootCauseRanker = rootCauseRanker;
    }

    public PipelineResult importFile(Path file, EventParser parser) {
        return process(importService.importFile(file, parser));
    }

    public PipelineResult process(ImportResult imported) {
        List<LogEvent> parsed = imported.events();
        events.saveAll(parsed);

        List<ThreatAlert> raised = detection.detect(parsed);
        alerts.saveAll(raised);

        List<Incident> grouped = correlation.correlate(raised);
        List<Incident> ready = new ArrayList<>();
        for (Incident incident : grouped) {
            ready.add(withRootCauses(incident));
        }
        incidents.saveAll(ready);

        PipelineResult result = new PipelineResult(imported, raised, ready);
        log.info("Pipeline finished: {}", result.summary());
        return result;
    }

    private Incident withRootCauses(Incident incident) {
        if (rootCauseRanker == null) {
            return incident;
        }
        try {
            return incident.withRootCauses(rootCauseRanker.rank(incident));
        } catch (RuntimeException e) {
            log.error("Root-cause ranking failed for incident {}", incident.id(), e);
            return incident;
        }
    }
}
