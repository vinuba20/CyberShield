package com.cybermonitor.service;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.ThreatAlert;

import java.util.List;

/** What one run of the pipeline produced. */
public record PipelineResult(ImportResult imported, List<ThreatAlert> alerts, List<Incident> incidents) {

    public PipelineResult {
        alerts = List.copyOf(alerts);
        incidents = List.copyOf(incidents);
    }

    public String summary() {
        return imported.summary() + " -> " + alerts.size() + " alerts -> " + incidents.size() + " incidents";
    }
}
