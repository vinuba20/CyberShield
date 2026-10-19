package com.cybermonitor.service;

import com.cybermonitor.filter.AlertFilter;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.repository.AlertRepository;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Read access to alerts for the UI: list, filter and open one with its evidence. */
public class AlertService {

    private final AlertRepository repository;

    public AlertService(AlertRepository repository) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
    }

    /** Alerts matching the filter, most severe first, then newest first. */
    public List<ThreatAlert> search(AlertFilter filter) {
        return filter.apply(repository.findAll()).stream()
                .sorted(Comparator.comparing(ThreatAlert::severity).reversed()
                        .thenComparing(ThreatAlert::timestamp, Comparator.reverseOrder()))
                .toList();
    }

    public List<ThreatAlert> listAlerts() {
        return search(AlertFilter.ANY);
    }

    public Optional<ThreatAlert> findAlert(String alertId) {
        return repository.findById(alertId);
    }
}
