package com.cybermonitor.service;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.repository.IncidentRepository;

import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Incident workflow on top of the repository: list, open, change status, add notes. */
public class DefaultIncidentService implements IncidentService {

    private static final DateTimeFormatter NOTE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final IncidentRepository repository;
    private final Clock clock;

    public DefaultIncidentService(IncidentRepository repository, Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    /** Most severe first, then newest first. */
    @Override
    public List<Incident> listIncidents() {
        return repository.findAll().stream()
                .sorted(Comparator.comparing(Incident::severity).reversed()
                        .thenComparing(DefaultIncidentService::lastAlertTime, Comparator.reverseOrder()))
                .toList();
    }

    @Override
    public Optional<Incident> findIncident(String incidentId) {
        return repository.findById(incidentId);
    }

    @Override
    public Incident changeStatus(String incidentId, IncidentStatus newStatus) {
        Objects.requireNonNull(newStatus, "newStatus must not be null");
        Incident updated = require(incidentId).withStatus(newStatus);
        repository.save(updated);
        return updated;
    }

    @Override
    public Incident addNote(String incidentId, String note) {
        if (note == null || note.isBlank()) {
            throw new IllegalArgumentException("note must not be blank");
        }
        Incident incident = require(incidentId);
        String line = "[" + NOTE_TIME.format(clock.instant()) + "] " + note.strip();
        String notes = incident.notes().isEmpty() ? line : incident.notes() + "\n" + line;
        Incident updated = incident.withNotes(notes);
        repository.save(updated);
        return updated;
    }

    private Incident require(String incidentId) {
        return repository.findById(incidentId)
                .orElseThrow(() -> new CyberShieldException("No incident with id " + incidentId));
    }

    private static java.time.Instant lastAlertTime(Incident incident) {
        return incident.alerts().isEmpty() ? java.time.Instant.EPOCH
                : incident.alerts().get(incident.alerts().size() - 1).timestamp();
    }
}
