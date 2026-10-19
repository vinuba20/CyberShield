package com.cybermonitor.testutil;

import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.repository.AlertRepository;
import com.cybermonitor.repository.EventRepository;
import com.cybermonitor.repository.IncidentRepository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Map-backed repositories, so service logic can be tested without a database. */
public final class InMemoryRepositories {

    private InMemoryRepositories() {
    }

    public static class Events implements EventRepository {
        public final Map<String, LogEvent> stored = new LinkedHashMap<>();

        @Override
        public void saveAll(List<LogEvent> events) {
            events.forEach(e -> stored.put(e.id(), e));
        }

        @Override
        public List<LogEvent> findAll() {
            return new ArrayList<>(stored.values());
        }

        @Override
        public long count() {
            return stored.size();
        }
    }

    public static class Alerts implements AlertRepository {
        public final Map<String, ThreatAlert> stored = new LinkedHashMap<>();

        @Override
        public void saveAll(List<ThreatAlert> alerts) {
            alerts.forEach(a -> stored.put(a.id(), a));
        }

        @Override
        public List<ThreatAlert> findAll() {
            return new ArrayList<>(stored.values());
        }

        @Override
        public Optional<ThreatAlert> findById(String alertId) {
            return Optional.ofNullable(stored.get(alertId));
        }
    }

    public static class Incidents implements IncidentRepository {
        public final Map<String, Incident> stored = new LinkedHashMap<>();

        @Override
        public void save(Incident incident) {
            stored.put(incident.id(), incident);
        }

        @Override
        public void saveAll(List<Incident> incidents) {
            incidents.forEach(this::save);
        }

        @Override
        public List<Incident> findAll() {
            return new ArrayList<>(stored.values());
        }

        @Override
        public Optional<Incident> findById(String incidentId) {
            return Optional.ofNullable(stored.get(incidentId));
        }
    }
}
