package com.cybermonitor.evaluation;

import com.cybermonitor.model.LogEvent;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Synthetic events together with the ground truth of which events belong to injected attacks.
 *
 * @param seed    the random seed that produced the data, so a run can be repeated exactly
 * @param events  all events, sorted by time
 * @param attacks the injected attacks
 */
public record LabeledDataset(long seed, List<LogEvent> events, List<Attack> attacks) {

    /** One injected attack and the ids of all events that belong to it. */
    public record Attack(String id, String type, String source, Set<String> eventIds) {
        public Attack {
            eventIds = Set.copyOf(eventIds);
        }
    }

    public LabeledDataset {
        events = List.copyOf(events);
        attacks = List.copyOf(attacks);
    }

    public Set<String> attackEventIds() {
        Set<String> ids = new HashSet<>();
        for (Attack attack : attacks) {
            ids.addAll(attack.eventIds());
        }
        return ids;
    }

    /** Events that are not part of any attack. */
    public long normalEventCount() {
        return events.size() - attackEventIds().size();
    }
}
