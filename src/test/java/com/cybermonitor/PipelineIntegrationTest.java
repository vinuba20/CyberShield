package com.cybermonitor;

import com.cybermonitor.config.AppConfig;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.parser.AuthLogParser;
import com.cybermonitor.service.AlertService;
import com.cybermonitor.service.IncidentService;
import com.cybermonitor.service.PipelineResult;
import com.cybermonitor.service.PipelineService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End to end through Spring and a real SQLite file: import the sample log, work an incident,
 * "restart" the application (a second Spring context on the same file) and check that nothing was lost.
 */
class PipelineIntegrationTest {

    private AnnotationConfigApplicationContext start(Path database, Map<String, Object> extra) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        java.util.Map<String, Object> properties = new java.util.HashMap<>(extra);
        properties.put(AppConfig.DB_PATH_PROPERTY, database.toString());
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test", properties));
        context.register(AppConfig.class);
        context.refresh();
        return context;
    }

    @Test
    void importWorkAnIncidentRestartAndReload(@TempDir Path folder) {
        Path database = folder.resolve("it.db");
        String incidentId;

        try (AnnotationConfigApplicationContext context = start(database, Map.of())) {
            PipelineResult result = context.getBean(PipelineService.class)
                    .importFile(Path.of("data/sample/auth_sample.log"), new AuthLogParser());
            assertEquals(4, result.alerts().size());
            assertEquals(3, result.incidents().size());

            IncidentService incidents = context.getBean(IncidentService.class);
            incidentId = incidents.listIncidents().get(0).id();
            incidents.changeStatus(incidentId, IncidentStatus.INVESTIGATING);
            incidents.addNote(incidentId, "Blocked the address");
            assertEquals(4, context.getBean(AlertService.class).listAlerts().size());
        }

        try (AnnotationConfigApplicationContext restarted = start(database, Map.of())) {
            IncidentService incidents = restarted.getBean(IncidentService.class);
            assertEquals(3, incidents.listIncidents().size());
            Incident reloaded = incidents.findIncident(incidentId).orElseThrow();
            assertEquals(IncidentStatus.INVESTIGATING, reloaded.status());
            assertTrue(reloaded.notes().contains("Blocked the address"));
            assertTrue(reloaded.alerts().stream().allMatch(a -> !a.evidence().isEmpty()));
        }
    }

    @Test
    void settingsCanBeChangedWithoutTouchingCode(@TempDir Path folder) {
        Map<String, Object> strict = Map.of("cybershield.detection.bruteforce.threshold", "20");

        try (AnnotationConfigApplicationContext context = start(folder.resolve("it2.db"), strict)) {
            PipelineResult result = context.getBean(PipelineService.class)
                    .importFile(Path.of("data/sample/auth_sample.log"), new AuthLogParser());

            // with a threshold of 20 the 8-failure burst is no longer a brute-force alert
            assertTrue(result.alerts().stream().noneMatch(a -> a.ruleName().equals("BRUTE_FORCE")));
        }
    }
}
