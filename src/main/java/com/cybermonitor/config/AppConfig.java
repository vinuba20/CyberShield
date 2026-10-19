package com.cybermonitor.config;

import com.cybermonitor.anomaly.AnomalyDetector;
import com.cybermonitor.correlation.CorrelationEngine;
import com.cybermonitor.correlation.RootCauseRanker;
import com.cybermonitor.correlation.TimeWindowCorrelationEngine;
import com.cybermonitor.detection.BruteForceRule;
import com.cybermonitor.detection.DefaultDetectionEngine;
import com.cybermonitor.detection.DetectionEngine;
import com.cybermonitor.detection.DetectionRule;
import com.cybermonitor.detection.FailThenSuccessRule;
import com.cybermonitor.export.CsvExporter;
import com.cybermonitor.parser.AuthLogParser;
import com.cybermonitor.repository.AlertRepository;
import com.cybermonitor.repository.EventRepository;
import com.cybermonitor.repository.IncidentRepository;
import com.cybermonitor.repository.sqlite.SchemaInitializer;
import com.cybermonitor.repository.sqlite.SqliteAlertRepository;
import com.cybermonitor.repository.sqlite.SqliteConnectionFactory;
import com.cybermonitor.repository.sqlite.SqliteEventRepository;
import com.cybermonitor.repository.sqlite.SqliteIncidentRepository;
import com.cybermonitor.service.AlertService;
import com.cybermonitor.service.DefaultIncidentService;
import com.cybermonitor.service.IncidentService;
import com.cybermonitor.service.LogImportService;
import com.cybermonitor.service.PipelineService;
import com.cybermonitor.service.StartupCheckService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * Spring configuration: creates the shared objects and wires them together.
 *
 * <p>The database file defaults to {@code cybershield.db} in the working directory.
 * Override it with the JVM option {@code -Dcybershield.db.path=...}. Detection and correlation
 * settings live in {@code cybershield.properties}.
 *
 * <p>Rules ({@link DetectionRule}), anomaly detectors ({@link AnomalyDetector}), parsers and an optional
 * {@link RootCauseRanker} are collected automatically: to add one, define one more {@code @Bean}.
 */
@Configuration
@PropertySource("classpath:cybershield.properties")
public class AppConfig {

    public static final String DB_PATH_PROPERTY = "cybershield.db.path";
    public static final String DEFAULT_DB_PATH = "cybershield.db";

    // ---- database ----

    @Bean
    public SqliteConnectionFactory sqliteConnectionFactory(Environment environment) {
        String dbPath = environment.getProperty(DB_PATH_PROPERTY, DEFAULT_DB_PATH);
        return new SqliteConnectionFactory(Path.of(dbPath));
    }

    @Bean(initMethod = "initialize")
    public SchemaInitializer schemaInitializer(SqliteConnectionFactory connections) {
        return new SchemaInitializer(connections);
    }

    @Bean
    @DependsOn("schemaInitializer")
    public StartupCheckService startupCheckService(SqliteConnectionFactory connections) {
        return new StartupCheckService(connections);
    }

    @Bean
    @DependsOn("schemaInitializer")
    public EventRepository eventRepository(SqliteConnectionFactory connections) {
        return new SqliteEventRepository(connections);
    }

    @Bean
    @DependsOn("schemaInitializer")
    public AlertRepository alertRepository(SqliteConnectionFactory connections) {
        return new SqliteAlertRepository(connections);
    }

    @Bean
    @DependsOn("schemaInitializer")
    public IncidentRepository incidentRepository(SqliteConnectionFactory connections, AlertRepository alerts) {
        return new SqliteIncidentRepository(connections, alerts);
    }

    // ---- parsing and detection ----

    @Bean
    public AuthLogParser authLogParser() {
        return new AuthLogParser();
    }

    @Bean
    public LogImportService logImportService() {
        return new LogImportService();
    }

    @Bean
    public BruteForceRule bruteForceRule(Environment environment) {
        return new BruteForceRule(
                environment.getProperty("cybershield.detection.bruteforce.threshold", Integer.class, 5),
                seconds(environment, "cybershield.detection.bruteforce.window.seconds", 10));
    }

    @Bean
    public FailThenSuccessRule failThenSuccessRule(Environment environment) {
        return new FailThenSuccessRule(
                environment.getProperty("cybershield.detection.failthensuccess.failures", Integer.class, 3),
                seconds(environment, "cybershield.detection.failthensuccess.window.seconds", 60));
    }

    @Bean
    public DetectionEngine detectionEngine(List<DetectionRule> rules, ObjectProvider<AnomalyDetector> detectors) {
        return new DefaultDetectionEngine(rules, detectors.orderedStream().toList());
    }

    // ---- correlation ----

    @Bean
    public CorrelationEngine correlationEngine(Environment environment) {
        return new TimeWindowCorrelationEngine(
                seconds(environment, "cybershield.correlation.window.seconds", 300),
                environment.getProperty("cybershield.correlation.match.source", Boolean.class, true),
                environment.getProperty("cybershield.correlation.match.rule", Boolean.class, false),
                environment.getProperty("cybershield.correlation.match.eventtype", Boolean.class, false));
    }

    // ---- services ----

    @Bean
    public PipelineService pipelineService(LogImportService importService, EventRepository events,
                                           DetectionEngine detection, AlertRepository alerts,
                                           CorrelationEngine correlation, IncidentRepository incidents,
                                           ObjectProvider<RootCauseRanker> rankers) {
        return new PipelineService(importService, events, detection, alerts, correlation, incidents,
                rankers.getIfAvailable());
    }

    @Bean
    public IncidentService incidentService(IncidentRepository incidents) {
        return new DefaultIncidentService(incidents, Clock.systemUTC());
    }

    @Bean
    public AlertService alertService(AlertRepository alerts) {
        return new AlertService(alerts);
    }

    @Bean
    public CsvExporter csvExporter() {
        return new CsvExporter();
    }

    private static Duration seconds(Environment environment, String key, int defaultSeconds) {
        return Duration.ofSeconds(environment.getProperty(key, Integer.class, defaultSeconds));
    }
}
