package com.cybermonitor.config;

import com.cybermonitor.anomaly.RollingZScoreAnomalyDetector;
import com.cybermonitor.correlation.PrecedenceRootCauseRanker;
import com.cybermonitor.correlation.PrecedenceStatistics;
import com.cybermonitor.correlation.RootCauseRanker;
import com.cybermonitor.detection.TelemetryThresholdRule;
import com.cybermonitor.model.Severity;
import com.cybermonitor.repository.sqlite.SqliteRootCauseCandidateStore;
import com.cybermonitor.repository.sqlite.SqliteConnectionFactory;
import com.cybermonitor.service.StartupCheckService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;

/**
 * Spring configuration: creates the shared objects and wires them together.
 *
 * <p>The database file defaults to {@code cybershield.db} in the working directory.
 * Override it with the JVM option {@code -Dcybershield.db.path=...}.
 */
@Configuration
public class AppConfig {

    public static final String DB_PATH_PROPERTY = "cybershield.db.path";
    public static final String DEFAULT_DB_PATH = "cybershield.db";
    public static final String TELEMETRY_THRESHOLD_PROPERTY = "cybershield.telemetry.threshold";
    public static final String TELEMETRY_COMPARISON_PROPERTY = "cybershield.telemetry.comparison";
    public static final String TELEMETRY_SEVERITY_PROPERTY = "cybershield.telemetry.severity";
    public static final String ANOMALY_WINDOW_SIZE_PROPERTY = "cybershield.anomaly.window-size";
    public static final String ANOMALY_Z_SCORE_THRESHOLD_PROPERTY = "cybershield.anomaly.z-score-threshold";
    public static final String ANOMALY_SEVERITY_PROPERTY = "cybershield.anomaly.severity";
    public static final String ROOT_CAUSE_SKEW_TOLERANCE_SECONDS_PROPERTY =
            "cybershield.root-cause.skew-tolerance-seconds";

    @Bean
    public SqliteConnectionFactory sqliteConnectionFactory(Environment environment) {
        String dbPath = environment.getProperty(DB_PATH_PROPERTY, DEFAULT_DB_PATH);
        return new SqliteConnectionFactory(Path.of(dbPath));
    }

    @Bean
    public StartupCheckService startupCheckService(SqliteConnectionFactory connections) {
        return new StartupCheckService(connections);
    }

    @Bean
    @Lazy
    public SqliteRootCauseCandidateStore sqliteRootCauseCandidateStore(SqliteConnectionFactory connections) {
        return new SqliteRootCauseCandidateStore(connections);
    }

    @Bean
    @Lazy
    public TelemetryThresholdRule telemetryThresholdRule(Environment environment) {
        double threshold = environment.getRequiredProperty(TELEMETRY_THRESHOLD_PROPERTY, Double.class);
        TelemetryThresholdRule.Comparison comparison = TelemetryThresholdRule.Comparison.valueOf(
                environment.getRequiredProperty(TELEMETRY_COMPARISON_PROPERTY).trim().toUpperCase(Locale.ROOT));
        Severity severity = Severity.valueOf(
                environment.getRequiredProperty(TELEMETRY_SEVERITY_PROPERTY).trim().toUpperCase(Locale.ROOT));
        return new TelemetryThresholdRule(threshold, comparison, severity);
    }

    @Bean
    @Lazy
    public RollingZScoreAnomalyDetector rollingZScoreAnomalyDetector(Environment environment) {
        int windowSize = environment.getRequiredProperty(ANOMALY_WINDOW_SIZE_PROPERTY, Integer.class);
        double zScoreThreshold = environment.getRequiredProperty(ANOMALY_Z_SCORE_THRESHOLD_PROPERTY, Double.class);
        Severity severity = Severity.valueOf(
                environment.getRequiredProperty(ANOMALY_SEVERITY_PROPERTY).trim().toUpperCase(Locale.ROOT));
        return new RollingZScoreAnomalyDetector(windowSize, zScoreThreshold, severity);
    }

    @Bean
    @Lazy
    public PrecedenceStatistics precedenceStatistics(Environment environment) {
        long skewToleranceSeconds =
                environment.getRequiredProperty(ROOT_CAUSE_SKEW_TOLERANCE_SECONDS_PROPERTY, Long.class);
        return new PrecedenceStatistics(Duration.ofSeconds(skewToleranceSeconds));
    }

    @Bean
    @Lazy
    public RootCauseRanker rootCauseRanker(PrecedenceStatistics statistics) {
        return new PrecedenceRootCauseRanker(statistics);
    }
}
