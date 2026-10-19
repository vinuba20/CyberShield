package com.cybermonitor.detection;

import com.cybermonitor.anomaly.AnomalyDetector;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.testutil.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultDetectionEngineTest {

    private static DetectionRule rule(String name, List<ThreatAlert> result) {
        return new DetectionRule() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public List<ThreatAlert> evaluate(List<LogEvent> events) {
                return result;
            }
        };
    }

    @Test
    void mergesAlertsFromAllRulesAndDetectorsSortedByTime() {
        ThreatAlert late = Fixtures.alert("A", "s", 30);
        ThreatAlert early = Fixtures.alert("B", "s", 10);
        ThreatAlert middle = Fixtures.alert("C", "s", 20);
        AnomalyDetector detector = events -> List.of(middle);
        DefaultDetectionEngine engine = new DefaultDetectionEngine(
                List.of(rule("A", List.of(late)), rule("B", List.of(early))), List.of(detector));

        List<ThreatAlert> alerts = engine.detect(List.of());

        assertEquals(List.of(early, middle, late), alerts);
    }

    @Test
    void aRuleThatThrowsIsSkippedAndTheOthersStillRun() {
        ThreatAlert good = Fixtures.alert("GOOD", "s", 1);
        DetectionRule broken = new DetectionRule() {
            @Override
            public String name() {
                return "BROKEN";
            }

            @Override
            public List<ThreatAlert> evaluate(List<LogEvent> events) {
                throw new IllegalStateException("boom");
            }
        };
        DefaultDetectionEngine engine = new DefaultDetectionEngine(
                List.of(broken, rule("GOOD", List.of(good))), List.of());

        assertEquals(List.of(good), engine.detect(List.of()));
    }

    @Test
    void worksWithNoRulesAtAll() {
        assertTrue(new DefaultDetectionEngine(List.of(), List.of()).detect(List.of()).isEmpty());
    }
}
