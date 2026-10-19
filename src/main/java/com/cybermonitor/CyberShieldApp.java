package com.cybermonitor;

import com.cybermonitor.config.AppConfig;
import com.cybermonitor.service.StartupCheckService;
import com.cybermonitor.ui.DashboardView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

/**
 * JavaFX entry point. Starts the Spring context, checks the database and shows a window.
 */
public class CyberShieldApp extends Application {

    private static final Logger log = LoggerFactory.getLogger(CyberShieldApp.class);

    private AnnotationConfigApplicationContext context;
    private boolean databaseConnected;

    @Override
    public void init() {
        context = new AnnotationConfigApplicationContext(AppConfig.class);
        log.info("Spring context started");
        databaseConnected = context.getBean(StartupCheckService.class).checkDatabase();
    }

    @Override
    public void start(Stage stage) {
        DashboardView dashboard = new DashboardView();
        dashboard.setPrefSize(1180, 860);
        stage.setTitle("CyberShield Desktop");
        stage.setScene(new Scene(dashboard, 1180, 860));
        stage.show();

        if (!databaseConnected) {
            log.warn("Dashboard is showing its unavailable state because SQLite did not connect");
        } else {
            log.info("Dashboard is showing its unavailable state because incident and event data providers are not configured");
        }
    }

    @Override
    public void stop() {
        if (context != null) {
            context.close();
            log.info("Spring context closed");
        }
    }
}
