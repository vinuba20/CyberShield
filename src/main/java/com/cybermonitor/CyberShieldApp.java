package com.cybermonitor;

import com.cybermonitor.config.AppConfig;
import com.cybermonitor.service.StartupCheckService;
import com.cybermonitor.export.CsvExporter;
import com.cybermonitor.parser.EventParser;
import com.cybermonitor.service.AlertService;
import com.cybermonitor.service.IncidentService;
import com.cybermonitor.service.PipelineService;
import com.cybermonitor.ui.MainWindow;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import java.util.List;

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
        MainWindow window = new MainWindow(
                context.getBean(PipelineService.class),
                context.getBean(AlertService.class),
                context.getBean(IncidentService.class),
                context.getBean(CsvExporter.class),
                List.copyOf(context.getBeansOfType(EventParser.class).values()),
                "SQLite: " + (databaseConnected ? "connected" : "FAILED (see log)"));

        stage.setTitle("CyberShield Desktop");
        stage.setScene(new Scene(window, 1200, 720));
        stage.show();
    }

    @Override
    public void stop() {
        if (context != null) {
            context.close();
            log.info("Spring context closed");
        }
    }
}
