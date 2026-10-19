package com.cybermonitor.ui;

import com.cybermonitor.export.CsvExporter;
import com.cybermonitor.filter.AlertFilter;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.service.AlertService;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.DatePicker;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Alerts screen: filter bar, alert table, and below it the explanation and evidence events
 * of the selected alert (so every alert can be checked).
 */
class AlertsView extends BorderPane {

    private final AlertService alertService;
    private final CsvExporter exporter;

    private final ComboBox<String> severityBox = new ComboBox<>();
    private final TextField sourceField = new TextField();
    private final TextField eventTypeField = new TextField();
    private final DatePicker fromPicker = new DatePicker();
    private final DatePicker toPicker = new DatePicker();
    private final Label countLabel = new Label();

    private final TableView<ThreatAlert> table = new TableView<>();
    private final TextArea explanation = new TextArea();
    private final TableView<LogEvent> evidenceTable = new TableView<>();

    private List<ThreatAlert> shown = List.of();

    AlertsView(AlertService alertService, CsvExporter exporter) {
        this.alertService = alertService;
        this.exporter = exporter;
        setTop(buildFilterBar());
        setCenter(buildBody());
        refresh();
    }

    private HBox buildFilterBar() {
        severityBox.getItems().add(UiSupport.ANY);
        for (Severity severity : Severity.values()) {
            severityBox.getItems().add(severity.name());
        }
        severityBox.setValue(UiSupport.ANY);
        sourceField.setPromptText("Source contains");
        eventTypeField.setPromptText("Event type");
        fromPicker.setPromptText("From (UTC)");
        toPicker.setPromptText("To (UTC)");

        Button apply = new Button("Apply");
        apply.setOnAction(e -> refresh());
        Button reset = new Button("Reset");
        reset.setOnAction(e -> {
            severityBox.setValue(UiSupport.ANY);
            sourceField.clear();
            eventTypeField.clear();
            fromPicker.setValue(null);
            toPicker.setValue(null);
            refresh();
        });
        Button export = new Button("Export CSV...");
        export.setOnAction(e -> exportCsv());

        HBox bar = new HBox(8, new Label("Severity"), severityBox, sourceField, eventTypeField,
                fromPicker, toPicker, apply, reset, export, countLabel);
        bar.setPadding(new Insets(10));
        return bar;
    }

    private SplitPane buildBody() {
        table.getColumns().add(UiSupport.<ThreatAlert>textColumn("Time (UTC)", 150, a -> UiSupport.time(a.timestamp())));
        table.getColumns().add(UiSupport.<ThreatAlert>severityColumn("Severity", ThreatAlert::severity));
        table.getColumns().add(UiSupport.<ThreatAlert>textColumn("Rule", 150, ThreatAlert::ruleName));
        table.getColumns().add(UiSupport.<ThreatAlert>textColumn("Source", 130, ThreatAlert::source));
        table.getColumns().add(UiSupport.<ThreatAlert>textColumn("Explanation", 520, ThreatAlert::explanation));
        table.getSelectionModel().selectedItemProperty().addListener((obs, old, alert) -> showDetail(alert));

        explanation.setEditable(false);
        explanation.setWrapText(true);
        explanation.setPrefRowCount(3);

        evidenceTable.getColumns().add(UiSupport.<LogEvent>textColumn("Time (UTC)", 150, e -> UiSupport.time(e.timestamp())));
        evidenceTable.getColumns().add(UiSupport.<LogEvent>textColumn("Event type", 120, LogEvent::eventType));
        evidenceTable.getColumns().add(UiSupport.<LogEvent>textColumn("Source", 130, LogEvent::source));
        evidenceTable.getColumns().add(UiSupport.<LogEvent>textColumn("User", 100, e -> e.user() == null ? "" : e.user()));
        evidenceTable.getColumns().add(UiSupport.<LogEvent>textColumn("Original line", 520, LogEvent::rawLine));

        VBox detail = new VBox(6, new Label("Why this alert was raised"), explanation,
                new Label("Evidence events"), evidenceTable);
        detail.setPadding(new Insets(8));
        VBox.setVgrow(evidenceTable, javafx.scene.layout.Priority.ALWAYS);

        SplitPane split = new SplitPane(table, detail);
        split.setOrientation(javafx.geometry.Orientation.VERTICAL);
        split.setDividerPositions(0.55);
        return split;
    }

    private void showDetail(ThreatAlert alert) {
        if (alert == null) {
            explanation.clear();
            evidenceTable.getItems().clear();
            return;
        }
        explanation.setText(alert.ruleName() + " (" + alert.severity() + "): " + alert.explanation());
        evidenceTable.setItems(FXCollections.observableArrayList(alert.evidence()));
    }

    /** Reloads the alerts from the database using the current filter. */
    final void refresh() {
        AlertFilter filter;
        try {
            Severity severity = UiSupport.severityOrNull(severityBox.getValue());
            filter = new AlertFilter(severity == null ? Set.of() : Set.of(severity),
                    UiSupport.startOfDay(fromPicker.getValue()), UiSupport.endOfDay(toPicker.getValue()),
                    eventTypeField.getText(), sourceField.getText(), null);
        } catch (IllegalArgumentException e) {
            UiSupport.error("Invalid filter: " + e.getMessage());
            return;
        }
        try {
            shown = alertService.search(filter);
        } catch (RuntimeException e) {
            UiSupport.error("Cannot load alerts: " + e.getMessage());
            return;
        }
        table.setItems(FXCollections.observableArrayList(shown));
        countLabel.setText(shown.size() + " alerts");
    }

    private void exportCsv() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export alerts");
        chooser.setInitialFileName("alerts.csv");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV files", "*.csv"));
        var file = chooser.showSaveDialog(getScene().getWindow());
        if (file == null) {
            return;
        }
        try {
            exporter.exportAlerts(shown, Path.of(file.getPath()));
            UiSupport.info("Exported " + shown.size() + " alerts to " + file.getName());
        } catch (RuntimeException e) {
            UiSupport.error("Export failed: " + e.getMessage());
        }
    }
}
