package com.cybermonitor.ui;

import com.cybermonitor.export.CsvExporter;
import com.cybermonitor.filter.AlertFilter;
import com.cybermonitor.filter.IncidentFilter;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.IncidentStatus;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.Severity;
import com.cybermonitor.model.ThreatAlert;
import com.cybermonitor.service.IncidentService;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Incidents screen: filter bar, incident table, and a detail panel with the grouped alerts,
 * root-cause candidates, status and notes.
 */
class IncidentsView extends BorderPane {

    private final IncidentService incidentService;
    private final CsvExporter exporter;

    private final ComboBox<String> statusBox = new ComboBox<>();
    private final ComboBox<String> severityBox = new ComboBox<>();
    private final TextField sourceField = new TextField();
    private final Label countLabel = new Label();

    private final TableView<Incident> table = new TableView<>();

    private final Label titleLabel = new Label("Select an incident");
    private final ComboBox<IncidentStatus> statusChange = new ComboBox<>();
    private final ListView<String> alertList = new ListView<>();
    private final ListView<String> rootCauseList = new ListView<>();
    private final TextArea notesArea = new TextArea();
    private final TextField newNote = new TextField();

    private List<Incident> shown = List.of();
    private Incident selected;
    private boolean updatingControls;

    IncidentsView(IncidentService incidentService, CsvExporter exporter) {
        this.incidentService = incidentService;
        this.exporter = exporter;
        setTop(buildFilterBar());
        setCenter(buildBody());
        refresh();
    }

    private HBox buildFilterBar() {
        statusBox.getItems().add(UiSupport.ANY);
        for (IncidentStatus status : IncidentStatus.values()) {
            statusBox.getItems().add(status.name());
        }
        statusBox.setValue(UiSupport.ANY);
        severityBox.getItems().add(UiSupport.ANY);
        for (Severity severity : Severity.values()) {
            severityBox.getItems().add(severity.name());
        }
        severityBox.setValue(UiSupport.ANY);
        sourceField.setPromptText("Source contains");

        Button apply = new Button("Apply");
        apply.setOnAction(e -> refresh());
        Button reset = new Button("Reset");
        reset.setOnAction(e -> {
            statusBox.setValue(UiSupport.ANY);
            severityBox.setValue(UiSupport.ANY);
            sourceField.clear();
            refresh();
        });
        Button export = new Button("Export CSV...");
        export.setOnAction(e -> exportCsv());

        HBox bar = new HBox(8, new Label("Status"), statusBox, new Label("Severity"), severityBox, sourceField,
                apply, reset, export, countLabel);
        bar.setPadding(new Insets(10));
        return bar;
    }

    private SplitPane buildBody() {
        table.getColumns().add(UiSupport.<Incident>severityColumn("Severity", Incident::severity));
        table.getColumns().add(UiSupport.<Incident>textColumn("Status", 110, i -> i.status().name()));
        table.getColumns().add(UiSupport.<Incident>textColumn("Title", 330, Incident::title));
        table.getColumns().add(UiSupport.<Incident>textColumn("Alerts", 60, i -> String.valueOf(i.alerts().size())));
        table.getColumns().add(UiSupport.<Incident>textColumn("First alert (UTC)", 150,
                i -> i.alerts().isEmpty() ? "" : UiSupport.time(i.alerts().get(0).timestamp())));
        table.getSelectionModel().selectedItemProperty().addListener((obs, old, incident) -> showDetail(incident));

        statusChange.getItems().addAll(IncidentStatus.values());
        statusChange.setOnAction(e -> {
            if (!updatingControls && selected != null && statusChange.getValue() != null
                    && statusChange.getValue() != selected.status()) {
                changeStatus(statusChange.getValue());
            }
        });

        notesArea.setEditable(false);
        notesArea.setWrapText(true);
        notesArea.setPrefRowCount(4);
        newNote.setPromptText("Write a note");
        HBox.setHgrow(newNote, Priority.ALWAYS);
        Button addNote = new Button("Add note");
        addNote.setOnAction(e -> addNote());
        newNote.setOnAction(e -> addNote());

        titleLabel.setStyle("-fx-font-size: 15px; -fx-font-weight: bold;");
        titleLabel.setWrapText(true);
        alertList.setPrefHeight(120);
        rootCauseList.setPrefHeight(80);

        VBox detail = new VBox(6, titleLabel,
                new HBox(8, new Label("Status"), statusChange),
                new Label("Grouped alerts"), alertList,
                new Label("Likely root causes (best first)"), rootCauseList,
                new Label("Notes"), notesArea, new HBox(8, newNote, addNote));
        detail.setPadding(new Insets(8));

        SplitPane split = new SplitPane(table, detail);
        split.setDividerPositions(0.55);
        return split;
    }

    private void showDetail(Incident incident) {
        selected = incident;
        updatingControls = true;
        try {
            if (incident == null) {
                titleLabel.setText("Select an incident");
                statusChange.setValue(null);
                alertList.getItems().clear();
                rootCauseList.getItems().clear();
                notesArea.clear();
                return;
            }
            titleLabel.setText(incident.title() + "  [" + incident.severity() + "]");
            statusChange.setValue(incident.status());
            List<String> alertLines = new ArrayList<>();
            for (ThreatAlert alert : incident.alerts()) {
                alertLines.add(UiSupport.time(alert.timestamp()) + "  " + alert.ruleName() + "  "
                        + alert.severity() + "  " + alert.explanation());
            }
            alertList.setItems(FXCollections.observableArrayList(alertLines));
            List<String> causeLines = new ArrayList<>();
            int rank = 1;
            for (RootCauseCandidate cause : incident.rootCauses()) {
                causeLines.add(rank++ + ". " + cause.eventType() + " @ " + cause.source()
                        + "  (score " + String.format("%.2f", cause.score()) + ")  " + cause.explanation());
            }
            if (causeLines.isEmpty()) {
                causeLines.add("No root-cause ranking available for this incident.");
            }
            rootCauseList.setItems(FXCollections.observableArrayList(causeLines));
            notesArea.setText(incident.notes());
        } finally {
            updatingControls = false;
        }
    }

    private void changeStatus(IncidentStatus status) {
        try {
            Incident updated = incidentService.changeStatus(selected.id(), status);
            refreshKeeping(updated.id());
        } catch (RuntimeException e) {
            UiSupport.error("Cannot change status: " + e.getMessage());
        }
    }

    private void addNote() {
        if (selected == null) {
            UiSupport.info("Select an incident first.");
            return;
        }
        if (newNote.getText() == null || newNote.getText().isBlank()) {
            return;
        }
        try {
            Incident updated = incidentService.addNote(selected.id(), newNote.getText());
            newNote.clear();
            refreshKeeping(updated.id());
        } catch (RuntimeException e) {
            UiSupport.error("Cannot add note: " + e.getMessage());
        }
    }

    /** Reloads the list and selects the incident with this id again. */
    private void refreshKeeping(String incidentId) {
        refresh();
        for (Incident incident : table.getItems()) {
            if (incident.id().equals(incidentId)) {
                table.getSelectionModel().select(incident);
                return;
            }
        }
    }

    /** Reloads the incidents from the database using the current filter. */
    final void refresh() {
        IncidentFilter filter;
        Set<IncidentStatus> statuses = Set.of();
        if (statusBox.getValue() != null && !UiSupport.ANY.equals(statusBox.getValue())) {
            statuses = Set.of(IncidentStatus.valueOf(statusBox.getValue()));
        }
        Severity severity = UiSupport.severityOrNull(severityBox.getValue());
        filter = new IncidentFilter(statuses, severity == null ? Set.of() : Set.of(severity),
                new AlertFilter(Set.of(), null, null, null, sourceField.getText(), null));
        try {
            shown = filter.apply(incidentService.listIncidents());
        } catch (RuntimeException e) {
            UiSupport.error("Cannot load incidents: " + e.getMessage());
            return;
        }
        table.setItems(FXCollections.observableArrayList(shown));
        countLabel.setText(shown.size() + " incidents");
    }

    private void exportCsv() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export incidents");
        chooser.setInitialFileName("incidents.csv");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV files", "*.csv"));
        var file = chooser.showSaveDialog(getScene().getWindow());
        if (file == null) {
            return;
        }
        try {
            exporter.exportIncidents(shown, Path.of(file.getPath()));
            UiSupport.info("Exported " + shown.size() + " incidents to " + file.getName());
        } catch (RuntimeException e) {
            UiSupport.error("Export failed: " + e.getMessage());
        }
    }
}
