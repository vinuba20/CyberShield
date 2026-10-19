package com.cybermonitor.ui;

import com.cybermonitor.evaluation.RootCauseEvaluation;
import com.cybermonitor.model.Incident;
import com.cybermonitor.model.LogEvent;
import com.cybermonitor.model.RootCauseCandidate;
import com.cybermonitor.model.ThreatAlert;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** JavaFX dashboard for real incident snapshots and measured root-cause evaluation. */
public final class DashboardView extends BorderPane {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault());

    private final Label dataStatus = new Label(
            "Dashboard data unavailable: concrete event/incident repositories and incident service are not configured.");
    private final Label eventCount = new Label("Events: —");
    private final Label incidentCount = new Label("Incidents: —");
    private final Label alertCount = new Label("Raw alerts: —");
    private final PieChart severityChart = new PieChart();
    private final ListView<Incident> incidentList = new ListView<>();
    private final ListView<String> timeline = new ListView<>();
    private final TableView<RootCauseCandidate> rootCauseTable = new TableView<>();
    private final VBox evaluationResults = new VBox(4);

    public DashboardView() {
        setPadding(new Insets(18));
        setTop(createHeader());
        setCenter(createContent());
        incidentList.getSelectionModel().selectedItemProperty()
                .addListener((observable, previous, selected) -> showIncidentDetails(selected));
    }

    /**
     * Replaces the display with counts and details from a data-provider snapshot.
     * The supplied event count should come from the event repository, not be inferred
     * from alert evidence (which may only contain a subset of imported events).
     */
    public void showSnapshot(DashboardSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot must not be null");
        dataStatus.setText("Showing repository-backed dashboard data.");
        eventCount.setText("Events: " + snapshot.eventCount());
        incidentCount.setText("Incidents: " + snapshot.incidentCount());
        alertCount.setText("Raw alerts: " + snapshot.rawAlertCount());

        severityChart.setData(FXCollections.observableArrayList());
        snapshot.incidentCountsBySeverity().forEach((severity, count) -> {
            if (count > 0) {
                severityChart.getData().add(new PieChart.Data(severity.name() + " (" + count + ")", count));
            }
        });

        incidentList.setItems(FXCollections.observableArrayList(snapshot.incidents()));
        incidentList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(Incident incident, boolean empty) {
                super.updateItem(incident, empty);
                setText(empty || incident == null ? null
                        : incident.title() + " — " + incident.severity() + " — " + incident.status());
            }
        });
        if (!snapshot.incidents().isEmpty()) {
            incidentList.getSelectionModel().selectFirst();
        } else {
            showIncidentDetails(null);
            dataStatus.setText("Repository data loaded; no incidents are currently stored.");
        }
        showEvaluation(snapshot.rootCauseEvaluation());
    }

    private VBox createHeader() {
        Label title = new Label("CyberShield Desktop Dashboard");
        title.setStyle("-fx-font-size: 22px; -fx-font-weight: bold;");
        HBox counts = new HBox(24, eventCount, incidentCount, alertCount);
        VBox header = new VBox(8, title, dataStatus, counts);
        header.setPadding(new Insets(0, 0, 14, 0));
        return header;
    }

    private VBox createContent() {
        severityChart.setTitle("Incidents by severity");
        severityChart.setLabelsVisible(true);
        severityChart.setLegendVisible(true);
        severityChart.setMinHeight(190);

        Label incidentsLabel = new Label("Incidents");
        VBox incidentPane = new VBox(6, incidentsLabel, incidentList);
        VBox.setVgrow(incidentList, Priority.ALWAYS);
        incidentPane.setPrefWidth(360);

        Label timelineLabel = new Label("Selected incident timeline");
        Label rootCauseLabel = new Label("Root-cause candidates");
        configureRootCauseColumns();
        VBox detailPane = new VBox(6, timelineLabel, timeline, rootCauseLabel, rootCauseTable);
        VBox.setVgrow(timeline, Priority.ALWAYS);
        VBox.setVgrow(rootCauseTable, Priority.ALWAYS);
        HBox incidentDetails = new HBox(12, incidentPane, detailPane);
        HBox.setHgrow(detailPane, Priority.ALWAYS);
        incidentDetails.setMinHeight(340);

        Label evaluationLabel = new Label("Root-cause accuracy (held-out evaluation)");
        evaluationResults.getChildren().add(new Label("No evaluation report supplied."));
        VBox lowerPane = new VBox(10, severityChart, evaluationLabel, evaluationResults);

        VBox content = new VBox(12, incidentDetails, lowerPane);
        VBox.setVgrow(incidentDetails, Priority.ALWAYS);
        return content;
    }

    private void configureRootCauseColumns() {
        TableColumn<RootCauseCandidate, String> eventType = new TableColumn<>("Event type");
        eventType.setCellValueFactory(cell ->
                new ReadOnlyObjectWrapper<>(cell.getValue().eventType()));
        TableColumn<RootCauseCandidate, String> source = new TableColumn<>("Source");
        source.setCellValueFactory(cell ->
                new ReadOnlyObjectWrapper<>(cell.getValue().source()));
        TableColumn<RootCauseCandidate, Number> score = new TableColumn<>("Score");
        score.setCellValueFactory(cell ->
                new ReadOnlyObjectWrapper<>(cell.getValue().score()));
        TableColumn<RootCauseCandidate, String> explanation = new TableColumn<>("Explanation");
        explanation.setCellValueFactory(cell ->
                new ReadOnlyObjectWrapper<>(cell.getValue().explanation()));
        eventType.setPrefWidth(140);
        source.setPrefWidth(130);
        score.setPrefWidth(80);
        explanation.setPrefWidth(420);
        rootCauseTable.getColumns().setAll(List.of(eventType, source, score, explanation));
        rootCauseTable.setPlaceholder(new Label("No ranked root-cause candidates are stored for this incident."));
        rootCauseTable.setPrefHeight(180);
    }

    private void showIncidentDetails(Incident incident) {
        if (incident == null) {
            timeline.setItems(FXCollections.observableArrayList());
            rootCauseTable.setItems(FXCollections.observableArrayList());
            return;
        }

        List<TimelineEntry> entries = new ArrayList<>();
        for (ThreatAlert alert : incident.alerts()) {
            for (LogEvent event : alert.evidence()) {
                entries.add(new TimelineEntry(event, alert));
            }
        }
        entries.sort(Comparator.comparing((TimelineEntry entry) -> entry.event().timestamp())
                .thenComparing(entry -> entry.event().eventType())
                .thenComparing(entry -> entry.event().source()));
        timeline.setItems(FXCollections.observableArrayList(entries.stream()
                .map(DashboardView::formatTimelineEntry).toList()));
        rootCauseTable.setItems(FXCollections.observableArrayList(
                incident.rootCauses().stream().limit(3).toList()));
    }

    private void showEvaluation(java.util.Optional<RootCauseEvaluation.EvaluationReport> evaluation) {
        evaluationResults.getChildren().clear();
        if (evaluation.isEmpty()) {
            evaluationResults.getChildren().add(new Label("No measured evaluation report supplied."));
            return;
        }
        RootCauseEvaluation.EvaluationReport report = evaluation.get();
        evaluationResults.getChildren().add(new Label(
                "Training seed " + report.trainingSeed() + ", test seed " + report.testSeed()
                        + ", ranker skew tolerance " + report.skewTolerance().toSeconds() + " s"));
        for (RootCauseEvaluation.SkewResult result : report.results()) {
            evaluationResults.getChildren().add(new Label(String.format(Locale.ROOT,
                    "%d s skew, %d test cascades — baseline top-1/top-3: %s/%s; ranker top-1/top-3: %s/%s",
                    result.injectedSkewSeconds(), result.testCaseCount(),
                    result.baselineAccuracy().formatTop1(), result.baselineAccuracy().formatTop3(),
                    result.rankerAccuracy().formatTop1(), result.rankerAccuracy().formatTop3())));
        }
        evaluationResults.getChildren().add(new Label(
                "Synthetic results only; they do not establish real-world accuracy."));
    }

    private static String formatTimelineEntry(TimelineEntry entry) {
        LogEvent event = entry.event();
        return TIMESTAMP_FORMAT.format(event.timestamp()) + "  " + event.source() + "  "
                + event.eventType() + "  [" + entry.alert().ruleName() + "]  "
                + entry.alert().explanation();
    }

    private record TimelineEntry(LogEvent event, ThreatAlert alert) {
    }
}
