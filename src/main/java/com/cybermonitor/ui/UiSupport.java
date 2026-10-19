package com.cybermonitor.ui;

import com.cybermonitor.model.Severity;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** Small helpers shared by the screens: time format, severity colours, dialogs. */
final class UiSupport {

    static final String ANY = "Any";

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    private UiSupport() {
    }

    static String time(Instant instant) {
        return TIME.format(instant);
    }

    static Instant startOfDay(LocalDate date) {
        return date == null ? null : date.atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    /** Last millisecond of the given day, so the "to" date is inclusive. */
    static Instant endOfDay(LocalDate date) {
        return date == null ? null : date.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant().minusMillis(1);
    }

    static Severity severityOrNull(String choice) {
        return choice == null || ANY.equals(choice) ? null : Severity.valueOf(choice);
    }

    static String severityStyle(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "-fx-text-fill: #b00020; -fx-font-weight: bold;";
            case HIGH -> "-fx-text-fill: #d9480f; -fx-font-weight: bold;";
            case MEDIUM -> "-fx-text-fill: #8a6d00;";
            case LOW -> "-fx-text-fill: #2b7a0b;";
        };
    }

    /** A column cell that shows the severity name in its colour. */
    static <T> TableColumn<T, String> severityColumn(String title, java.util.function.Function<T, Severity> getter) {
        TableColumn<T, String> column = new TableColumn<>(title);
        column.setCellValueFactory(cell -> new javafx.beans.property.SimpleStringProperty(
                getter.apply(cell.getValue()).name()));
        column.setCellFactory(col -> new TableCell<T, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    setStyle(severityStyle(Severity.valueOf(item)));
                }
            }
        });
        column.setPrefWidth(90);
        return column;
    }

    static <T> TableColumn<T, String> textColumn(String title, double width,
                                                 java.util.function.Function<T, String> getter) {
        TableColumn<T, String> column = new TableColumn<>(title);
        column.setCellValueFactory(cell -> new javafx.beans.property.SimpleStringProperty(
                getter.apply(cell.getValue())));
        column.setPrefWidth(width);
        return column;
    }

    static void error(String message) {
        new Alert(Alert.AlertType.ERROR, message, ButtonType.OK).showAndWait();
    }

    static void info(String message) {
        new Alert(Alert.AlertType.INFORMATION, message, ButtonType.OK).showAndWait();
    }
}
