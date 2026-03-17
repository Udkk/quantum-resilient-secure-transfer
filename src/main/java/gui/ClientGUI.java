package gui;

import javafx.animation.*;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;
import javafx.util.Duration;

import network.SecureClient;
import network.ProgressCallback;

import java.io.File;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

public class ClientGUI extends Application {

    private ProgressBar progressBar;
    private TextArea logArea;
    private Label statusBadge;
    private Label speedLabel;
    private Label encryptionTimeLabel;
    private Label cpuLabel;
    private ListView<String> historyList;

    private volatile boolean cancelRequested = false;
    private File selectedFile;
    private long startTime;

    @Override
    public void start(Stage stage) {

        TextField hostField = new TextField("localhost");
        TextField portField = new TextField("5000");

        progressBar = new ProgressBar(0);
        progressBar.setPrefHeight(12);

        logArea = new TextArea();
        logArea.setEditable(false);

        statusBadge = new Label("IDLE");
        statusBadge.getStyleClass().addAll("status-badge", "status-idle");

        speedLabel = new Label("Speed: 0 MB/s");
        encryptionTimeLabel = new Label("Encryption Time: 0s");
        cpuLabel = new Label("CPU Usage: 0%");

        historyList = new ListView<>();
        historyList.setPrefHeight(120);

        Label cryptoMode = new Label("Hybrid ECDH + Kyber + Dilithium");
        cryptoMode.setStyle("-fx-text-fill:#22d3ee;");

        Button sendButton = new Button("Send Securely");
        Button cancelButton = new Button("Cancel Transfer");
        Button themeToggle = new Button("Toggle Theme");

        cancelButton.setDisable(true);

        VBox dropZone = new VBox();
        dropZone.setAlignment(Pos.CENTER);
        dropZone.setPrefHeight(80);
        dropZone.setStyle("-fx-border-color:#334155; -fx-border-radius:10; -fx-border-width:2;");
        dropZone.getChildren().add(new Label("Drag & Drop File Here"));

        dropZone.setOnDragOver(e -> {
            if (e.getDragboard().hasFiles()) {
                e.acceptTransferModes(TransferMode.COPY);
            }
            e.consume();
        });

        dropZone.setOnDragDropped(e -> {
            var db = e.getDragboard();
            if (db.hasFiles()) {
                selectedFile = db.getFiles().get(0);
                log("Selected: " + selectedFile.getName());
                updateStatus("CONNECTED", "status-connected");
            }
            e.setDropCompleted(true);
            e.consume();
        });

        sendButton.setOnAction(e -> {

            if (selectedFile == null) {
                log("No file selected.");
                return;
            }

            cancelRequested = false;
            cancelButton.setDisable(false);

            new Thread(() -> {

                startTime = System.currentTimeMillis();
                updateStatus("TRANSFERRING", "status-transferring");

                Platform.runLater(() ->
                        progressBar.getStyleClass().add("progress-glow"));

                boolean result = SecureClient.sendFile(
                        hostField.getText(),
                        Integer.parseInt(portField.getText()),
                        selectedFile.toPath(),
                        new ProgressCallback() {

                            @Override
                            public void onProgress(double value) {

                                if (cancelRequested) return;

                                long elapsed = System.currentTimeMillis() - startTime;
                                double seconds = elapsed / 1000.0;

                                double fileSizeMB =
                                        selectedFile.length() / (1024.0 * 1024.0);

                                double speed =
                                        seconds > 0 ? fileSizeMB / seconds : 0;

                                OperatingSystemMXBean osBean =
                                        (OperatingSystemMXBean)
                                                ManagementFactory.getOperatingSystemMXBean();

                                double cpuLoad = osBean.getSystemCpuLoad() * 100;

                                Platform.runLater(() -> {
                                    progressBar.setProgress(value);
                                    speedLabel.setText(
                                            String.format("Speed: %.2f MB/s", speed));
                                    encryptionTimeLabel.setText(
                                            String.format("Encryption Time: %.2fs", seconds));
                                    cpuLabel.setText(
                                            String.format("CPU Usage: %.1f%%", cpuLoad));
                                });
                            }

                            @Override
                            public void onLog(String message) {
                                Platform.runLater(() -> log(message));
                            }
                        });

                Platform.runLater(() -> {

                    progressBar.getStyleClass().remove("progress-glow");
                    cancelButton.setDisable(true);

                    if (!cancelRequested && result) {
                        updateStatus("COMPLETED", "status-connected");

                        historyList.getItems().add(
                                selectedFile.getName() + " ✓ (" +
                                        String.format("%.2f MB",
                                                selectedFile.length() / 1024.0 / 1024.0) + ")"
                        );

                    } else if (cancelRequested) {
                        updateStatus("CANCELLED", "status-failed");
                        log("Transfer cancelled.");
                    } else {
                        updateStatus("FAILED", "status-failed");
                    }
                });

            }).start();
        });

        cancelButton.setOnAction(e -> cancelRequested = true);

        themeToggle.setOnAction(e -> {
            Scene scene = stage.getScene();
            if (scene.getStylesheets().contains(
                    getClass().getResource("/style.css").toExternalForm())) {

                scene.getStylesheets().clear();
            } else {
                scene.getStylesheets().add(
                        getClass().getResource("/style.css").toExternalForm());
            }
        });

        VBox card = new VBox(15);
        card.getStyleClass().add("card");
        card.setMaxWidth(550);

        Label title = new Label("🔐 Hybrid PQ Secure Client");
        title.getStyleClass().add("label-title");

        HBox statusRow = new HBox(10, new Label("Status:"), statusBadge);
        statusRow.setAlignment(Pos.CENTER_LEFT);

        HBox buttonRow = new HBox(10, sendButton, cancelButton, themeToggle);

        card.getChildren().addAll(
                title,
                cryptoMode,
                new Label("Host"), hostField,
                new Label("Port"), portField,
                dropZone,
                buttonRow,
                progressBar,
                speedLabel,
                encryptionTimeLabel,
                cpuLabel,
                statusRow,
                new Label("Transfer History"),
                historyList,
                logArea
        );

        StackPane root = new StackPane(createParticles(), card);
        root.setPadding(new Insets(40));

        Scene scene = new Scene(root, 750, 800);
        scene.getStylesheets().add(
                getClass().getResource("/style.css").toExternalForm()
        );

        FadeTransition ft = new FadeTransition(Duration.seconds(1), card);
        ft.setFromValue(0);
        ft.setToValue(1);
        ft.play();

        stage.setTitle("Hybrid PQ Secure Client");
        stage.setScene(scene);
        stage.show();
    }

    private void updateStatus(String text, String style) {
        statusBadge.setText(text);
        statusBadge.getStyleClass().clear();
        statusBadge.getStyleClass().addAll("status-badge", style);
    }

    private void log(String message) {
        logArea.appendText(message + "\n");
    }

    private Pane createParticles() {

        Pane pane = new Pane();
        pane.setMouseTransparent(true);

        for (int i = 0; i < 25; i++) {

            Circle c = new Circle(Math.random() * 3 + 1,
                    Color.web("#1e293b"));

            c.setTranslateX(Math.random() * 1000);
            c.setTranslateY(Math.random() * 800);

            TranslateTransition tt =
                    new TranslateTransition(
                            Duration.seconds(20 + Math.random() * 20), c);

            tt.setByY(-900);
            tt.setCycleCount(Animation.INDEFINITE);
            tt.play();

            pane.getChildren().add(c);
        }

        return pane;
    }

    public static void main(String[] args) {
        launch();
    }
}