package gui;

import javafx.animation.*;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;
import javafx.util.Duration;

import network.SecureServer;

import java.util.concurrent.atomic.AtomicInteger;

public class ServerGUI extends Application {

    private TextArea logArea;
    private Label connectionLabel;
    private AtomicInteger connectionCount = new AtomicInteger(0);

    @Override
    public void start(Stage stage) {

        TextField portField = new TextField("5000");
        Button startButton = new Button("Start Server");

        logArea = new TextArea();
        logArea.setEditable(false);

        connectionLabel = new Label("Connections: 0");

        Label modeBadge = new Label("HYBRID PQ ACTIVE");
        modeBadge.setStyle("-fx-background-color:#16a34a; -fx-text-fill:white; -fx-padding:5 12; -fx-background-radius:20;");

        Circle statusLight = new Circle(6, Color.RED);

        Timeline blink = new Timeline(
                new KeyFrame(Duration.seconds(0.8),
                        e -> statusLight.setFill(
                                statusLight.getFill() == Color.RED ? Color.LIMEGREEN : Color.RED))
        );
        blink.setCycleCount(Animation.INDEFINITE);

        startButton.setOnAction(e -> {

            blink.play();

            new Thread(() -> {
                SecureServer.startServer(
                        Integer.parseInt(portField.getText()),
                        message -> Platform.runLater(() -> {

                            logArea.appendText(message + "\n");

                            if (message.contains("Client connected")) {
                                int count = connectionCount.incrementAndGet();
                                connectionLabel.setText("Connections: " + count);
                            }
                        })
                );
            }).start();

            log("Server started.");
        });

        VBox card = new VBox(15);
        card.getStyleClass().add("card");
        card.setMaxWidth(500);

        Label title = new Label("🛡 Hybrid PQ Secure Server");
        title.getStyleClass().add("label-title");

        HBox topRow = new HBox(10, new Label("Status:"), statusLight, modeBadge);
        topRow.setAlignment(Pos.CENTER_LEFT);

        card.getChildren().addAll(
                title,
                topRow,
                connectionLabel,
                new Label("Port"),
                portField,
                startButton,
                logArea
        );

        StackPane root = new StackPane(card);
        root.setPadding(new Insets(40));

        Scene scene = new Scene(root, 650, 600);
        scene.getStylesheets().add(
                getClass().getResource("/style.css").toExternalForm()
        );

        stage.setTitle("Hybrid PQ Secure Server");
        stage.setScene(scene);
        stage.show();
    }

    private void log(String message) {
        logArea.appendText(message + "\n");
    }

    public static void main(String[] args) {
        launch();
    }
}