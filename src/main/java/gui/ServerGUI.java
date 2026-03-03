package gui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import network.SecureServer;

public class ServerGUI extends Application {

    private TextField portField = new TextField("5000");
    private TextArea logArea = new TextArea();
    private Label statusLabel = new Label("Server not running.");

    @Override
    public void start(Stage stage) {

        logArea.setEditable(false);
        logArea.setPrefHeight(250);

        Button startBtn = new Button("Start Server");

        startBtn.setOnAction(e -> {

            startBtn.setDisable(true);
            statusLabel.setText("✔ Server running...");

            new Thread(() -> {

                SecureServer.startServer(
                        Integer.parseInt(portField.getText()),
                        message -> Platform.runLater(() -> log(message))
                );

            }).start();
        });

        VBox root = new VBox(10,
                new Label("Port:"),
                portField,
                startBtn,
                statusLabel,
                new Label("Server Logs:"),
                logArea);

        root.setPadding(new Insets(15));

        stage.setTitle("Secure PQ File Transfer - Server");
        stage.setScene(new Scene(root, 400, 450));
        stage.show();
    }

    private void log(String message) {
        logArea.appendText(message + "\n");
    }

    public static void main(String[] args) {
        launch();
    }
}