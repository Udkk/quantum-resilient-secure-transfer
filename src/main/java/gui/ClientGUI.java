package gui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import network.SecureClient;
import network.ProgressCallback;

import java.io.File;

public class ClientGUI extends Application {

    private TextField hostField = new TextField("localhost");
    private TextField portField = new TextField("5000");
    private TextArea logArea = new TextArea();
    private ProgressBar progressBar = new ProgressBar(0);
    private File selectedFile;

    @Override
    public void start(Stage stage) {

        logArea.setEditable(false);
        logArea.setPrefHeight(200);
        progressBar.setPrefWidth(350);

        Button chooseBtn = new Button("Choose File");
        Button sendBtn = new Button("Send File");

        chooseBtn.setOnAction(e -> {
            FileChooser fc = new FileChooser();
            selectedFile = fc.showOpenDialog(stage);

            if (selectedFile != null) {
                log("Selected file: " + selectedFile.getName());
            }
        });

        sendBtn.setOnAction(e -> {

            if (selectedFile == null) {
                log("⚠ Please select a file first.");
                return;
            }

            progressBar.setProgress(0);

            new Thread(() -> {

                boolean result = SecureClient.sendFile(
                        hostField.getText(),
                        Integer.parseInt(portField.getText()),
                        selectedFile.toPath(),
                        new ProgressCallback() {

                            @Override
                            public void onProgress(double progress) {
                                Platform.runLater(() ->
                                        progressBar.setProgress(progress));
                            }

                            @Override
                            public void onLog(String message) {
                                Platform.runLater(() -> log(message));
                            }
                        });

                Platform.runLater(() -> {
                    if (result)
                        log("✔ Transfer Successful!");
                    else
                        log("✘ Transfer Failed.");
                });

            }).start();
        });

        VBox root = new VBox(10,
                new Label("Host:"), hostField,
                new Label("Port:"), portField,
                chooseBtn,
                sendBtn,
                progressBar,
                new Label("Logs:"),
                logArea);

        root.setPadding(new Insets(15));

        stage.setTitle("Secure PQ File Transfer - Client");
        stage.setScene(new Scene(root, 400, 500));
        stage.show();
    }

    private void log(String message) {
        logArea.appendText(message + "\n");
    }

    public static void main(String[] args) {
        launch();
    }
}