package network;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

public class SecureServer {

    private static final int GCM_TAG_LENGTH = 128;

    public static void startServer(int port, Consumer<String> logger) {

        try (ServerSocket serverSocket = new ServerSocket(port)) {

            logger.accept("Server started on port " + port);
            logger.accept("Waiting for client...");

            while (true) {

                Socket socket = serverSocket.accept();
                logger.accept("Client connected: " + socket.getInetAddress());

                handleClient(socket, logger);
            }

        } catch (Exception e) {
            logger.accept("Server error: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket, Consumer<String> logger) {

        try (DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            // Receive metadata
            String fileName = dis.readUTF();
            long fileSize = dis.readLong();

            int ivLength = dis.readInt();
            byte[] iv = new byte[ivLength];
            dis.readFully(iv);

            int keyLength = dis.readInt();
            byte[] keyBytes = new byte[keyLength];
            dis.readFully(keyBytes);

            logger.accept("Receiving file: " + fileName);
            logger.accept("File size: " + fileSize + " bytes");

            // Prepare AES key
            SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

            ByteArrayOutputStream encryptedBuffer = new ByteArrayOutputStream();

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = dis.read(buffer)) != -1) {
                encryptedBuffer.write(buffer, 0, bytesRead);
            }

            byte[] encryptedData = encryptedBuffer.toByteArray();
            byte[] decryptedData = cipher.doFinal(encryptedData);

            // Save file
            Path outputPath = Path.of("received_" + fileName);
            Files.write(outputPath, decryptedData);

            logger.accept("File saved as: " + outputPath.toString());
            logger.accept("Decryption successful.");
            logger.accept("Transfer complete.");

        } catch (Exception e) {
            logger.accept("Client handling error: " + e.getMessage());
        }
    }
}