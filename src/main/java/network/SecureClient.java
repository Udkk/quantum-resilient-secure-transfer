package network;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

public class SecureClient {

    private static final int AES_KEY_SIZE = 32; // 256-bit
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public static boolean sendFile(
            String host,
            int port,
            Path filePath,
            ProgressCallback callback) {

        try (Socket socket = new Socket(host, port);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             FileInputStream fis = new FileInputStream(filePath.toFile())) {

            callback.onLog("Connected to server.");

            long fileSize = Files.size(filePath);
            String fileName = filePath.getFileName().toString();

            // 🔐 Generate AES key
            byte[] keyBytes = new byte[AES_KEY_SIZE];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

            // 🔐 Generate IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            // Send metadata first
            dos.writeUTF(fileName);
            dos.writeLong(fileSize);
            dos.writeInt(iv.length);
            dos.write(iv);
            dos.writeInt(keyBytes.length);
            dos.write(keyBytes);

            callback.onLog("Metadata sent. Starting encryption...");

            // 🔐 Initialize AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

            byte[] buffer = new byte[4096];
            int bytesRead;
            long totalSent = 0;

            while ((bytesRead = fis.read(buffer)) != -1) {

                byte[] encrypted = cipher.update(buffer, 0, bytesRead);
                if (encrypted != null) {
                    dos.write(encrypted);
                }

                totalSent += bytesRead;
                double progress = (double) totalSent / fileSize;
                callback.onProgress(progress);
            }

            // Final block (includes GCM tag)
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) {
                dos.write(finalBlock);
            }

            dos.flush();

            callback.onLog("Encryption complete.");
            callback.onLog("File transfer finished.");

            return true;

        } catch (Exception e) {
            callback.onLog("Error: " + e.getMessage());
            return false;
        }
    }
}