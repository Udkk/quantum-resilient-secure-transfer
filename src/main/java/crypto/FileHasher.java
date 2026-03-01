package crypto;

import java.io.FileInputStream;
import java.security.MessageDigest;

public class FileHasher {

    public static byte[] sha256(String filePath) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        return digest.digest();
    }
}