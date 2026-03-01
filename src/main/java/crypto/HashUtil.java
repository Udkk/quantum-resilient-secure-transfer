package crypto;

import java.security.MessageDigest;

public class HashUtil {

    // SHA-256 for byte[]
    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}