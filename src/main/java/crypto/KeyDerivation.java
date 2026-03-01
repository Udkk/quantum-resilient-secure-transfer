package crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyDerivation {

    public static SecretKey deriveAESKeyFromSharedSecret(byte[] sharedSecret) throws Exception {
        byte[] salt = "PQSecureSalt".getBytes();
        byte[] info = "AES-256-GCM-Key".getBytes();

        byte[] keyBytes = HKDF.deriveKey(sharedSecret, salt, info, 32); // 32 bytes = 256-bit key
        return new SecretKeySpec(keyBytes, "AES");
    }
}