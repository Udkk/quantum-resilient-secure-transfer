package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESUtil {

    private static final int GCM_TAG_LENGTH = 128; // in bits

    public static SecretKey generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[12]; // 12 bytes is standard for GCM
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] encrypt(byte[] data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec =
                new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV());

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec =
                new GCMParameterSpec(GCM_TAG_LENGTH, iv.getIV());

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(encryptedData);
    }
}