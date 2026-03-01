package crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class HKDF {

    public static byte[] extract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");

        if (salt == null) {
            salt = new byte[32]; // 32 bytes of zeros for SHA-256
        }

        SecretKeySpec keySpec = new SecretKeySpec(salt, "HmacSHA256");
        mac.init(keySpec);

        return mac.doFinal(ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(prk, "HmacSHA256");
        mac.init(keySpec);

        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int bytesGenerated = 0;
        int counter = 1;

        while (bytesGenerated < length) {
            mac.reset();
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update((byte) counter);

            t = mac.doFinal();

            int bytesToCopy = Math.min(t.length, length - bytesGenerated);
            System.arraycopy(t, 0, result, bytesGenerated, bytesToCopy);

            bytesGenerated += bytesToCopy;
            counter++;
        }

        return result;
    }

    public static byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        byte[] prk = extract(salt, ikm);
        return expand(prk, info, length);
    }
}