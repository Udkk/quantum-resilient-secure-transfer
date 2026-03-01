package crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class HybridKeyDerivation {

    public static SecretKey deriveHybridAESKey(byte[] ecdhSecret, byte[] kyberSecret) {

        byte[] combined = new byte[ecdhSecret.length + kyberSecret.length];
        System.arraycopy(ecdhSecret, 0, combined, 0, ecdhSecret.length);
        System.arraycopy(kyberSecret, 0, combined, ecdhSecret.length, kyberSecret.length);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(combined, null, "HYBRID-AES-KEY".getBytes()));

        byte[] aesKeyBytes = new byte[32]; // AES-256
        hkdf.generateBytes(aesKeyBytes, 0, 32);

        return new SecretKeySpec(aesKeyBytes, "AES");
    }
}