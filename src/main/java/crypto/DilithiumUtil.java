package crypto;

import java.security.*;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public class DilithiumUtil {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BC");
        kpg.initialize(DilithiumParameterSpec.dilithium2);
        return kpg.generateKeyPair();
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("Dilithium", "BC");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("Dilithium", "BC");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signatureBytes);
    }
}