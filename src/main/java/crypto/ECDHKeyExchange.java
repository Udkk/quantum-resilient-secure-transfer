package crypto;

import javax.crypto.KeyAgreement;
import java.security.*;

public class ECDHKeyExchange {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);

        return ka.generateSecret();
    }
}