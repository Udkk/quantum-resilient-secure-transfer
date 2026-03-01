package crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.security.SecureRandom;

public class KyberKeyExchange {

    private static final KyberParameters PARAMS = KyberParameters.kyber512;

    public static AsymmetricCipherKeyPair generateKyberKeyPair() {
        KyberKeyPairGenerator generator = new KyberKeyPairGenerator();
        generator.init(new KyberKeyGenerationParameters(new SecureRandom(), PARAMS));
        return generator.generateKeyPair();
    }

    public static SecretWithEncapsulation encapsulate(KyberPublicKeyParameters publicKey) {
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(new SecureRandom());
        return kemGenerator.generateEncapsulated(publicKey);
    }

    public static byte[] decapsulate(KyberPrivateKeyParameters privateKey, byte[] encapsulation) {
        KyberKEMExtractor extractor = new KyberKEMExtractor(privateKey);
        return extractor.extractSecret(encapsulation);
    }
}