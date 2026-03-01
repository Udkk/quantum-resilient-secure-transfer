package crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;

public class DilithiumKeyExchange {

    public static AsymmetricCipherKeyPair generateKeyPair() {

        DilithiumKeyPairGenerator generator =
                new DilithiumKeyPairGenerator();

        generator.init(
                new DilithiumKeyGenerationParameters(
                        new SecureRandom(),
                        DilithiumParameters.dilithium3  // Strong security level
                )
        );

        return generator.generateKeyPair();
    }
}