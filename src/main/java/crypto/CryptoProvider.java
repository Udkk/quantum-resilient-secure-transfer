package crypto;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class CryptoProvider {

    private static boolean initialized = false;

    public static synchronized void register() {

        if (initialized) {
            return;
        }

        // Register classical BC first
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Register PQC provider
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        initialized = true;

        System.out.println("BouncyCastle Providers Registered Successfully.");
    }
}