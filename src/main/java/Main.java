import crypto.*;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

import javax.crypto.SecretKey;
import java.security.KeyPair;

public class Main {

    public static void main(String[] args) {

        try {
            CryptoProvider.register();

            String inputFile = "input.txt";
            String encryptedFile = "encrypted.dat";
            String decryptedFile = "decrypted.txt";

            // -------------------------
            // 1) Classical ECDH Exchange
            // -------------------------
            KeyPair clientECDH = ECDHKeyExchange.generateKeyPair();
            KeyPair serverECDH = ECDHKeyExchange.generateKeyPair();

            byte[] clientECDHSecret = ECDHKeyExchange.computeSharedSecret(
                    clientECDH.getPrivate(),
                    serverECDH.getPublic()
            );

            byte[] serverECDHSecret = ECDHKeyExchange.computeSharedSecret(
                    serverECDH.getPrivate(),
                    clientECDH.getPublic()
            );

            // -------------------------
            // 2) PQC Kyber Exchange (Low-level API)
            // -------------------------
            AsymmetricCipherKeyPair serverKyberKP = KyberKeyExchange.generateKyberKeyPair();

            KyberPublicKeyParameters serverKyberPublic =
                    (KyberPublicKeyParameters) serverKyberKP.getPublic();

            KyberPrivateKeyParameters serverKyberPrivate =
                    (KyberPrivateKeyParameters) serverKyberKP.getPrivate();

            // Client encapsulation
            SecretWithEncapsulation clientEncap = KyberKeyExchange.encapsulate(serverKyberPublic);

            byte[] kyberEncapsulation = clientEncap.getEncapsulation();
            byte[] clientKyberSecret = clientEncap.getSecret();

            // Server decapsulation
            byte[] serverKyberSecret = KyberKeyExchange.decapsulate(serverKyberPrivate, kyberEncapsulation);

            // -------------------------
            // 3) Hybrid Key Derivation
            // -------------------------
            SecretKey clientFinalAES = HybridKeyDerivation.deriveHybridAESKey(clientECDHSecret, clientKyberSecret);
            SecretKey serverFinalAES = HybridKeyDerivation.deriveHybridAESKey(serverECDHSecret, serverKyberSecret);

            // -------------------------
            // 4) Encrypt + Decrypt File
            // -------------------------
            byte[] iv = FileEncryptor.generateIV();

            System.out.println("Encrypting with HYBRID PQC AES key...");
            FileEncryptor.encryptFile(inputFile, encryptedFile, clientFinalAES, iv);

            System.out.println("Decrypting with HYBRID PQC AES key...");
            FileEncryptor.decryptFile(encryptedFile, decryptedFile, serverFinalAES);

            System.out.println("SUCCESS: Hybrid PQC encryption/decryption worked!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}