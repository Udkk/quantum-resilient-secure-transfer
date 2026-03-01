import crypto.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;

public class MainClient {

    public static void main(String[] args) {

        try {
            CryptoProvider.register();

            if (args.length == 0) {
                System.out.println("Usage: java MainClient <file_path>");
                return;
            }

            String host = "localhost";
            int port = 5000;

            Path filePath = Paths.get(args[0]);

            if (!Files.exists(filePath)) {
                System.out.println("File not found: " + filePath);
                return;
            }

            String fileName = filePath.getFileName().toString();
            byte[] fileBytes = Files.readAllBytes(filePath);

            System.out.println("Connecting to server...");

            try (Socket socket = new Socket(host, port)) {

                DataInputStream dis =
                        new DataInputStream(socket.getInputStream());
                DataOutputStream dos =
                        new DataOutputStream(socket.getOutputStream());

                // ==============================
                // 1. RECEIVE SERVER PUBLIC KEYS
                // ==============================

                int serverECDHPubLen = dis.readInt();
                byte[] serverECDHPubBytes = new byte[serverECDHPubLen];
                dis.readFully(serverECDHPubBytes);

                KeyFactory kf = KeyFactory.getInstance("EC");

                PublicKey serverECDHPublic =
                        kf.generatePublic(
                                new X509EncodedKeySpec(serverECDHPubBytes));

                int serverKyberPubLen = dis.readInt();
                byte[] serverKyberPubBytes = new byte[serverKyberPubLen];
                dis.readFully(serverKyberPubBytes);

                KyberPublicKeyParameters serverKyberPublic =
                        new KyberPublicKeyParameters(
                                KyberParameters.kyber512,
                                serverKyberPubBytes
                        );

                // ==============================
                // 2. CLIENT ECDH
                // ==============================

                KeyPair clientECDH =
                        ECDHKeyExchange.generateKeyPair();

                byte[] clientECDHPubBytes =
                        clientECDH.getPublic().getEncoded();

                dos.writeInt(clientECDHPubBytes.length);
                dos.write(clientECDHPubBytes);

                byte[] clientECDHSecret =
                        ECDHKeyExchange.computeSharedSecret(
                                clientECDH.getPrivate(),
                                serverECDHPublic
                        );

                // ==============================
                // 3. KYBER ENCAPSULATION
                // ==============================

                SecretWithEncapsulation clientEncap =
                        KyberKeyExchange.encapsulate(serverKyberPublic);

                byte[] kyberEncapsulation =
                        clientEncap.getEncapsulation();

                byte[] clientKyberSecret =
                        clientEncap.getSecret();

                dos.writeInt(kyberEncapsulation.length);
                dos.write(kyberEncapsulation);

                // ==============================
                // 4. DERIVE HYBRID AES KEY
                // ==============================

                SecretKey clientAESKey =
                        HybridKeyDerivation.deriveHybridAESKey(
                                clientECDHSecret,
                                clientKyberSecret
                        );

                System.out.println("Hybrid AES key derived!");

                // ==============================
                // 5. GENERATE DILITHIUM KEYPAIR
                // ==============================

                AsymmetricCipherKeyPair dilithiumKP =
                        DilithiumKeyExchange.generateKeyPair();

                DilithiumPublicKeyParameters dilithiumPublic =
                        (DilithiumPublicKeyParameters) dilithiumKP.getPublic();

                DilithiumPrivateKeyParameters dilithiumPrivate =
                        (DilithiumPrivateKeyParameters) dilithiumKP.getPrivate();

                byte[] dilithiumPubBytes =
                        dilithiumPublic.getEncoded();

                // ==============================
                // 6. GENERATE IV
                // ==============================

                IvParameterSpec iv =
                        AESUtil.generateIV();

                byte[] ivBytes = iv.getIV();

                // ==============================
                // 7. ENCRYPT FILE
                // ==============================

                byte[] encryptedFile =
                        AESUtil.encrypt(
                                fileBytes,
                                clientAESKey,
                                iv
                        );

                // ==============================
                // 8. HASH ENCRYPTED FILE
                // ==============================

                byte[] encryptedHash =
                        HashUtil.sha256(encryptedFile);

                // ==============================
                // 9. BUILD SIGNED METADATA
                // ==============================

                ByteArrayOutputStream metaStream =
                        new ByteArrayOutputStream();
                DataOutputStream metaOut =
                        new DataOutputStream(metaStream);

                metaOut.writeUTF(fileName);
                metaOut.writeLong(encryptedFile.length);
                metaOut.write(encryptedHash);

                byte[] dataToSign =
                        metaStream.toByteArray();

                DilithiumSigner signer =
                        new DilithiumSigner();

                signer.init(true, dilithiumPrivate);

                byte[] signature =
                        signer.generateSignature(dataToSign);

                // ==============================
                // 10. SEND EVERYTHING
                // ==============================

                // Send Dilithium public key
                dos.writeInt(dilithiumPubBytes.length);
                dos.write(dilithiumPubBytes);

                // Send signature
                dos.writeInt(signature.length);
                dos.write(signature);

                // Send file metadata
                dos.writeUTF(fileName);

                dos.writeInt(ivBytes.length);
                dos.write(ivBytes);

                dos.writeLong(encryptedFile.length);
                dos.write(encryptedFile);

                dos.writeInt(encryptedHash.length);
                dos.write(encryptedHash);

                dos.flush();

                System.out.println("SUCCESS: Secure hybrid PQ file sent!");

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}