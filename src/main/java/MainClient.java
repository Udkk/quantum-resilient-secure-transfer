import crypto.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
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
                System.out.println("File not found.");
                return;
            }

            String fileName = filePath.getFileName().toString();
            long fileSize = Files.size(filePath);

            System.out.println("Connecting to server...");

            try (Socket socket = new Socket(host, port);
                 DataInputStream dis = new DataInputStream(socket.getInputStream());
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

                // ===== Receive Server Keys =====
                int serverECDHLen = dis.readInt();
                byte[] serverECDHPub = new byte[serverECDHLen];
                dis.readFully(serverECDHPub);

                KeyFactory kf = KeyFactory.getInstance("EC");
                PublicKey serverECDHPublic =
                        kf.generatePublic(new X509EncodedKeySpec(serverECDHPub));

                int serverKyberLen = dis.readInt();
                byte[] serverKyberPub = new byte[serverKyberLen];
                dis.readFully(serverKyberPub);

                KyberPublicKeyParameters serverKyberPublic =
                        new KyberPublicKeyParameters(
                                KyberParameters.kyber512,
                                serverKyberPub);

                // ===== ECDH =====
                KeyPair clientECDH = ECDHKeyExchange.generateKeyPair();

                byte[] clientECDHPub =
                        clientECDH.getPublic().getEncoded();

                dos.writeInt(clientECDHPub.length);
                dos.write(clientECDHPub);

                byte[] ecdhSecret =
                        ECDHKeyExchange.computeSharedSecret(
                                clientECDH.getPrivate(),
                                serverECDHPublic);

                // ===== Kyber =====
                SecretWithEncapsulation encap =
                        KyberKeyExchange.encapsulate(serverKyberPublic);

                dos.writeInt(encap.getEncapsulation().length);
                dos.write(encap.getEncapsulation());

                byte[] kyberSecret = encap.getSecret();

                // ===== Hybrid AES Key =====
                SecretKey aesKey =
                        HybridKeyDerivation.deriveHybridAESKey(
                                ecdhSecret,
                                kyberSecret);

                System.out.println("Hybrid AES key derived.");

                // ===== Dilithium =====
                AsymmetricCipherKeyPair dilKP =
                        DilithiumKeyExchange.generateKeyPair();

                DilithiumPublicKeyParameters dilPublic =
                        (DilithiumPublicKeyParameters) dilKP.getPublic();

                DilithiumPrivateKeyParameters dilPrivate =
                        (DilithiumPrivateKeyParameters) dilKP.getPrivate();

                byte[] dilPubBytes = dilPublic.getEncoded();

                // ===== IV =====
                IvParameterSpec iv = AESUtil.generateIV();
                byte[] ivBytes = iv.getIV();

                // 🔥 IMPORTANT FIX
                long encryptedSize = fileSize + 16; // GCM tag

                // ===== Sign metadata =====
                ByteArrayOutputStream metaStream = new ByteArrayOutputStream();
                DataOutputStream metaOut = new DataOutputStream(metaStream);

                metaOut.writeUTF(fileName);
                metaOut.writeLong(encryptedSize);

                DilithiumSigner signer = new DilithiumSigner();
                signer.init(true, dilPrivate);

                byte[] signature =
                        signer.generateSignature(metaStream.toByteArray());

                // ===== Send metadata =====
                dos.writeInt(dilPubBytes.length);
                dos.write(dilPubBytes);

                dos.writeInt(signature.length);
                dos.write(signature);

                dos.writeUTF(fileName);
                dos.writeInt(ivBytes.length);
                dos.write(ivBytes);
                dos.writeLong(encryptedSize);

                // ===== Streaming Encrypt =====
                Cipher cipher =
                        Cipher.getInstance("AES/GCM/NoPadding");

                GCMParameterSpec spec =
                        new GCMParameterSpec(128, ivBytes);

                cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

                try (FileInputStream fis =
                             new FileInputStream(filePath.toFile())) {

                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    while ((bytesRead = fis.read(buffer)) != -1) {

                        byte[] encryptedChunk =
                                cipher.update(buffer, 0, bytesRead);

                        if (encryptedChunk != null) {
                            dos.write(encryptedChunk);
                        }
                    }

                    byte[] finalBytes = cipher.doFinal();
                    if (finalBytes != null) {
                        dos.write(finalBytes);
                    }
                }

                dos.flush();

                System.out.println("File sent. Waiting for confirmation...");

                boolean success = dis.readBoolean();

                if (success)
                    System.out.println("✅ Secure transfer complete.");
                else
                    System.out.println("❌ Server rejected transfer.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}