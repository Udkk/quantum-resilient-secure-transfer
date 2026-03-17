package network;

import crypto.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;

public class SecureClient {

    public static boolean sendFile(
            String host,
            int port,
            Path filePath,
            ProgressCallback callback) {

        try {
            CryptoProvider.register();

            if (!Files.exists(filePath)) {
                callback.onLog("File not found.");
                return false;
            }

            String fileName = filePath.getFileName().toString();
            long fileSize = Files.size(filePath);

            callback.onLog("Connecting to server...");

            try (Socket socket = new Socket(host, port);
                 DataInputStream dis = new DataInputStream(socket.getInputStream());
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

                // ===== RECEIVE SERVER KEYS =====
                int serverECDHLen = dis.readInt();
                byte[] serverECDHPub = new byte[serverECDHLen];
                dis.readFully(serverECDHPub);

                PublicKey serverECDHPublic =
                        KeyFactory.getInstance("EC")
                                .generatePublic(new X509EncodedKeySpec(serverECDHPub));

                int serverKyberLen = dis.readInt();
                byte[] serverKyberPub = new byte[serverKyberLen];
                dis.readFully(serverKyberPub);

                KyberPublicKeyParameters serverKyberPublic =
                        new KyberPublicKeyParameters(
                                KyberParameters.kyber512,
                                serverKyberPub);

                // ===== ECDH =====
                KeyPair clientECDH = ECDHKeyExchange.generateKeyPair();
                byte[] clientECDHPub = clientECDH.getPublic().getEncoded();

                dos.writeInt(clientECDHPub.length);
                dos.write(clientECDHPub);

                byte[] ecdhSecret =
                        ECDHKeyExchange.computeSharedSecret(
                                clientECDH.getPrivate(),
                                serverECDHPublic);

                // ===== KYBER =====
                SecretWithEncapsulation encap =
                        KyberKeyExchange.encapsulate(serverKyberPublic);

                dos.writeInt(encap.getEncapsulation().length);
                dos.write(encap.getEncapsulation());

                byte[] kyberSecret = encap.getSecret();

                // ===== HYBRID KEY DERIVATION =====
                SecretKey aesKey =
                        HybridKeyDerivation.deriveHybridAESKey(
                                ecdhSecret,
                                kyberSecret);

                callback.onLog("Hybrid AES key derived.");

                // ===== DILITHIUM SIGNATURE =====
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

                long encryptedSize = fileSize + 16; // GCM tag

                // ===== SIGN METADATA =====
                ByteArrayOutputStream metaStream = new ByteArrayOutputStream();
                DataOutputStream metaOut = new DataOutputStream(metaStream);

                metaOut.writeUTF(fileName);
                metaOut.writeLong(encryptedSize);

                DilithiumSigner signer = new DilithiumSigner();
                signer.init(true, dilPrivate);

                byte[] signature =
                        signer.generateSignature(metaStream.toByteArray());


                // ===== SEND METADATA =====
                dos.writeInt(dilPubBytes.length);
                dos.write(dilPubBytes);

                dos.writeInt(signature.length);
                dos.write(signature);

                dos.writeUTF(fileName);
                dos.writeInt(ivBytes.length);
                dos.write(ivBytes);
                dos.writeLong(encryptedSize);

                // ===== STREAMING ENCRYPTION =====
                Cipher cipher =
                        Cipher.getInstance("AES/GCM/NoPadding");

                GCMParameterSpec spec =
                        new GCMParameterSpec(128, ivBytes);

                cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

                try (InputStream fis = Files.newInputStream(filePath)) {

                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    long totalSent = 0;

                    while ((bytesRead = fis.read(buffer)) != -1) {

                        byte[] encryptedChunk =
                                cipher.update(buffer, 0, bytesRead);

                        if (encryptedChunk != null) {
                            dos.write(encryptedChunk);
                            totalSent += encryptedChunk.length;

                            double progress =
                                    (double) totalSent / encryptedSize;

                            callback.onProgress(progress);
                        }
                    }

                    byte[] finalBytes = cipher.doFinal();
                    if (finalBytes != null) {
                        dos.write(finalBytes);
                    }
                }

                dos.flush();

                callback.onLog("File sent. Waiting for confirmation...");

                boolean success = dis.readBoolean();

                if (success)
                    callback.onLog("Secure transfer complete.");
                else
                    callback.onLog("Server rejected transfer.");

            }

        } catch (Exception e) {
            callback.onLog("Client error: " + e.getMessage());

        }
        return true;
    }
}