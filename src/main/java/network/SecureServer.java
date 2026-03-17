package network;

import crypto.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.AEADBadTagException;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Consumer;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;

public class SecureServer {

    public static void startServer(int port, Consumer<String> logger) {

        try {
            CryptoProvider.register();

            ServerSocket serverSocket = new ServerSocket(port);
            logger.accept("Server started on port " + port);

            while (true) {
                Socket socket = serverSocket.accept();
                logger.accept("Client connected.");
                handleClient(socket, logger);
            }

        } catch (Exception e) {
            logger.accept("Server error: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket, Consumer<String> logger) {

        try (DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            // ===== Generate fresh keys per session =====
            KeyPair serverECDH = ECDHKeyExchange.generateKeyPair();
            AsymmetricCipherKeyPair serverKyberKP =
                    KyberKeyExchange.generateKyberKeyPair();

            KyberPublicKeyParameters serverKyberPublic =
                    (KyberPublicKeyParameters) serverKyberKP.getPublic();
            KyberPrivateKeyParameters serverKyberPrivate =
                    (KyberPrivateKeyParameters) serverKyberKP.getPrivate();

            // ===== Send server keys =====
            byte[] serverECDHPub = serverECDH.getPublic().getEncoded();
            dos.writeInt(serverECDHPub.length);
            dos.write(serverECDHPub);

            byte[] serverKyberPub = serverKyberPublic.getEncoded();
            dos.writeInt(serverKyberPub.length);
            dos.write(serverKyberPub);
            dos.flush();

            // ===== Receive client ECDH =====
            int clientECDHLen = dis.readInt();
            byte[] clientECDHPub = new byte[clientECDHLen];
            dis.readFully(clientECDHPub);

            PublicKey clientECDHPublic =
                    KeyFactory.getInstance("EC")
                            .generatePublic(new X509EncodedKeySpec(clientECDHPub));

            byte[] ecdhSecret =
                    ECDHKeyExchange.computeSharedSecret(
                            serverECDH.getPrivate(),
                            clientECDHPublic);

            // ===== Kyber =====
            int encapLen = dis.readInt();
            byte[] encapsulation = new byte[encapLen];
            dis.readFully(encapsulation);

            byte[] kyberSecret =
                    KyberKeyExchange.decapsulate(
                            serverKyberPrivate,
                            encapsulation);

            SecretKey aesKey =
                    HybridKeyDerivation.deriveHybridAESKey(
                            ecdhSecret,
                            kyberSecret);

            logger.accept("Hybrid AES key derived.");

            // ===== Continue EXACT SAME as before =====

            int dilLen = dis.readInt();
            byte[] dilPubBytes = new byte[dilLen];
            dis.readFully(dilPubBytes);

            DilithiumPublicKeyParameters clientDilPublic =
                    new DilithiumPublicKeyParameters(
                            DilithiumParameters.dilithium3,
                            dilPubBytes);

            int sigLen = dis.readInt();
            byte[] signature = new byte[sigLen];
            dis.readFully(signature);

            String fileName = dis.readUTF();

            int ivLen = dis.readInt();
            byte[] ivBytes = new byte[ivLen];
            dis.readFully(ivBytes);

            long encryptedSize = dis.readLong();

            logger.accept("Receiving: " + fileName);

            // ===== Verify signature =====
            ByteArrayOutputStream metaStream = new ByteArrayOutputStream();
            DataOutputStream metaOut = new DataOutputStream(metaStream);
            metaOut.writeUTF(fileName);
            metaOut.writeLong(encryptedSize);


            DilithiumSigner verifier = new DilithiumSigner();
            verifier.init(false, clientDilPublic);

            if (!verifier.verifySignature(
                    metaStream.toByteArray(),
                    signature)) {

                logger.accept("Signature invalid.");
                dos.writeBoolean(false);
                dos.flush();
                return;
            }

            logger.accept("Signature verified.");

            Cipher cipher =
                    Cipher.getInstance("AES/GCM/NoPadding");

            GCMParameterSpec spec =
                    new GCMParameterSpec(128, ivBytes);

            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

            try (FileOutputStream fos =
                         new FileOutputStream("received_" + fileName)) {

                byte[] buffer = new byte[4096];
                long totalRead = 0;

                while (totalRead < encryptedSize) {
                    int toRead = (int)Math.min(buffer.length,
                            encryptedSize - totalRead);

                    int bytesRead = dis.read(buffer, 0, toRead);
                    if (bytesRead == -1) break;

                    totalRead += bytesRead;

                    byte[] decryptedChunk =
                            cipher.update(buffer, 0, bytesRead);

                    if (decryptedChunk != null)
                        fos.write(decryptedChunk);
                }

                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null)
                    fos.write(finalBytes);

                logger.accept("File decrypted successfully.");
                dos.writeBoolean(true);
                dos.flush();

            } catch (AEADBadTagException e) {
                logger.accept("GCM tag verification failed.");
                dos.writeBoolean(false);
                dos.flush();
            }

        } catch (Exception e) {
            logger.accept("Client error: " + e.getMessage());
        }
    }
}