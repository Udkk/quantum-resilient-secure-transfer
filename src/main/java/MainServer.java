import crypto.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.AEADBadTagException;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;

public class MainServer {

    public static void main(String[] args) {

        try {
            CryptoProvider.register();

            int port = 5000;
            System.out.println("Server starting on port " + port + "...");

            KeyPair serverECDH =
                    ECDHKeyExchange.generateKeyPair();

            AsymmetricCipherKeyPair serverKyberKP =
                    KyberKeyExchange.generateKyberKeyPair();

            KyberPublicKeyParameters serverKyberPublic =
                    (KyberPublicKeyParameters) serverKyberKP.getPublic();

            KyberPrivateKeyParameters serverKyberPrivate =
                    (KyberPrivateKeyParameters) serverKyberKP.getPrivate();

            try (ServerSocket serverSocket =
                         new ServerSocket(port)) {

                System.out.println("Waiting for client...");

                try (Socket socket = serverSocket.accept();
                     DataInputStream dis =
                             new DataInputStream(socket.getInputStream());
                     DataOutputStream dos =
                             new DataOutputStream(socket.getOutputStream())) {

                    System.out.println("Client connected.");

                    // ===== Send server keys =====
                    byte[] serverECDHPub =
                            serverECDH.getPublic().getEncoded();

                    dos.writeInt(serverECDHPub.length);
                    dos.write(serverECDHPub);

                    byte[] serverKyberPub =
                            serverKyberPublic.getEncoded();

                    dos.writeInt(serverKyberPub.length);
                    dos.write(serverKyberPub);
                    dos.flush();

                    // ===== Receive client ECDH =====
                    int clientECDHLen = dis.readInt();
                    byte[] clientECDHPub =
                            new byte[clientECDHLen];
                    dis.readFully(clientECDHPub);

                    KeyFactory kf =
                            KeyFactory.getInstance("EC");

                    PublicKey clientECDHPublic =
                            kf.generatePublic(
                                    new X509EncodedKeySpec(clientECDHPub));

                    byte[] ecdhSecret =
                            ECDHKeyExchange.computeSharedSecret(
                                    serverECDH.getPrivate(),
                                    clientECDHPublic);

                    // ===== Receive Kyber encapsulation =====
                    int encapLen = dis.readInt();
                    byte[] encapsulation =
                            new byte[encapLen];
                    dis.readFully(encapsulation);

                    byte[] kyberSecret =
                            KyberKeyExchange.decapsulate(
                                    serverKyberPrivate,
                                    encapsulation);

                    SecretKey aesKey =
                            HybridKeyDerivation.deriveHybridAESKey(
                                    ecdhSecret,
                                    kyberSecret);

                    System.out.println("Hybrid AES key derived.");

                    // ===== Receive Dilithium pub =====
                    int dilLen = dis.readInt();
                    byte[] dilPubBytes =
                            new byte[dilLen];
                    dis.readFully(dilPubBytes);

                    DilithiumPublicKeyParameters clientDilPublic =
                            new DilithiumPublicKeyParameters(
                                    DilithiumParameters.dilithium3,
                                    dilPubBytes);

                    // ===== Signature =====
                    int sigLen = dis.readInt();
                    byte[] signature =
                            new byte[sigLen];
                    dis.readFully(signature);

                    // ===== Metadata =====
                    String fileName = dis.readUTF();

                    int ivLen = dis.readInt();
                    byte[] ivBytes =
                            new byte[ivLen];
                    dis.readFully(ivBytes);

                    IvParameterSpec iv =
                            new IvParameterSpec(ivBytes);

                    long encryptedSize =
                            dis.readLong();

                    System.out.println("Receiving: " + fileName);
                    System.out.println("Encrypted size: " + encryptedSize);

                    // ===== Verify Signature =====
                    ByteArrayOutputStream metaStream =
                            new ByteArrayOutputStream();
                    DataOutputStream metaOut =
                            new DataOutputStream(metaStream);

                    metaOut.writeUTF(fileName);
                    metaOut.writeLong(encryptedSize);

                    DilithiumSigner verifier =
                            new DilithiumSigner();
                    verifier.init(false, clientDilPublic);

                    if (!verifier.verifySignature(
                            metaStream.toByteArray(),
                            signature)) {

                        System.out.println("❌ Signature invalid.");
                        dos.writeBoolean(false);
                        dos.flush();
                        return;
                    }

                    System.out.println("✅ Signature verified.");

                    // ===== Streaming Decrypt =====
                    Cipher cipher =
                            Cipher.getInstance("AES/GCM/NoPadding");

                    GCMParameterSpec spec =
                            new GCMParameterSpec(128, ivBytes);

                    cipher.init(Cipher.DECRYPT_MODE,
                            aesKey,
                            spec);

                    String outputPath =
                            "received_" + fileName;

                    try (FileOutputStream fos =
                                 new FileOutputStream(outputPath)) {

                        byte[] buffer = new byte[4096];
                        long totalRead = 0;

                        while (totalRead < encryptedSize) {

                            int toRead =
                                    (int)Math.min(buffer.length,
                                            encryptedSize - totalRead);

                            int bytesRead =
                                    dis.read(buffer, 0, toRead);

                            if (bytesRead == -1)
                                break;

                            totalRead += bytesRead;

                            byte[] decryptedChunk =
                                    cipher.update(buffer, 0, bytesRead);

                            if (decryptedChunk != null)
                                fos.write(decryptedChunk);
                        }

                        byte[] finalBytes =
                                cipher.doFinal();

                        if (finalBytes != null)
                            fos.write(finalBytes);

                        System.out.println("✅ File decrypted.");
                        dos.writeBoolean(true);
                        dos.flush();

                    } catch (AEADBadTagException e) {

                        System.out.println("❌ GCM tag verification failed.");
                        dos.writeBoolean(false);
                        dos.flush();
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}