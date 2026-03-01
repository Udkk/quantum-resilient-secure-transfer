import crypto.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

import org.bouncycastle.pqc.crypto.crystals.dilithium.*;

public class MainServer {

    public static void main(String[] args) {

        try {
            CryptoProvider.register();

            int port = 5000;
            System.out.println("Server starting on port " + port + "...");

            // =========================
            // GENERATE SERVER KEYS
            // =========================

            KeyPair serverECDH = ECDHKeyExchange.generateKeyPair();

            AsymmetricCipherKeyPair serverKyberKP =
                    KyberKeyExchange.generateKyberKeyPair();

            KyberPublicKeyParameters serverKyberPublic =
                    (KyberPublicKeyParameters) serverKyberKP.getPublic();

            KyberPrivateKeyParameters serverKyberPrivate =
                    (KyberPrivateKeyParameters) serverKyberKP.getPrivate();

            try (ServerSocket serverSocket = new ServerSocket(port)) {

                System.out.println("Waiting for client...");

                try (Socket socket = serverSocket.accept();
                     DataInputStream dis = new DataInputStream(socket.getInputStream());
                     DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

                    System.out.println("Client connected!");

                    // =========================
                    // 1. SEND SERVER PUBLIC KEYS
                    // =========================

                    byte[] serverECDHPubBytes =
                            serverECDH.getPublic().getEncoded();
                    dos.writeInt(serverECDHPubBytes.length);
                    dos.write(serverECDHPubBytes);

                    byte[] serverKyberPubBytes =
                            serverKyberPublic.getEncoded();
                    dos.writeInt(serverKyberPubBytes.length);
                    dos.write(serverKyberPubBytes);

                    dos.flush();

                    // =========================
                    // 2. RECEIVE CLIENT ECDH PUBLIC KEY
                    // =========================

                    int clientECDHPubLen = dis.readInt();
                    byte[] clientECDHPubBytes = new byte[clientECDHPubLen];
                    dis.readFully(clientECDHPubBytes);

                    KeyFactory kf = KeyFactory.getInstance("EC");
                    PublicKey clientECDHPublic =
                            kf.generatePublic(
                                    new X509EncodedKeySpec(clientECDHPubBytes));

                    byte[] serverECDHSecret =
                            ECDHKeyExchange.computeSharedSecret(
                                    serverECDH.getPrivate(),
                                    clientECDHPublic
                            );

                    // =========================
                    // 3. RECEIVE KYBER ENCAPSULATION
                    // =========================

                    int encapLen = dis.readInt();
                    byte[] kyberEncapsulation = new byte[encapLen];
                    dis.readFully(kyberEncapsulation);

                    byte[] serverKyberSecret =
                            KyberKeyExchange.decapsulate(
                                    serverKyberPrivate,
                                    kyberEncapsulation
                            );

                    // =========================
                    // 4. DERIVE HYBRID AES KEY
                    // =========================

                    SecretKey serverAESKey =
                            HybridKeyDerivation.deriveHybridAESKey(
                                    serverECDHSecret,
                                    serverKyberSecret
                            );

                    System.out.println("Hybrid AES key derived successfully!");

                    // =========================
                    // 5. RECEIVE DILITHIUM PUBLIC KEY
                    // =========================

                    int dilithiumPubLen = dis.readInt();
                    byte[] dilithiumPubBytes =
                            new byte[dilithiumPubLen];
                    dis.readFully(dilithiumPubBytes);

                    DilithiumPublicKeyParameters clientDilithiumPublic =
                            new DilithiumPublicKeyParameters(
                                    DilithiumParameters.dilithium3,
                                    dilithiumPubBytes
                            );

                    // =========================
                    // 6. RECEIVE SIGNATURE
                    // =========================

                    int sigLen = dis.readInt();
                    byte[] signature = new byte[sigLen];
                    dis.readFully(signature);

                    // =========================
                    // 7. RECEIVE FILE METADATA
                    // =========================

                    String fileName = dis.readUTF();
                    System.out.println("Receiving file: " + fileName);

                    int ivLength = dis.readInt();
                    byte[] ivBytes = new byte[ivLength];
                    dis.readFully(ivBytes);
                    IvParameterSpec iv = new IvParameterSpec(ivBytes);

                    long fileSize = dis.readLong();
                    System.out.println("Encrypted file size: " + fileSize);

                    // =========================
                    // 8. RECEIVE ENCRYPTED FILE
                    // =========================

                    byte[] encryptedFile =
                            new byte[(int) fileSize];
                    dis.readFully(encryptedFile);

                    // =========================
                    // 9. RECEIVE HASH (Encrypted Integrity)
                    // =========================

                    int hashLen = dis.readInt();
                    byte[] receivedHash = new byte[hashLen];
                    dis.readFully(receivedHash);

                    byte[] computedHash =
                            HashUtil.sha256(encryptedFile);

                    if (!Arrays.equals(receivedHash, computedHash)) {
                        System.out.println("ERROR: File hash mismatch!");
                        return;
                    }

                    System.out.println("Encrypted file hash verified!");

                    // =========================
                    // 10. DECRYPT FILE
                    // =========================

                    byte[] decryptedFile =
                            AESUtil.decrypt(
                                    encryptedFile,
                                    serverAESKey,
                                    iv
                            );

                    String decryptedFilePath =
                            "received_decrypted_" + fileName;

                    try (FileOutputStream fos =
                                 new FileOutputStream(decryptedFilePath)) {
                        fos.write(decryptedFile);
                    }

                    System.out.println("File decrypted successfully!");

                    // =========================
                    // 11. VERIFY DILITHIUM SIGNATURE
                    // =========================

                    byte[] plaintextHash =
                            HashUtil.sha256(decryptedFile);

                    ByteArrayOutputStream metaStream =
                            new ByteArrayOutputStream();
                    DataOutputStream metaOut =
                            new DataOutputStream(metaStream);

                    metaOut.writeUTF(fileName);
                    metaOut.writeLong(fileSize);
                    metaOut.write(plaintextHash);

                    byte[] dataToVerify =
                            metaStream.toByteArray();

                    DilithiumSigner verifier =
                            new DilithiumSigner();
                    verifier.init(false, clientDilithiumPublic);

                    boolean valid =
                            verifier.verifySignature(
                                    dataToVerify,
                                    signature
                            );

                    if (!valid) {
                        System.out.println("❌ SIGNATURE VERIFICATION FAILED!");
                        return;
                    }

                    System.out.println("✅ Dilithium signature verified successfully!");
                    System.out.println("SUCCESS: Secure file transfer complete!");

                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}