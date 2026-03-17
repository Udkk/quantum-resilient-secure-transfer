package network;

public class TransferProtocol {

    // ===== Protocol Identity =====
    public static final String PROTOCOL_NAME = "HPQ-SFTS"; // Hybrid Post-Quantum Secure File Transfer System
    public static final String VERSION = "1.0";

    // ===== Cryptographic Suite =====
    public static final String KEY_EXCHANGE = "ECDH + KYBER-768";
    public static final String KDF = "HKDF-SHA256";
    public static final String CIPHER = "AES-256-GCM";
    public static final String SIGNATURE = "Dilithium";

    // ===== Protocol Steps =====
    public static final int STEP_HELLO = 1;
    public static final int STEP_KEY_EXCHANGE = 2;
    public static final int STEP_METADATA = 3;
    public static final int STEP_FILE_TRANSFER = 4;
    public static final int STEP_COMPLETE = 5;

    private TransferProtocol() {
        // Prevent instantiation
    }
}