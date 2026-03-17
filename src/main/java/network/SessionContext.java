package network;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class SessionContext {

    private final String sessionId;
    private final long timestamp;
    private byte[] sharedSecret;
    private byte[] clientNonce;
    private byte[] serverNonce;

    public SessionContext() {
        this.sessionId = UUID.randomUUID().toString();
        this.timestamp = Instant.now().toEpochMilli();
        this.clientNonce = generateNonce();
        this.serverNonce = generateNonce();
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public String getSessionId() {
        return sessionId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public byte[] getClientNonce() {
        return clientNonce;
    }

    public byte[] getServerNonce() {
        return serverNonce;
    }

    public String getEncodedClientNonce() {
        return Base64.getEncoder().encodeToString(clientNonce);
    }

    public String getEncodedServerNonce() {
        return Base64.getEncoder().encodeToString(serverNonce);
    }
}