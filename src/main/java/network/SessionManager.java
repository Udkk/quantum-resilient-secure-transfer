package network;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {

    // Allow max 2 minutes clock skew
    private static final long ALLOWED_TIME_WINDOW_MS = 2 * 60 * 1000;

    // Session cache
    private static final Map<String, Long> sessionCache = new ConcurrentHashMap<>();

    // Register session
    public static boolean registerSession(String sessionId, long timestamp) {

        long now = Instant.now().toEpochMilli();

        // Check timestamp validity
        if (Math.abs(now - timestamp) > ALLOWED_TIME_WINDOW_MS) {
            System.out.println("[SECURITY] Timestamp outside allowed window.");
            return false;
        }

        // Prevent replay
        if (sessionCache.containsKey(sessionId)) {
            System.out.println("[SECURITY] Replay detected. Session already exists.");
            return false;
        }

        sessionCache.put(sessionId, timestamp);
        return true;
    }

    // Cleanup old sessions
    public static void startCleanupThread() {

        Thread cleaner = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60_000); // cleanup every 60 seconds
                    long now = Instant.now().toEpochMilli();

                    sessionCache.entrySet().removeIf(entry ->
                            now - entry.getValue() > ALLOWED_TIME_WINDOW_MS
                    );

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });

        cleaner.setDaemon(true);
        cleaner.start();
    }
}