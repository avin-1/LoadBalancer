package Routing;

import Config.ConfigLoader;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Consistent Hashing Router with Virtual Nodes.
 * Replaces the previous Least-Connections router to support state-machine evictions.
 */
public class Routing {

    private static final int VIRTUAL_NODES = 100;
    
    // The consistent hashing ring
    private static final TreeMap<Integer, String> hashRing = new TreeMap<>();
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    // Track active connections for observability
    public static final Map<String, Integer> activeConnections = new ConcurrentHashMap<>();

    static {
        // Initialize ring from Config bootstrapper
        for (String url : ConfigLoader.getInstance().backends) {
            addServer(url);
            activeConnections.put(url, 0);
        }
    }

    /**
     * Adds a server to the hash ring by creating virtual nodes.
     * Uses a Write Lock to prevent concurrent routing issues.
     */
    public static void addServer(String serverUrl) {
        lock.writeLock().lock();
        try {
            for (int i = 0; i < VIRTUAL_NODES; i++) {
                int hash = getHash(serverUrl + "-VN" + i);
                hashRing.put(hash, serverUrl);
            }
            System.out.println("[Routing] Server added/restored to ring: " + serverUrl);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Removes a server completely from the hash ring.
     * Uses a Write Lock.
     */
    public static void evictServer(String serverUrl) {
        lock.writeLock().lock();
        try {
            // Remove all virtual nodes that map to this server URL
            hashRing.values().removeIf(val -> val.equals(serverUrl));
            System.err.println("[Routing] 🚨 Server EVICTED from ring: " + serverUrl);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Finds the appropriate backend server for a given client IP.
     * Uses a Read Lock for high concurrency.
     */
    public static String getServer(String clientIp) {
        lock.readLock().lock();
        try {
            if (hashRing.isEmpty()) {
                return null; // All servers are dead
            }
            int hash = getHash(clientIp);
            Map.Entry<Integer, String> entry = hashRing.ceilingEntry(hash);
            if (entry == null) {
                // Wrap around to the first node
                entry = hashRing.firstEntry();
            }
            return entry.getValue();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Generates a stable hash using MD5.
     */
    private static int getHash(String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(key.getBytes(StandardCharsets.UTF_8));
            // Use the first 4 bytes to form an integer
            return ((digest[3] & 0xFF) << 24) |
                   ((digest[2] & 0xFF) << 16) |
                   ((digest[1] & 0xFF) << 8)  |
                    (digest[0] & 0xFF);
        } catch (NoSuchAlgorithmException e) {
            return key.hashCode(); // Fallback
        }
    }
}
