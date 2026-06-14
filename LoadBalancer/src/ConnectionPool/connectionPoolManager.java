package ConnectionPool;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * WHY: A Load Balancer talks to multiple different backend servers (Server 1, Server 2, etc.). 
 *      We need a centralized place to manage the individual connection pools for all of them.
 * 
 * WHAT: The `connectionPoolManager` acts as a registry. It holds a mapping of `Server ID` -> `BackendConnectionPool`.
 *       It also runs a single background maintenance thread to clean up dead connections across all pools.
 * 
 * HOW: 
 *   - Uses a `ConcurrentHashMap` to safely store and retrieve pools by their Server ID.
 *   - Spawns a background `ScheduledExecutorService` (daemon thread) that wakes up every 5 seconds.
 *   - When it wakes up, it loops through every registered pool and calls `evictExpired()` to clean up old connections.
 */
public final class connectionPoolManager {
    private final ConcurrentHashMap<String, BackendConnectionPool> pools = new ConcurrentHashMap<>();
    private final ScheduledExecutorService evictionExecutor;

    public connectionPoolManager() {
        this.evictionExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "pool-eviction-thread");
            thread.setDaemon(true);
            return thread;
        });
        this.evictionExecutor.scheduleAtFixedRate(this::evictIdleConnections, 5, 5, TimeUnit.SECONDS);
    }

    public void registerPool(String serverID, InetSocketAddress remoteAddress, int maxConnections, long idleTtlMs) {
        pools.put(serverID, new BackendConnectionPool(remoteAddress, maxConnections, idleTtlMs));
    }

    public BackendConnectionPool getPool(String serverID) {
        return pools.get(serverID);
    }

    private void evictIdleConnections() {
        for (BackendConnectionPool pool : pools.values()) {
            pool.evictExpired();
        }
    }

    public void shutdown() {
        evictionExecutor.shutdownNow();
        for (Map.Entry<String, BackendConnectionPool> entry : pools.entrySet()) {
            entry.getValue().closeAll();
        }
        pools.clear();
    }
}
