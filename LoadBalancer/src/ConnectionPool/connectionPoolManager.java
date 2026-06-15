package ConnectionPool;

// ─────────────────────────────────────────────────────────────────────────────
// IMPORTS — Why each one is needed
// ─────────────────────────────────────────────────────────────────────────────

// InetSocketAddress: Represents a "hostname + port" pair (e.g., "backend-1.internal:443").
// Used when registering a new BackendConnectionPool so it knows which server to connect to.
import java.net.InetSocketAddress;

// Map.Entry: Provides typed iteration over the key-value pairs in the pools map.
import java.util.Map;

// ConcurrentHashMap: Thread-safe hash map used to store the pools keyed by server ID string.
// Multiple threads (request handlers) may simultaneously call getPool() to retrieve pools,
// so a regular HashMap would be unsafe here.
import java.util.concurrent.ConcurrentHashMap;

// Executors + ScheduledExecutorService + TimeUnit: Used to create a single background thread
// that wakes up every 5 seconds and evicts idle connections from ALL registered pools.
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Centralized registry and lifecycle supervisor for all per-server {@link BackendConnectionPool} instances.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER CONTEXT — Why do we need a "Manager" on top of the Pool?
 * ═══════════════════════════════════════════════════════════════════
 * A load balancer doesn't talk to just ONE backend server — it manages traffic
 * across MULTIPLE backend servers (e.g., Server-1 at localhost:3001,
 * Server-2 at localhost:3002, Server-3 at localhost:3003).
 *
 * Each backend server needs its OWN dedicated connection pool (since connections
 * are server-specific — you can't reuse a socket to Server-1 when talking to Server-2).
 *
 * This creates a new problem: who manages all those individual pools?
 *   - Who creates them when a new backend is registered?
 *   - Who looks up the right pool when a request arrives?
 *   - Who runs eviction (cleanup of stale connections) across ALL pools?
 *   - Who shuts them all down when the server stops?
 *
 * The connectionPoolManager answers all of these questions. It's a single central
 * authority — a registry — that the rest of the load balancer can use via simple
 * methods like registerPool("server-1", ...) and getPool("server-1").
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * Without a central manager, every component that needed a backend connection would
 * have to create, track, and clean up its own pool — duplicating logic and risk.
 * The manager centralizes all pool lifecycle operations in one place, following
 * the Single Responsibility Principle.
 *
 * <p><strong>WHAT this class does:</strong>
 * <ul>
 *   <li>Maintains a {@link ConcurrentHashMap} of Server ID → {@link BackendConnectionPool}.</li>
 *   <li>{@link #registerPool}: Adds a new pool for a backend server.</li>
 *   <li>{@link #getPool}: Retrieves the pool for a specific server so callers can lease connections.</li>
 *   <li>Runs a single background eviction thread that periodically sweeps all registered pools.</li>
 *   <li>{@link #shutdown}: Stops the eviction thread and closes ALL connections in ALL pools.</li>
 * </ul>
 *
 * <p><strong>HOW the eviction loop works:</strong>
 * A single daemon thread wakes up every 5 seconds and calls {@link BackendConnectionPool#evictExpired()}
 * on every registered pool. This means even if you have 10 backend servers registered, there is
 * still only ONE eviction thread — not 10. This is efficient because eviction is fast (just
 * checking timestamps) and does not need to run on a per-pool basis simultaneously.
 *
 * <p><strong>Naming note:</strong>
 * The class name starts with a lowercase letter ({@code connectionPoolManager}) which is
 * non-standard Java convention (classes should be PascalCase). In production code this
 * would be named {@code ConnectionPoolManager}. The functionality is unchanged.
 */
public final class connectionPoolManager {

    // ─────────────────────────────────────────────────────────────────────────
    // FIELDS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The central registry mapping a human-readable server ID to its connection pool.
     *
     * <p><strong>Key:</strong>   A unique string identifier for the backend server.
     *                            Example: "server-1", "api-backend-us-east", "db-proxy".
     *                            This can be any string the operator chooses.
     *
     * <p><strong>Value:</strong> The {@link BackendConnectionPool} dedicated to that server.
     *                            Each pool manages connections to ONE specific host:port.
     *
     * <p><strong>WHY ConcurrentHashMap:</strong>
     * The main request-handling threads call {@link #getPool(String)} on every incoming request,
     * which is a concurrent read operation. Meanwhile, a (rare) server registration event via
     * {@link #registerPool} is a concurrent write. ConcurrentHashMap handles all combinations
     * safely without blocking readers during writes.
     */
    private final ConcurrentHashMap<String, BackendConnectionPool> pools = new ConcurrentHashMap<>();

    /**
     * The background daemon thread that periodically evicts stale idle connections from ALL pools.
     *
     * <p><strong>WHY a single shared eviction thread for all pools:</strong>
     * Eviction is a lightweight scan operation — it checks timestamps and closes dead sockets.
     * It runs every 5 seconds, takes a fraction of a millisecond, and does not block request handling.
     * Using ONE shared thread (instead of one per pool) minimizes OS thread overhead and context switching.
     * This design scales to any number of registered pools without adding more threads.
     *
     * <p><strong>WHY a daemon thread:</strong>
     * Daemon threads are automatically killed when the JVM shuts down (when no non-daemon threads
     * remain). This means we don't HAVE to call {@link #shutdown()} for the JVM to exit cleanly.
     * However, calling shutdown() is still recommended for a graceful, controlled teardown.
     */
    private final ScheduledExecutorService evictionExecutor;

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initializes the manager and immediately starts the background eviction scheduler.
     *
     * <p><strong>WHY start the scheduler in the constructor (not lazily on first use):</strong>
     * If we waited until the first pool was registered to start eviction, there would be a gap
     * where stale connections could accumulate without being cleaned. Starting the scheduler
     * immediately guarantees eviction runs from the moment the manager exists.
     *
     * <p><strong>HOW the thread factory works:</strong>
     * {@code Executors.newSingleThreadScheduledExecutor(threadFactory)} takes a {@link java.util.concurrent.ThreadFactory}
     * — a factory that creates the actual OS thread. The lambda here:
     * <ol>
     *   <li>Creates a new {@link Thread} wrapping the {@code runnable} (the scheduler's internal task runner).</li>
     *   <li>Names it {@code "pool-eviction-thread"} — this name appears in thread dumps and logs,
     *       making debugging much easier ("which thread is stuck?" → "pool-eviction-thread").</li>
     *   <li>Sets it as a daemon thread so JVM shutdown is not blocked.</li>
     * </ol>
     *
     * <p><strong>HOW the eviction schedule is set up:</strong>
     * {@code scheduleAtFixedRate(task, initialDelay, period, unit)}:
     * <ul>
     *   <li>{@code task}: {@code this::evictIdleConnections} — the method to run each cycle.</li>
     *   <li>{@code initialDelay}: 5 seconds — wait 5 seconds before the very first eviction run.
     *       This gives the server time to start up and populate the pools before we scan them.</li>
     *   <li>{@code period}: 5 seconds — run every 5 seconds after that.</li>
     *   <li>{@code unit}: {@link TimeUnit#SECONDS}.</li>
     * </ul>
     */
    public connectionPoolManager() {
        // Create a single-threaded scheduled executor with a named daemon thread.
        this.evictionExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "pool-eviction-thread"); // Named for debugging
            thread.setDaemon(true); // Don't block JVM shutdown
            return thread;
        });

        // Schedule the eviction task to run every 5 seconds, starting 5 seconds from now.
        // scheduleAtFixedRate: if eviction takes less than 5 seconds (which it always should),
        // the next run starts exactly 5 seconds after the PREVIOUS START time (not end time).
        this.evictionExecutor.scheduleAtFixedRate(this::evictIdleConnections, 5, 5, TimeUnit.SECONDS);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Registers a new backend server and creates a dedicated connection pool for it.
     *
     * <p><strong>WHY use a string serverID (not just the address):</strong>
     * An IP address or hostname might change (e.g., servers behind a load balancer IP, or
     * after a rolling deployment). A stable, human-readable ID like "api-server-1" gives
     * the operator control over naming and allows address updates without changing all call sites.
     *
     * <p><strong>WHAT:</strong>
     * Creates a new {@link BackendConnectionPool} configured for the given server address
     * and stores it in the registry under the given ID. If a pool already exists under that
     * ID, it is replaced (the old pool is NOT closed automatically — caller must manage that).
     *
     * <p><strong>HOW:</strong>
     * Delegates all pool creation logic to the {@link BackendConnectionPool} constructor,
     * then inserts the result into the {@link ConcurrentHashMap} with {@code put()}.
     *
     * @param serverID        A unique identifier for this backend server (e.g., "server-1").
     * @param remoteAddress   The host and port of the backend server to connect to.
     * @param maxConnections  The maximum number of simultaneous connections to maintain.
     * @param idleTtlMs       How long (ms) a connection can sit idle before being evicted.
     */
    public void registerPool(String serverID, InetSocketAddress remoteAddress,
                             int maxConnections, long idleTtlMs) {
        // Create a new pool for this server and store it in the registry.
        // ConcurrentHashMap.put() is atomic — thread-safe without additional locking.
        pools.put(serverID, new BackendConnectionPool(remoteAddress, maxConnections, idleTtlMs));
    }

    /**
     * Retrieves the connection pool for a specific backend server by its ID.
     *
     * <p><strong>WHY return BackendConnectionPool (not SocketChannel directly):</strong>
     * The caller may need to perform multiple operations on the pool: lease a connection,
     * use it to forward a request, then release it. Returning the pool object gives the
     * caller full control over the acquire/release lifecycle. Returning just a socket
     * would hide the pool abstraction and make release impossible.
     *
     * <p><strong>WHAT:</strong>
     * Returns the {@link BackendConnectionPool} registered under {@code serverID},
     * or {@code null} if no pool has been registered for that ID.
     *
     * <p><strong>HOW:</strong>
     * A simple {@link ConcurrentHashMap#get(Object)} lookup — O(1) average time complexity.
     * Thread-safe because ConcurrentHashMap guarantees safe concurrent reads.
     *
     * <p><strong>Caller usage pattern:</strong>
     * <pre>
     *   BackendConnectionPool pool = manager.getPool("server-1");
     *   if (pool == null) { // handle: server not registered }
     *   SocketChannel channel = pool.leaseConnection(5000);
     *   try {
     *       // ... forward request using channel ...
     *   } finally {
     *       pool.releaseConnection(channel, true); // ALWAYS release in a finally block
     *   }
     * </pre>
     *
     * @param serverID The same identifier that was used in {@link #registerPool}.
     * @return The {@link BackendConnectionPool} for that server, or {@code null} if not registered.
     */
    public BackendConnectionPool getPool(String serverID) {
        return pools.get(serverID);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The eviction task: iterates over every registered pool and triggers idle connection cleanup.
     *
     * <p><strong>WHY this is private:</strong>
     * This method is the scheduler's internal task — it should ONLY be called by the
     * eviction scheduler thread, never directly by external code. Making it private
     * enforces this contract.
     *
     * <p><strong>WHAT:</strong>
     * Calls {@link BackendConnectionPool#evictExpired()} on every pool in the registry.
     * Each pool's {@code evictExpired()} method handles its own internal cleanup logic.
     *
     * <p><strong>HOW:</strong>
     * Iterates over the values (the pool objects) of the {@link ConcurrentHashMap}.
     * ConcurrentHashMap guarantees that this iteration is safe even if another thread
     * is simultaneously adding/removing pools (the iteration sees a weakly consistent
     * snapshot — it won't throw {@link java.util.ConcurrentModificationException}).
     *
     * <p><strong>Performance note:</strong>
     * This method is called every 5 seconds. Even with 50 registered backends, each
     * call to evictExpired() is fast (microseconds), so this task completes almost instantly.
     */
    private void evictIdleConnections() {
        // Loop through every registered pool and trigger its own eviction sweep.
        // Each pool knows its own TTL and handles its own internal cleanup.
        for (BackendConnectionPool pool : pools.values()) {
            pool.evictExpired();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LIFECYCLE
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Shuts down the background eviction scheduler and closes ALL connections in ALL pools.
     *
     * <p><strong>WHY this should be called on server shutdown:</strong>
     * Without calling shutdown():
     * <ul>
     *   <li>The eviction daemon thread (being a daemon) would be killed abruptly, potentially
     *       mid-eviction, leaving some connections in an inconsistent state.</li>
     *   <li>Active backend connections would NOT be gracefully closed — the remote servers
     *       would see abrupt TCP resets instead of proper TLS close_notify + TCP FIN sequences.</li>
     *   <li>In testing frameworks, leftover live sockets may prevent test teardown from completing.</li>
     * </ul>
     *
     * <p><strong>WHAT:</strong>
     * Forcibly stops the eviction scheduler (immediate, not graceful — we use {@code shutdownNow()}
     * here to terminate quickly during server shutdown). Then closes every connection in every pool.
     *
     * <p><strong>HOW:</strong>
     * <ol>
     *   <li>{@code evictionExecutor.shutdownNow()}: Sends an interrupt to the eviction thread
     *       and returns a list of unstarted tasks (which we discard — there are none in a periodic scheduler).</li>
     *   <li>Iterates over all registered pools via {@code entrySet()} and calls {@link BackendConnectionPool#closeAll()}
     *       on each, which closes every socket in that pool (idle + active).</li>
     *   <li>Clears the registry map so all pool references are released for garbage collection.</li>
     * </ol>
     */
    public void shutdown() {
        // Step 1: Force-stop the eviction scheduler immediately (don't wait for current task).
        // WHY shutdownNow() instead of shutdown() + awaitTermination():
        // During server shutdown, we want to exit as fast as possible. The eviction task
        // is idempotent and non-critical — if we interrupt it mid-scan, nothing is corrupted.
        evictionExecutor.shutdownNow();

        // Step 2: Close all connections in all registered pools.
        for (Map.Entry<String, BackendConnectionPool> entry : pools.entrySet()) {
            // closeAll() closes every idle and active socket in this pool and resets it to empty.
            entry.getValue().closeAll();
        }

        // Step 3: Clear the registry — releases all pool object references for GC.
        pools.clear();
    }
}
