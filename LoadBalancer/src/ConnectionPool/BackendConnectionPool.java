package ConnectionPool;

// ─────────────────────────────────────────────────────────────────────────────
// IMPORTS — Why each one is needed
// ─────────────────────────────────────────────────────────────────────────────
import java.io.IOException;
import java.net.InetSocketAddress; // Represents a host:port combination (e.g., "backend.server.com:443")
import java.nio.ByteBuffer;        // Java NIO buffer used for TLS handshake data exchange
import java.nio.channels.SocketChannel; // NIO non-blocking TCP socket channel

// SecureRandom / X509Certificate: Required for building a "trust all" SSL context
// for connecting to backend servers with self-signed certificates.
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

// Objects: Provides Objects.requireNonNull() for null-safe parameter validation.
import java.util.Objects;

// BlockingQueue / LinkedBlockingQueue: A thread-safe queue that holds idle connections.
// "Blocking" means poll() can optionally WAIT for an item rather than returning null.
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

// TimeUnit + TimeoutException: For expressing wait durations and signaling timeout.
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

// AtomicInteger: A thread-safe integer counter. Used to track total allocated connections
// without needing synchronized blocks. compareAndSet() ensures race-free increments.
import java.util.concurrent.atomic.AtomicInteger;

// ConcurrentHashMap: Thread-safe map to track ACTIVE (in-use) connections.
import java.util.concurrent.ConcurrentHashMap;

// Logger: Java's built-in logging API for diagnostic messages.
import java.util.logging.Level;
import java.util.logging.Logger;

// SSL imports: For creating encrypted TLS connections to backend servers.
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * A pool of reusable, pre-established TLS connections to a SINGLE backend server.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER CONTEXT — What is a Connection Pool and why do we need one?
 * ═══════════════════════════════════════════════════════════════════
 * Every time the load balancer needs to forward a client request to a backend
 * server, it needs a network connection. Creating a brand new TCP+TLS connection
 * involves:
 *
 *   1. TCP 3-Way Handshake (~1-2 round trips): SYN → SYN-ACK → ACK
 *   2. TLS Handshake (~2+ round trips): ClientHello, ServerHello, certificate
 *      exchange, key agreement, ChangeCipherSpec messages.
 *
 * This entire process can take 50-300ms PER REQUEST. If we open and close a
 * fresh connection for every single client request, those 50-300ms of overhead
 * ACCUMULATES to thousands of milliseconds of wasted time under load.
 *
 * A Connection Pool solves this by:
 *   • Pre-establishing connections to the backend and keeping them OPEN.
 *   • When a request comes in, it BORROWS an idle connection (instant — no handshake).
 *   • When done, it RETURNS the connection to the pool instead of closing it.
 *   • This reduces per-request overhead to nearly zero once the pool is "warmed up".
 *
 * Think of it like renting bikes at a bike station:
 *   Without pool: Buy a new bike for every trip, then discard it. Very wasteful.
 *   With pool:    Pick up an existing bike, ride it, return it. Much faster.
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * Establishing a new TLS connection to a backend server for every single forwarded
 * request is extremely expensive in latency and CPU cycles (TLS key negotiation
 * requires asymmetric cryptography). This pool amortizes that cost by reusing
 * established TLS sessions.
 *
 * <p><strong>WHAT this class manages:</strong>
 * <ul>
 *   <li>An idle queue ({@link #idleQueue}) of available, pre-connected {@link PooledTLSConnection} objects.</li>
 *   <li>An active registry ({@link #activeRegistry}) of connections currently in use.</li>
 *   <li>A count of total allocated connections to enforce the maximum cap.</li>
 *   <li>TLS handshake logic for creating new connections when the pool needs to grow.</li>
 * </ul>
 *
 * <p><strong>HOW connections flow through the pool:</strong>
 * <pre>
 *   [IDLE QUEUE]  ──leaseConnection()──▶  [ACTIVE REGISTRY]
 *       ▲                                         │
 *       └────────releaseConnection()──────────────┘
 *                  (if keepAlive=true)
 * </pre>
 * <ol>
 *   <li>{@link #leaseConnection(long)}: Tries to get an idle connection. If none available,
 *       creates a new one (up to {@link #maxConnections}). If at capacity, waits for one to be released.</li>
 *   <li>{@link #releaseConnection(SocketChannel, boolean)}: Returns the connection to the idle queue
 *       (if healthy and keepAlive=true) or closes it permanently (if damaged or keepAlive=false).</li>
 * </ol>
 */
public final class BackendConnectionPool {

    // A logger for diagnostic messages — uses the class name as the logger category.
    private static final Logger logger = Logger.getLogger(BackendConnectionPool.class.getName());

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURATION FIELDS
    // ─────────────────────────────────────────────────────────────────────────

    // The host:port of the backend server this pool connects to.
    // Example: new InetSocketAddress("backend.example.com", 443)
    private final InetSocketAddress remoteAddress;

    // The hard cap on the total number of connections this pool can hold.
    // Prevents unbounded connection growth under extreme load.
    private final int maxConnections;

    // Maximum time (in milliseconds) a connection can sit idle in the queue before
    // being considered "stale" and evicted by the eviction task.
    private final long idleTtlMs;

    // ─────────────────────────────────────────────────────────────────────────
    // STATE FIELDS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Thread-safe queue holding idle (available) connections ready to be leased.
     *
     * <p><strong>WHY LinkedBlockingQueue:</strong>
     * A blocking queue allows {@link #leaseConnection(long)} to WAIT for an idle connection
     * to become available (via {@code idleQueue.poll(timeout, unit)}) instead of immediately
     * throwing a timeout exception. This absorbs brief traffic spikes gracefully.
     *
     * <p><strong>WHY no capacity limit on the queue constructor:</strong>
     * The total connection count is bounded by {@link #totalAllocatedCount} and
     * {@link #maxConnections}. The queue itself doesn't need a secondary capacity limit.
     */
    private final BlockingQueue<PooledTLSConnection> idleQueue;

    /**
     * Thread-safe map of connections currently lent out to request handlers.
     *
     * <p><strong>Key:</strong>   The {@link SocketChannel} object (unique per connection).
     * <p><strong>Value:</strong> The full {@link PooledTLSConnection} wrapper (contains the SSLEngine).
     *
     * <p><strong>WHY track active connections separately:</strong>
     * We need to retrieve the {@link SSLEngine} for a given {@link SocketChannel}
     * (so we can encrypt/decrypt data over it). The active registry provides this
     * O(1) lookup. It also lets us count how many connections are currently "checked out".
     */
    private final ConcurrentHashMap<SocketChannel, PooledTLSConnection> activeRegistry;

    /**
     * Atomic counter tracking the TOTAL number of connections allocated (idle + active).
     *
     * <p><strong>WHY AtomicInteger (not a regular int or synchronized block):</strong>
     * Multiple threads may try to create new connections simultaneously (if the idle queue
     * is empty and all threads see a count below {@link #maxConnections}). We use
     * {@link AtomicInteger#compareAndSet(int, int)} to ensure only ONE thread successfully
     * "claims" the right to create a new connection — the others retry the lease loop.
     * This is a lock-free approach that avoids bottlenecks.
     */
    private final AtomicInteger totalAllocatedCount;

    // The SSL context used to create new SSLEngine instances for backend TLS connections.
    // Pre-built once in the constructor and reused for all new connections.
    private final SSLContext sslContext;

    // ─────────────────────────────────────────────────────────────────────────
    // INNER CLASS: PooledTLSConnection
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Bundles a {@link SocketChannel} and its dedicated {@link SSLEngine} into one managed unit.
     *
     * <p><strong>WHY bundle these two objects together:</strong>
     * A TLS connection is NOT just a TCP socket. It also has an {@link SSLEngine} that
     * maintains the cryptographic session state (encryption keys, sequence numbers, etc.).
     * An SSLEngine is BOUND to one specific connection — you cannot swap engines between sockets.
     * By wrapping both in one object, we ensure they are always kept together and neither
     * is ever accidentally mixed up with another connection's engine.
     *
     * <p><strong>WHAT it holds:</strong>
     * <ul>
     *   <li>{@link #channel}: The underlying TCP socket channel for sending/receiving bytes.</li>
     *   <li>{@link #engine}: The TLS session engine for encrypting/decrypting those bytes.</li>
     *   <li>{@link #idleStartTimestamp}: When this connection was last returned to the idle queue
     *       (used by the eviction task to find stale connections).</li>
     * </ul>
     */
    public static final class PooledTLSConnection {
        private final SocketChannel channel;  // The raw TCP socket
        private final SSLEngine engine;       // The TLS session associated with this socket
        private long idleStartTimestamp;      // Millisecond timestamp of when this entered the idle queue

        /**
         * Creates a new pooled connection wrapper.
         *
         * @param channel The connected, TLS-handshaked {@link SocketChannel}.
         * @param engine  The {@link SSLEngine} configured for this specific channel.
         */
        public PooledTLSConnection(SocketChannel channel, SSLEngine engine) {
            this.channel = channel;
            this.engine = engine;
            // Record when this connection was created/returned to idle, for TTL eviction.
            this.idleStartTimestamp = System.currentTimeMillis();
        }

        // ── Accessors ──
        public SocketChannel channel() { return channel; }
        public SSLEngine engine()       { return engine; }
        public long idleStartTimestamp()  { return idleStartTimestamp; }

        /**
         * Refreshes the idle timestamp to "now" when the connection is returned to the pool.
         *
         * WHY: The TTL clock should reset each time the connection re-enters the idle queue,
         * not count from when it was first created. A connection in heavy use every few seconds
         * should NOT be evicted just because it has existed for a long time.
         */
        public void updateIdleTimestamp() {
            this.idleStartTimestamp = System.currentTimeMillis();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initializes the connection pool for a specific backend server.
     *
     * <p><strong>WHY the "trust all" SSLContext:</strong>
     * Backend servers in development typically use self-signed TLS certificates.
     * Java's default SSL context would reject these with an {@code SSLHandshakeException}.
     * We override certificate validation so the pool can connect to ANY backend regardless
     * of its certificate authority. In production, use a proper CA or import the cert.
     *
     * @param remoteAddress   The host and port of the backend server.
     * @param maxConnections  Maximum number of simultaneous connections to this server.
     * @param idleTtlMs       Milliseconds of inactivity before an idle connection is evicted.
     */
    public BackendConnectionPool(InetSocketAddress remoteAddress, int maxConnections, long idleTtlMs) {
        // Validate required parameters — null address would cause confusing NullPointerExceptions later.
        this.remoteAddress = Objects.requireNonNull(remoteAddress);
        this.maxConnections = maxConnections;
        this.idleTtlMs = idleTtlMs;
        this.idleQueue = new LinkedBlockingQueue<>();          // Unbounded idle queue
        this.activeRegistry = new ConcurrentHashMap<>();       // Active connection tracker
        this.totalAllocatedCount = new AtomicInteger(0);       // Start with zero connections

        // ── Build the "trust all" SSL context for backend connections ──
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            this.sslContext = SSLContext.getInstance("TLS");
            this.sslContext.init(null, trustAllCerts, new SecureRandom());
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SSL Context for Connection Pool", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Borrows an idle connection from the pool, creating a new one if needed.
     *
     * <p><strong>WHY this method exists (not just "create a new socket each time"):</strong>
     * See the class-level JavaDoc for the full connection pool rationale.
     * The key benefit is reusing the TLS session to avoid repeated handshakes.
     *
     * <p><strong>WHAT it does:</strong>
     * Returns a {@link SocketChannel} to a fully connected, TLS-handshaked backend server.
     * The caller MUST return this channel via {@link #releaseConnection(SocketChannel, boolean)}
     * when done; otherwise the connection is permanently "leaked" from the pool.
     *
     * <p><strong>HOW the acquisition strategy works (in priority order):</strong>
     * <ol>
     *   <li><strong>Try idle queue first</strong>: {@code idleQueue.poll()} returns an idle
     *       connection instantly if one is available. Health-check it; if healthy → use it.
     *       If unhealthy (disconnected) → discard it and try again.</li>
     *   <li><strong>Create a new connection</strong>: If idle queue is empty AND total
     *       connections is below {@link #maxConnections}, atomically claim a slot using CAS
     *       and create a new TLS connection.</li>
     *   <li><strong>Wait for release</strong>: If at max capacity, block on
     *       {@code idleQueue.poll(timeout)} until a connection is returned or timeout expires.</li>
     * </ol>
     *
     * @param timeoutMs Maximum milliseconds to wait for an available connection.
     * @return A healthy, connected {@link SocketChannel} ready for use.
     * @throws TimeoutException     If no connection becomes available within {@code timeoutMs}.
     * @throws InterruptedException If the waiting thread is interrupted.
     */
    public SocketChannel leaseConnection(long timeoutMs) throws TimeoutException, InterruptedException {
        // Compute the absolute deadline for this acquisition attempt.
        long deadline = System.currentTimeMillis() + timeoutMs;

        while (true) {
            // ── Strategy 1: Try to grab an existing idle connection ──
            // poll() is non-blocking — returns null immediately if the queue is empty.
            PooledTLSConnection pooled = idleQueue.poll();
            if (pooled != null) {
                if (isChannelHealthy(pooled)) {
                    // Connection is alive and connected → register as active and return it.
                    activeRegistry.put(pooled.channel(), pooled);
                    return pooled.channel();
                } else {
                    // Connection died while sitting in the idle queue (server restarted, etc.)
                    // Discard it and try the queue again.
                    closeChannelResources(pooled);
                    continue; // Loop back to try polling another idle connection
                }
            }

            // ── Strategy 2: Create a new connection if under the cap ──
            // Read the current count and attempt to atomically increment it.
            int currentCount = totalAllocatedCount.get();
            if (currentCount < maxConnections) {
                // compareAndSet(expected, newValue):
                //   • If totalAllocatedCount == currentCount → set it to currentCount+1 → return true.
                //   • If another thread already changed it → return false → retry the outer loop.
                // This prevents two threads from both creating connections at the limit boundary.
                if (totalAllocatedCount.compareAndSet(currentCount, currentCount + 1)) {
                    try {
                        // Successfully claimed a new connection slot — create the actual connection.
                        PooledTLSConnection newConn = createNewChannel();
                        activeRegistry.put(newConn.channel(), newConn);
                        return newConn.channel();
                    } catch (Exception e) {
                        // Connection creation failed — decrement the counter to release the claimed slot.
                        totalAllocatedCount.decrementAndGet();
                        logger.log(Level.WARNING, "Failed to instantiate on-demand TLS backend channel", e);
                        // Don't return — loop and try again (maybe an idle one was just returned).
                    }
                }
                // CAS failed (another thread beat us) → loop and retry.
                continue;
            }

            // ── Strategy 3: Pool is at capacity — wait for a connection to be released ──
            long remainingWait = deadline - System.currentTimeMillis();
            if (remainingWait <= 0) {
                // We've already exceeded our deadline without getting a connection.
                throw new TimeoutException("Pool capacity exhausted: no connections available within timeout.");
            }

            // Block until a connection is returned to the idle queue or timeout expires.
            // poll(timeout, unit) returns null if no item appears within the timeout window.
            pooled = idleQueue.poll(remainingWait, TimeUnit.MILLISECONDS);
            if (pooled == null) {
                throw new TimeoutException("Pool capacity exhausted: timed out waiting for idle connection.");
            }

            // Got a connection after waiting — health check it before using.
            if (isChannelHealthy(pooled)) {
                activeRegistry.put(pooled.channel(), pooled);
                return pooled.channel();
            } else {
                // The returned connection was dead — discard it and fall through to retry.
                closeChannelResources(pooled);
            }
        }
    }

    /**
     * Retrieves the {@link PooledTLSConnection} (which contains the {@link SSLEngine})
     * associated with a currently active {@link SocketChannel}.
     *
     * <p><strong>WHY we need this:</strong>
     * The caller receives a plain {@link SocketChannel} from {@link #leaseConnection(long)}.
     * To encrypt/decrypt data over that channel, they also need the channel's paired
     * {@link SSLEngine}. This method provides that lookup.
     *
     * @param channel The active channel returned by a previous {@link #leaseConnection(long)} call.
     * @return The {@link PooledTLSConnection} wrapper, or {@code null} if not found.
     */
    public PooledTLSConnection getTLSConnection(SocketChannel channel) {
        return activeRegistry.get(channel);
    }

    /**
     * Returns a previously leased connection back to the pool (or closes it if damaged).
     *
     * <p><strong>WHY this MUST be called after every leaseConnection():</strong>
     * Failing to release a connection removes it permanently from the pool's tracking.
     * The {@link #totalAllocatedCount} counter stays elevated, and the connection is
     * never returned to the idle queue, effectively "leaking" one connection slot.
     * Under sustained load, leaked slots cause the pool to hit {@link #maxConnections}
     * and start throwing {@link TimeoutException}s.
     *
     * <p><strong>HOW keepAlive routing works:</strong>
     * <ul>
     *   <li>{@code keepAlive = true}: Connection is healthy → refresh idle timestamp → put back in queue.</li>
     *   <li>{@code keepAlive = false}: Client sent "Connection: close" header → close and discard.</li>
     *   <li>Unhealthy channel: Always closed regardless of keepAlive value.</li>
     * </ul>
     *
     * @param channel   The channel previously obtained from {@link #leaseConnection(long)}.
     * @param keepAlive {@code true} to return to the idle pool, {@code false} to permanently close.
     */
    public void releaseConnection(SocketChannel channel, boolean keepAlive) {
        if (channel == null) return;

        // Remove from the active registry. If not found, it was never properly leased.
        PooledTLSConnection pooled = activeRegistry.remove(channel);
        if (pooled == null) {
            // Unknown channel — just close it defensively to avoid a socket leak.
            try { channel.close(); } catch (IOException ignored) {}
            return;
        }

        if (keepAlive && isChannelHealthy(pooled)) {
            // Connection is still alive and the caller wants to keep it → return to idle pool.
            pooled.updateIdleTimestamp(); // Reset TTL clock for eviction purposes.
            if (!idleQueue.offer(pooled)) {
                // idleQueue.offer() fails only if the queue has a capacity limit set and is full.
                // Since we use an unbounded queue, this should rarely (never) fail.
                // If it does, fall through and close the connection.
                closeChannelResources(pooled);
            }
        } else {
            // Connection is damaged OR caller requested close → permanently close it.
            closeChannelResources(pooled);
        }
    }

    /**
     * Scans the idle queue and removes connections that have exceeded their TTL.
     *
     * <p><strong>WHY expire idle connections:</strong>
     * Backend servers may close connections from their side if they've been idle too long
     * (e.g., server-side idle timeout of 30 seconds). If we keep them in our idle queue,
     * the next caller would get a dead connection, causing a failed request. Proactively
     * evicting stale connections prevents this scenario.
     *
     * <p><strong>HOW the scan works:</strong>
     * We poll ALL items from the queue (a snapshot of the current size). For each:
     * <ul>
     *   <li>If it's old ({@code idleTime > idleTtlMs}) or unhealthy → close it.</li>
     *   <li>Otherwise → put it back in the queue (still fresh).</li>
     * </ul>
     * This "drain and re-enqueue" pattern is safe with a blocking queue.
     *
     * <p>This method is called periodically by the {@code connectionPoolManager}'s
     * background eviction thread.
     */
    public void evictExpired() {
        // Snapshot the current queue size to avoid an infinite loop
        // (we re-add healthy connections back to the queue during the loop).
        int queueSize = idleQueue.size();
        long now = System.currentTimeMillis();

        for (int i = 0; i < queueSize; i++) {
            PooledTLSConnection pooled = idleQueue.poll();
            if (pooled == null) break; // Queue drained faster than expected

            long idleTime = now - pooled.idleStartTimestamp();
            if (idleTime > idleTtlMs || !isChannelHealthy(pooled)) {
                // This connection is too old or already dead → close and discard.
                closeChannelResources(pooled);
            } else {
                // This connection is still fresh and healthy → put it back.
                idleQueue.offer(pooled);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Creates a brand new TCP + TLS connection to the backend server.
     *
     * <p><strong>WHY we connect synchronously (blocking) even in an NIO server:</strong>
     * Connection creation is a one-time, infrequent event per pool slot. Paying the cost
     * of a blocking connect here means all subsequent leaseConnection() calls can use the
     * pre-established connection instantly. The blocking cost is amortized across many requests.
     * We then switch the channel to non-blocking mode AFTER the connection is established.
     *
     * <p><strong>HOW:</strong>
     * <ol>
     *   <li>Open a {@link SocketChannel} and connect it to the backend (blocking).</li>
     *   <li>Switch to non-blocking mode (required for NIO operations).</li>
     *   <li>Create an {@link SSLEngine} in client mode for this specific connection.</li>
     *   <li>Run the full TLS handshake via {@link #executeClientTLSHandshake(SocketChannel, SSLEngine)}.</li>
     *   <li>Wrap both in a {@link PooledTLSConnection} and return it.</li>
     * </ol>
     *
     * @return A fully connected and TLS-handshaked {@link PooledTLSConnection}.
     * @throws IOException If connection or handshake fails.
     */
    private PooledTLSConnection createNewChannel() throws IOException {
        // Open a new TCP socket channel and connect it to the backend server.
        // connect() blocks until the TCP 3-way handshake completes.
        SocketChannel channel = SocketChannel.open();
        channel.connect(remoteAddress);

        // Switch to non-blocking mode after connecting — required for NIO-based I/O.
        channel.configureBlocking(false);

        // Create an SSLEngine configured for CLIENT mode (we are connecting TO the backend).
        // WHY pass host and port to createSSLEngine: Enables Server Name Indication (SNI),
        // which tells the server which virtual host certificate to present during the handshake.
        SSLEngine engine = sslContext.createSSLEngine(remoteAddress.getHostString(), remoteAddress.getPort());
        engine.setUseClientMode(true); // We are the client (load balancer) connecting to the server (backend)

        // Execute the multi-step TLS handshake to establish the encrypted session.
        executeClientTLSHandshake(channel, engine);

        // Return the fully established connection wrapper.
        return new PooledTLSConnection(channel, engine);
    }

    /**
     * Executes the TLS handshake state machine as the CLIENT side of the connection.
     *
     * ═══════════════════════════════════════════════════════════════════
     * BEGINNER CONTEXT — What is the TLS Handshake?
     * ═══════════════════════════════════════════════════════════════════
     * TLS (Transport Layer Security) is the protocol that secures HTTPS connections.
     * Before any application data can be exchanged, the client and server must
     * complete a "handshake" to:
     *   1. Agree on which TLS version and cipher suite to use.
     *   2. Authenticate the server (and optionally the client) via certificates.
     *   3. Establish shared symmetric encryption keys (via asymmetric key exchange).
     *
     * Java's {@link SSLEngine} models this handshake as a state machine with these states:
     *   • NEED_WRAP:   Engine has outgoing data to send → call engine.wrap() and write to channel.
     *   • NEED_UNWRAP: Engine needs incoming data → read from channel and call engine.unwrap().
     *   • NEED_TASK:   Engine needs to run a CPU-intensive task (e.g., cert validation).
     *                  Run it synchronously on THIS thread (blocking is acceptable here).
     *   • FINISHED / NOT_HANDSHAKING: Handshake complete! We can now exchange application data.
     * ═══════════════════════════════════════════════════════════════════
     *
     * <p><strong>WHY this is a separate private method:</strong>
     * The handshake logic is complex (~40 lines) and used only during connection creation.
     * Extracting it into a named method makes {@link #createNewChannel()} readable.
     *
     * <p><strong>WHY the Thread.sleep(5) in NEED_UNWRAP:</strong>
     * The channel is in non-blocking mode. If the server's response hasn't arrived yet,
     * {@code channel.read()} returns 0 instead of blocking. We sleep briefly (5ms) before
     * retrying to avoid a tight CPU-burning busy-wait loop while waiting for incoming data.
     *
     * @param channel The connected non-blocking {@link SocketChannel}.
     * @param engine  The {@link SSLEngine} initialized in client mode.
     * @throws IOException If any I/O error occurs during the handshake.
     */
    private void executeClientTLSHandshake(SocketChannel channel, SSLEngine engine) throws IOException {
        // Signal the engine to start the handshake process.
        engine.beginHandshake();

        // Allocate four ByteBuffers for the four data directions:
        //   myNetData:   Outgoing ENCRYPTED data (wrapped by the engine before sending)
        //   peerNetData: Incoming ENCRYPTED data (read from channel before unwrapping)
        //   dummyAppData:Outgoing PLAINTEXT data (empty during handshake — no app data yet)
        //   peerAppData: Incoming PLAINTEXT data (decrypted from peerNetData by the engine)
        ByteBuffer myNetData   = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteBuffer peerNetData = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteBuffer dummyAppData= ByteBuffer.allocate(0); // Nothing to send as application data
        ByteBuffer peerAppData = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());

        // Run the handshake state machine until the engine reports FINISHED.
        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        while (status != SSLEngineResult.HandshakeStatus.FINISHED
            && status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            switch (status) {

                case NEED_UNWRAP:
                    // The engine needs incoming TLS data from the server to proceed.
                    // Read bytes from the backend server into peerNetData.
                    int bytesRead = channel.read(peerNetData);
                    if (bytesRead < 0) {
                        // Server closed the connection unexpectedly during handshake.
                        throw new SSLException("Channel closed during TLS handshake.");
                    } else if (bytesRead == 0) {
                        // Non-blocking read returned nothing yet — server's data is still in transit.
                        // Sleep 5ms to avoid burning the CPU in a tight loop, then retry.
                        try { Thread.sleep(5); } catch (InterruptedException e) {
                            Thread.currentThread().interrupt(); // Preserve interrupt status
                        }
                        continue;
                    }
                    // Flip peerNetData to read-mode so the engine can decrypt it.
                    peerNetData.flip();
                    SSLEngineResult res = engine.unwrap(peerNetData, peerAppData);
                    // Compact back to write-mode for the next read from the channel.
                    peerNetData.compact();
                    status = res.getHandshakeStatus();

                    // Handle buffer overflow: peerAppData wasn't large enough for the decrypted data.
                    // Double the buffer size and copy existing data into the new buffer.
                    if (res.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        ByteBuffer newPeerAppData = ByteBuffer.allocate(peerAppData.capacity() * 2);
                        peerAppData.flip();
                        newPeerAppData.put(peerAppData); // Transfer existing data
                        peerAppData = newPeerAppData;    // Replace old buffer with larger one
                    }
                    break;

                case NEED_WRAP:
                    // The engine has handshake data to send to the server (e.g., ClientHello).
                    myNetData.clear();
                    res = engine.wrap(dummyAppData, myNetData);
                    status = res.getHandshakeStatus();
                    // Flip to read-mode so we can write the encrypted data to the channel.
                    myNetData.flip();
                    // Write loop: channel.write() may not write all bytes at once.
                    while (myNetData.hasRemaining()) {
                        channel.write(myNetData);
                    }
                    break;

                case NEED_TASK:
                    // A CPU-intensive delegated task needs to run (e.g., certificate chain validation,
                    // RSA private key decryption for key exchange).
                    // We run these synchronously on the current thread.
                    // WHY synchronous here (unlike the server's Main.java which offloads to a worker pool):
                    // This method is already being called during connection CREATION, which only happens
                    // infrequently. The blocking cost here is paid once and amortized across many reuses.
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    status = engine.getHandshakeStatus();
                    break;

                default:
                    // FINISHED or NOT_HANDSHAKING shouldn't reach here (loop condition catches them),
                    // but any other unexpected state is a programming error.
                    throw new IllegalStateException("Unexpected SSL handshake status: " + status);
            }
        }
        // Handshake complete — the SSLEngine is now ready for encrypted application data exchange.
    }

    /**
     * Checks if a pooled connection is still alive and usable.
     *
     * <p><strong>WHY both isOpen() AND isConnected():</strong>
     * <ul>
     *   <li>{@code isOpen()}: Checks if the channel has NOT been explicitly closed.</li>
     *   <li>{@code isConnected()}: Checks if the TCP connection is established and active.</li>
     * </ul>
     * A channel can be "open" but "not connected" (e.g., during the opening phase before connect()).
     * We need both conditions to be true for the connection to be usable.
     *
     * <p><strong>Limitation:</strong>
     * These checks verify the LOCAL socket state. A socket can appear "connected" locally even
     * if the remote server has crashed (TCP FIN not yet propagated). A true health check would
     * require sending a probe request and waiting for a response.
     *
     * @param pooled The connection to inspect.
     * @return {@code true} if the channel appears healthy, {@code false} if it should be discarded.
     */
    private boolean isChannelHealthy(PooledTLSConnection pooled) {
        return pooled.channel().isOpen() && pooled.channel().isConnected();
    }

    /**
     * Closes a connection's socket and decrements the total allocation counter.
     *
     * <p><strong>WHY decrement the counter in the finally block:</strong>
     * We MUST always decrement the count, even if channel.close() throws an exception.
     * Failing to decrement would permanently reduce the effective pool capacity, eventually
     * causing the pool to hit {@link #maxConnections} and refuse new allocations indefinitely.
     *
     * @param pooled The connection to close permanently.
     */
    private void closeChannelResources(PooledTLSConnection pooled) {
        try {
            if (pooled.channel().isOpen()) {
                pooled.channel().close(); // Release the OS socket file descriptor
            }
        } catch (IOException e) {
            // FINE level: not an error, just a diagnostic note — the socket was likely
            // already closed on the remote side before we tried to close it locally.
            logger.log(Level.FINE, "Exception while releasing channel resources", e);
        } finally {
            // CRITICAL: always decrement, regardless of whether close() succeeded.
            totalAllocatedCount.decrementAndGet();
        }
    }

    /**
     * Forcibly closes ALL connections (both idle and active) and resets the pool to empty.
     *
     * <p><strong>WHY:</strong>
     * Called during graceful server shutdown to ensure all backend sockets are properly closed
     * and no TCP connections are left in TIME_WAIT or CLOSE_WAIT states, which would waste
     * OS resources and potentially block the backend servers' accept queues.
     *
     * <p><strong>HOW:</strong>
     * Drains the idle queue completely, then closes all active connections from the registry.
     * Finally, clears the registry and resets the count to zero.
     */
    public void closeAll() {
        // Close all idle (waiting) connections.
        PooledTLSConnection pooled;
        while ((pooled = idleQueue.poll()) != null) {
            try {
                pooled.channel().close();
            } catch (IOException ignored) {}
        }

        // Close all active (currently leased) connections.
        // NOTE: Callers that are still using these channels may encounter IOExceptions.
        // This should only be called during a controlled shutdown where no new requests are arriving.
        for (PooledTLSConnection active : activeRegistry.values()) {
            try {
                active.channel().close();
            } catch (IOException ignored) {}
        }

        // Clear tracking structures and reset count.
        activeRegistry.clear();
        totalAllocatedCount.set(0);
    }
}