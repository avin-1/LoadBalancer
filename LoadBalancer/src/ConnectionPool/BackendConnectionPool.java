package ConnectionPool;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * WHY: Establishing a new TLS connection to a backend server for every single client request 
 *      is slow and consumes a lot of CPU/Network resources.
 * 
 * WHAT: This class implements an End-to-End HTTPS "Connection Pool". Instead of closing a connection when done, 
 *       it saves the connection (and its dedicated SSLEngine state) in a queue (`idleQueue`). The next time a request comes in, 
 *       it reuses an existing idle TLS connection rather than making a new one.
 * 
 * HOW: 
 *   - It uses a `LinkedBlockingQueue` to safely hold idle `PooledTLSConnection` objects.
 *   - `leaseConnection()` tries to pop an existing connection from the queue. If empty, it creates a new one (up to `maxConnections`).
 *   - `releaseConnection()` puts the connection back into the queue when the request is finished.
 *   - Contains an inline, non-blocking TLS Handshake loop (`executeClientTLSHandshake`) to establish secure sessions instantly upon socket creation.
 */
public final class BackendConnectionPool {
    private static final Logger logger = Logger.getLogger(BackendConnectionPool.class.getName());

    private final InetSocketAddress remoteAddress;
    private final int maxConnections;
    private final long idleTtlMs;
    private final BlockingQueue<PooledTLSConnection> idleQueue;
    private final ConcurrentHashMap<SocketChannel, PooledTLSConnection> activeRegistry;
    private final AtomicInteger totalAllocatedCount;
    private final SSLContext sslContext;

    public static final class PooledTLSConnection {
        private final SocketChannel channel;
        private final SSLEngine engine;
        private long idleStartTimestamp;

        public PooledTLSConnection(SocketChannel channel, SSLEngine engine) {
            this.channel = channel;
            this.engine = engine;
            this.idleStartTimestamp = System.currentTimeMillis();
        }

        public SocketChannel channel() { return channel; }
        public SSLEngine engine() { return engine; }
        public long idleStartTimestamp() { return idleStartTimestamp; }
        public void updateIdleTimestamp() { this.idleStartTimestamp = System.currentTimeMillis(); }
    }

    public BackendConnectionPool(InetSocketAddress remoteAddress, int maxConnections, long idleTtlMs) {
        this.remoteAddress = Objects.requireNonNull(remoteAddress);
        this.maxConnections = maxConnections;
        this.idleTtlMs = idleTtlMs;
        this.idleQueue = new LinkedBlockingQueue<>();
        this.activeRegistry = new ConcurrentHashMap<>();
        this.totalAllocatedCount = new AtomicInteger(0);

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

    public SocketChannel leaseConnection(long timeoutMs) throws TimeoutException, InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (true) {
            PooledTLSConnection pooled = idleQueue.poll();
            if (pooled != null) {
                if (isChannelHealthy(pooled)) {
                    activeRegistry.put(pooled.channel(), pooled);
                    return pooled.channel();
                } else {
                    closeChannelResources(pooled);
                    continue;
                }
            }

            int currentCount = totalAllocatedCount.get();
            if (currentCount < maxConnections) {
                if (totalAllocatedCount.compareAndSet(currentCount, currentCount + 1)) {
                    try {
                        PooledTLSConnection newConn = createNewChannel();
                        activeRegistry.put(newConn.channel(), newConn);
                        return newConn.channel();
                    } catch (Exception e) {
                        totalAllocatedCount.decrementAndGet();
                        logger.log(Level.WARNING, "Failed to instantiate on-demand TLS backend channel", e);
                    }
                }
                continue;
            }

            long remainingWait = deadline - System.currentTimeMillis();
            if (remainingWait <= 0) {
                throw new TimeoutException("Pool capacity exhausted.");
            }

            pooled = idleQueue.poll(remainingWait, TimeUnit.MILLISECONDS);
            if (pooled == null) {
                throw new TimeoutException("Pool capacity exhausted.");
            }

            if (isChannelHealthy(pooled)) {
                activeRegistry.put(pooled.channel(), pooled);
                return pooled.channel();
            } else {
                closeChannelResources(pooled);
            }
        }
    }

    /**
     * Retrieves the associated PooledTLSConnection (containing the SSLEngine) for a leased SocketChannel.
     */
    public PooledTLSConnection getTLSConnection(SocketChannel channel) {
        return activeRegistry.get(channel);
    }

    public void releaseConnection(SocketChannel channel, boolean keepAlive) {
        if (channel == null) return;
        
        PooledTLSConnection pooled = activeRegistry.remove(channel);
        if (pooled == null) {
            // Unregistered channel, just close it
            try { channel.close(); } catch (IOException ignored) {}
            return;
        }

        if (keepAlive && isChannelHealthy(pooled)) {
            pooled.updateIdleTimestamp();
            if (!idleQueue.offer(pooled)) {
                closeChannelResources(pooled);
            }
        } else {
            closeChannelResources(pooled);
        }
    }

    public void evictExpired() {
        int queueSize = idleQueue.size();
        long now = System.currentTimeMillis();
        for (int i = 0; i < queueSize; i++) {
            PooledTLSConnection pooled = idleQueue.poll();
            if (pooled == null) break;

            long idleTime = now - pooled.idleStartTimestamp();
            if (idleTime > idleTtlMs || !isChannelHealthy(pooled)) {
                closeChannelResources(pooled);
            } else {
                idleQueue.offer(pooled);
            }
        }
    }

    private PooledTLSConnection createNewChannel() throws IOException {
        SocketChannel channel = SocketChannel.open();
        // Connect synchronously first to ensure it's fully connected
        channel.connect(remoteAddress);
        channel.configureBlocking(false);

        SSLEngine engine = sslContext.createSSLEngine(remoteAddress.getHostString(), remoteAddress.getPort());
        engine.setUseClientMode(true);

        executeClientTLSHandshake(channel, engine);

        return new PooledTLSConnection(channel, engine);
    }

    private void executeClientTLSHandshake(SocketChannel channel, SSLEngine engine) throws IOException {
        engine.beginHandshake();

        ByteBuffer myNetData = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteBuffer peerNetData = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteBuffer dummyAppData = ByteBuffer.allocate(0); // Client does not send app data during handshake
        ByteBuffer peerAppData = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());

        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        while (status != SSLEngineResult.HandshakeStatus.FINISHED && status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (status) {
                case NEED_UNWRAP:
                    int bytesRead = channel.read(peerNetData);
                    if (bytesRead < 0) {
                        throw new SSLException("Channel closed during handshake.");
                    } else if (bytesRead == 0) {
                        // Non-blocking read might return 0 bytes if data hasn't arrived.
                        try { Thread.sleep(5); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                        continue; // try reading again
                    }
                    peerNetData.flip();
                    SSLEngineResult res = engine.unwrap(peerNetData, peerAppData);
                    peerNetData.compact();
                    status = res.getHandshakeStatus();
                    
                    if (res.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        ByteBuffer newPeerAppData = ByteBuffer.allocate(peerAppData.capacity() * 2);
                        peerAppData.flip();
                        newPeerAppData.put(peerAppData);
                        peerAppData = newPeerAppData;
                    }
                    break;
                case NEED_WRAP:
                    myNetData.clear();
                    res = engine.wrap(dummyAppData, myNetData);
                    status = res.getHandshakeStatus();
                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        channel.write(myNetData);
                    }
                    break;
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    status = engine.getHandshakeStatus();
                    break;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + status);
            }
        }
    }

    private boolean isChannelHealthy(PooledTLSConnection pooled) {
        return pooled.channel().isOpen() && pooled.channel().isConnected();
    }

    private void closeChannelResources(PooledTLSConnection pooled) {
        try {
            if (pooled.channel().isOpen()) {
                pooled.channel().close();
            }
        } catch (IOException e) {
            logger.log(Level.FINE, "Exception while releasing channel resources", e);
        } finally {
            totalAllocatedCount.decrementAndGet();
        }
    }

    public void closeAll() {
        PooledTLSConnection pooled;
        while ((pooled = idleQueue.poll()) != null) {
            try {
                pooled.channel().close();
            } catch (IOException ignored) {
            }
        }
        for (PooledTLSConnection active : activeRegistry.values()) {
            try {
                active.channel().close();
            } catch (IOException ignored) {
            }
        }
        activeRegistry.clear();
        totalAllocatedCount.set(0);
    }
}