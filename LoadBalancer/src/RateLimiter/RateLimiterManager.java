package RateLimiter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Registry and supervisor for client-specific token buckets.
 *
 * <p><strong>WHY:</strong>
 * Rate limiting must be tracked individually for each client (by their IP address). If we used a single global
 * bucket for the entire server, one aggressive user would consume all tokens, blocking all other customers.
 *
 * Additionally, if we keep adding client buckets to memory, a malicious user could spoof millions of fake IP addresses,
 * creating millions of empty buckets and running our server out of memory (a Denial of Service attack). We need a manager
 * that stores these buckets and actively cleans up inactive ones.
 *
 * <p><strong>WHAT:</strong>
 * Manages the mapping of IP addresses to {@link TokenBucket} objects, handles checking incoming requests, and runs
 * a background task to evict inactive buckets from memory.
 *
 * <p><strong>HOW:</strong>
 * It stores buckets inside a thread-safe {@link ConcurrentHashMap}. It spawns a background thread that runs
 * a periodic clean-up loop. This loop inspects the last access time of all buckets and removes any that have been
 * silent for longer than the configured Time-To-Live (TTL).
 */
public class RateLimiterManager {

    // A thread-safe Map storing client IP addresses mapped to their respective TokenBuckets.
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    
    private final double bucketCapacity;
    private final double refillRatePerSecond;
    private final long ttlNanos;
    
    // A single background thread scheduled to run the clean-up task at fixed intervals.
    private final ScheduledExecutorService cleanupScheduler;

    /**
     * Initializes the supervisor manager with rate limiting and cleanup parameters.
     *
     * <p><strong>WHY:</strong>
     * We need to establish the baseline rate limits (capacity, refill rate) that apply to all new client buckets,
     * configure how long an inactive bucket remains in memory (TTL), and start the clean-up worker.
     *
     * <p><strong>WHAT:</strong>
     * Saves the configuration parameters, sets the TTL, and starts a background thread that runs every minute.
     *
     * <p><strong>HOW:</strong>
     * 1. Stores capacity, refill rate, and converts TTL minutes into nanoseconds.
     * 2. Spawns a single-threaded {@link ScheduledExecutorService}. It configures the thread as a "daemon" thread,
     *    which means Java can shut down the program without waiting for this background thread to finish.
     * 3. Configures the executor to run the `evictExpiredBuckets()` method every 1 minute.
     *
     * @param bucketCapacity       Maximum tokens per bucket.
     * @param refillRatePerSecond  Refill speed per bucket.
     * @param ttlMinutes           Inactive time before eviction.
     */
    public RateLimiterManager(double bucketCapacity, double refillRatePerSecond, long ttlMinutes) {
        this.bucketCapacity = bucketCapacity;
        this.refillRatePerSecond = refillRatePerSecond;
        this.ttlNanos = ttlMinutes * 60 * 1_000_000_000L;

        // Active eviction scheduler
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "rate-limiter-eviction");
            thread.setDaemon(true); // Allow JVM to shutdown cleanly
            return thread;
        });

        // Run cleanup every minute
        this.cleanupScheduler.scheduleAtFixedRate(this::evictExpiredBuckets, 1, 1, TimeUnit.MINUTES);
    }

    /**
     * Primary entry point to check if a client request should be allowed or blocked.
     *
     * <p><strong>WHY:</strong>
     * The Layer 7 proxy server needs a simple, fast, and thread-safe method to query whether
     * a client's IP address has exceeded its request limits.
     *
     * <p><strong>WHAT:</strong>
     * Returns true if the client IP has enough tokens and consumes one token. Returns false if throttled.
     *
     * <p><strong>HOW:</strong>
     * 1. Rejects blank or null IPs immediately.
     * 2. Looks up the IP in the `buckets` ConcurrentHashMap. If the IP is not in the map, it constructs
     *    a new `TokenBucket` atomically using `computeIfAbsent()`. This prevents two threads from accidentally
     *    creating two separate buckets for the same IP.
     * 3. Calls `allowRequest()` on that specific bucket and returns the result.
     */
    public boolean allowRequest(String clientIP) {
        if (clientIP == null || clientIP.isBlank()) {
            return false;
        }

        // Get existing bucket or create a new one atomically
        TokenBucket bucket = buckets.computeIfAbsent(clientIP, 
            ip -> new TokenBucket(bucketCapacity, refillRatePerSecond)
        );

        return bucket.allowRequest();
    }

    /**
     * Scans and deletes expired client buckets from memory.
     *
     * <p><strong>WHY:</strong>
     * Over time, thousands of transient client IPs will connect and disconnect. If we keep their buckets
     * in memory forever, the server will eventually run out of RAM (memory leak).
     *
     * <p><strong>WHAT:</strong>
     * Evicts any bucket from the map if it has been inactive for longer than the TTL window.
     *
     * <p><strong>HOW:</strong>
     * It uses the thread-safe `entrySet().removeIf()` method on the map. For each entry, it calculates
     * `System.nanoTime() - bucket.getLastAccessTimestamp()`. If this difference is greater than `ttlNanos`,
     * the entry is removed.
     */
    private void evictExpiredBuckets() {
        long now = System.nanoTime();
        buckets.entrySet().removeIf(entry -> {
            TokenBucket bucket = entry.getValue();
            return (now - bucket.getLastAccessTimestamp()) > ttlNanos;
        });
    }

    /**
     * Shuts down the background clean-up thread pool.
     *
     * <p><strong>WHY:</strong>
     * When the main server stops, we must clean up background threads to prevent resources from leaking
     * or blocking proper shutdown.
     *
     * <p><strong>WHAT:</strong>
     * Shuts down the `cleanupScheduler` executor service.
     *
     * <p><strong>HOW:</strong>
     * Calls `shutdown()` on the scheduler and waits up to 5 seconds for it to stop cleanly.
     * If it doesn't stop, it forces it to terminate using `shutdownNow()`.
     */
    public void shutdown() {
        cleanupScheduler.shutdown();
        try {
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Returns the current number of tracked IP addresses in memory.
     *
     * <p><strong>WHY:</strong>
     * Primarily used for unit testing and system inspection to verify that eviction works and
     * monitor the size of the registry.
     *
     * <p><strong>WHAT:</strong>
     * Returns the total map size.
     *
     * <p><strong>HOW:</strong>
     * Calls and returns `buckets.size()`.
     */
    public int getRegistrySize() {
        return buckets.size();
    }
}
