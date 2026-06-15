package RateLimiter;

// ─────────────────────────────────────────────────────────────────────────────
// WHY we import ConcurrentHashMap:
//   A normal java.util.HashMap is NOT safe to use when multiple threads
//   (i.e., multiple incoming requests) access it at the same time. One thread
//   could be inserting a new client bucket while another thread is reading,
//   causing a corrupted internal state (null pointer exceptions, infinite loops).
//   ConcurrentHashMap is a thread-safe version of HashMap that uses fine-grained
//   internal locking (per-bucket locking, not the whole map), making concurrent
//   reads and writes safe AND fast.
// ─────────────────────────────────────────────────────────────────────────────
import java.util.concurrent.ConcurrentHashMap;

// ─────────────────────────────────────────────────────────────────────────────
// WHY we import ScheduledExecutorService / Executors / TimeUnit:
//   We need a background cleanup task that runs automatically every N minutes.
//   Java's ScheduledExecutorService is a thread pool specifically designed to
//   run tasks at a fixed rate or after a fixed delay, much like a cron job.
//   Using a dedicated thread pool (via Executors.newSingleThreadScheduledExecutor)
//   prevents the cleanup from accidentally blocking any request-handling threads.
// ─────────────────────────────────────────────────────────────────────────────
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Registry, supervisor, and lifecycle manager for all per-client {@link TokenBucket} instances.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER CONTEXT — Why do we need a "Manager"?
 * ═══════════════════════════════════════════════════════════════════
 * The {@link TokenBucket} class handles rate limiting for ONE client.
 * But a real server handles THOUSANDS of different clients, each identified
 * by a unique IP address. We need something that:
 *
 *   1. Maintains a lookup table: "IP address → its bucket"
 *   2. Automatically creates a NEW bucket the first time an IP is seen.
 *   3. Provides a single, simple method the server can call: "Is this IP allowed?"
 *   4. Cleans up old buckets to prevent a memory leak attack where an attacker
 *      sends requests from millions of fake IPs, each creating a bucket.
 *
 * The RateLimiterManager does all four of these things.
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * Rate limiting must be tracked INDIVIDUALLY for each client IP address.
 * A single global bucket would let one greedy user starve all others.
 * Additionally, storing buckets forever is a memory leak risk — a malicious
 * attacker could generate millions of spoofed IP addresses, each creating a
 * new bucket entry, eventually exhausting all server RAM (a memory-exhaustion
 * Denial of Service attack). This manager solves both problems.
 *
 * <p><strong>WHAT this class does:</strong>
 * <ul>
 *   <li>Maintains a {@link ConcurrentHashMap} mapping each client IP → its {@link TokenBucket}.</li>
 *   <li>Exposes {@link #allowRequest(String)} — the single entry point for checking a request.</li>
 *   <li>Runs a background eviction thread that periodically removes inactive buckets.</li>
 *   <li>Provides {@link #shutdown()} to cleanly stop background threads on server termination.</li>
 * </ul>
 *
 * <p><strong>HOW it works at a high level:</strong>
 * <ol>
 *   <li>The main server calls {@code allowRequest("192.168.1.5")} for every incoming request.</li>
 *   <li>The manager looks up the IP in the map. If not found, it atomically creates a new bucket.</li>
 *   <li>It delegates to {@link TokenBucket#allowRequest()} and returns the boolean result.</li>
 *   <li>Every minute, a background daemon thread wakes up, scans the entire map, and removes
 *       any bucket whose last access time is older than the configured TTL.</li>
 * </ol>
 */
public class RateLimiterManager {

    // ─────────────────────────────────────────────────────────────────────────
    // FIELDS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The central registry mapping client IP address strings → their {@link TokenBucket}.
     *
     * WHY ConcurrentHashMap specifically:
     *   - Thread-safe: multiple request handler threads can read/write it concurrently.
     *   - computeIfAbsent() is atomic: if two threads send requests from the same NEW IP
     *     at the exact same millisecond, ConcurrentHashMap guarantees only ONE bucket
     *     is created (not two), and both threads see the same bucket.
     *   - No global lock: reads on different keys proceed in parallel, so high-traffic
     *     servers don't bottleneck on a single lock while looking up different clients.
     */
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    // The maximum number of tokens a new client bucket starts with and can accumulate.
    // This value is shared by ALL buckets created by this manager.
    private final double bucketCapacity;

    // How many tokens per second are added back to each client's bucket.
    // Controls the long-term sustained request rate for every client.
    private final double refillRatePerSecond;

    /**
     * Time-To-Live expressed in nanoseconds.
     *
     * WHY nanoseconds (not minutes):
     *   System.nanoTime() returns nanoseconds. Converting the TTL to nanoseconds once
     *   here means the eviction loop can do a simple subtraction and comparison without
     *   any unit conversion on every iteration, making it marginally faster.
     *
     * WHY long (not int or double):
     *   A minute in nanoseconds = 60 * 1,000,000,000 = 60,000,000,000. This exceeds
     *   the maximum value of int (about 2.1 billion), so we MUST use a long here.
     */
    private final long ttlNanos;

    /**
     * The single background thread that runs the eviction scan on a schedule.
     *
     * WHY ScheduledExecutorService instead of a raw Thread with Thread.sleep():
     *   ScheduledExecutorService is more robust — it handles exceptions gracefully
     *   (a crash in one iteration doesn't kill the scheduler), manages thread lifecycle,
     *   and provides clean shutdown APIs. A raw {@code while(true) { sleep(); cleanup(); }}
     *   loop is fragile and harder to stop cleanly.
     */
    private final ScheduledExecutorService cleanupScheduler;

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initializes the RateLimiterManager with rate-limiting and eviction parameters,
     * then immediately starts the background cleanup thread.
     *
     * <p><strong>WHY the constructor starts the cleaner:</strong>
     * The eviction process should begin as soon as the manager is created. If we
     * forgot to call a separate "start()" method, buckets would accumulate forever.
     * By starting the scheduler in the constructor, the caller cannot forget.
     *
     * <p><strong>WHAT:</strong>
     * Stores the configuration constants, converts TTL minutes to nanoseconds,
     * creates a single-thread scheduled executor with a named daemon thread,
     * and schedules the eviction task to run every 1 minute with an initial
     * 1-minute delay (so the first cleanup happens 1 minute after startup).
     *
     * <p><strong>HOW — the "daemon thread" detail:</strong>
     * When the JVM tries to shut down, it waits for all non-daemon threads to finish.
     * If our eviction thread were non-daemon, it would BLOCK server shutdown forever
     * (since it runs in an infinite loop). Marking it as {@code daemon = true} tells
     * the JVM: "This thread is a background helper — kill it when the main program exits."
     *
     * @param bucketCapacity       Maximum tokens per individual client bucket.
     *                             Example: {@code 10} → burst limit of 10 requests.
     * @param refillRatePerSecond  Token refill speed per client bucket per second.
     *                             Example: {@code 2.0} → steady-state 2 requests/second.
     * @param ttlMinutes           Minutes of inactivity before a client's bucket is evicted.
     *                             Example: {@code 5} → buckets inactive for 5 min are deleted.
     */
    public RateLimiterManager(double bucketCapacity, double refillRatePerSecond, long ttlMinutes) {
        // Store the rate limiting parameters for use when creating new TokenBuckets.
        this.bucketCapacity = bucketCapacity;
        this.refillRatePerSecond = refillRatePerSecond;

        // Convert TTL from minutes → nanoseconds for direct comparison with System.nanoTime().
        // Formula: minutes * 60 seconds/minute * 1,000,000,000 nanoseconds/second.
        // The L suffix on the literal forces the multiplication to happen in long arithmetic,
        // preventing integer overflow (60 * 1,000,000,000 overflows a 32-bit int).
        this.ttlNanos = ttlMinutes * 60 * 1_000_000_000L;

        // ── Create the background eviction scheduler ──
        // newSingleThreadScheduledExecutor accepts a ThreadFactory — a function that
        // creates the actual OS thread. We provide a lambda that:
        //   1. Creates a new Thread with our target task (the eviction Runnable).
        //   2. Gives it a human-readable name "rate-limiter-eviction" (visible in stack traces).
        //   3. Marks it as a DAEMON thread so it does not block JVM shutdown.
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "rate-limiter-eviction"); // Named for easy debugging
            thread.setDaemon(true); // Background daemon: JVM can shut down without waiting for this thread
            return thread;
        });

        // ── Schedule the eviction task ──
        // scheduleAtFixedRate(task, initialDelay, period, unit):
        //   - task:         this::evictExpiredBuckets → the method reference to run
        //   - initialDelay: 1 minute → wait 1 minute after startup before first run
        //   - period:       1 minute → run every 1 minute thereafter
        //   - unit:         TimeUnit.MINUTES
        // If evictExpiredBuckets() takes longer than 1 minute, the next run is skipped
        // (not queued), preventing overlapping cleanup tasks.
        this.cleanupScheduler.scheduleAtFixedRate(this::evictExpiredBuckets, 1, 1, TimeUnit.MINUTES);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The primary entry point — checks whether the given client IP is allowed to make a request.
     *
     * <p><strong>WHY this is the only public method the server needs to call:</strong>
     * The main server loop should not care about bucket creation, eviction, or thread safety
     * internals. It should just ask one simple question: "Is this IP allowed right now?"
     * This method hides all complexity behind a single, clean boolean contract.
     *
     * <p><strong>WHAT:</strong>
     * Returns {@code true} if the client IP has at least 1 token available (and consumes it).
     * Returns {@code false} if the client is rate-limited (throttled).
     * Also returns {@code false} immediately for null or blank IPs.
     *
     * <p><strong>HOW — the key detail is {@code computeIfAbsent}:</strong>
     * {@link ConcurrentHashMap#computeIfAbsent(Object, java.util.function.Function)} is an
     * atomic operation: it checks if the key exists, and if not, runs the provided factory
     * function and stores the result — ALL IN ONE UNINTERRUPTIBLE STEP. This guarantees that
     * even if 100 threads simultaneously make the first-ever request from the same new IP,
     * exactly ONE bucket is created and all 100 threads see the same bucket.
     * A naive {@code if (!buckets.contains(ip)) buckets.put(ip, new TokenBucket(...))} would
     * have a race window where two threads both pass the if-check and create two separate buckets.
     *
     * @param clientIP The IP address string of the incoming client (e.g., "203.0.113.42").
     * @return {@code true} if the request is allowed, {@code false} if throttled.
     */
    public boolean allowRequest(String clientIP) {
        // ── Guard: Reject null or empty IPs immediately ──
        // A blank IP is almost certainly an internal error (misconfigured proxy, direct socket).
        // We cannot meaningfully track rate limits for an unknown IP, so we reject it.
        if (clientIP == null || clientIP.isBlank()) {
            return false;
        }

        // ── Look up or atomically create the client's bucket ──
        // computeIfAbsent(key, mappingFunction):
        //   • If `clientIP` is already in the map → returns the existing TokenBucket.
        //   • If NOT in the map → calls the lambda `ip -> new TokenBucket(bucketCapacity, refillRatePerSecond)`,
        //     stores the result under `clientIP`, and returns the new TokenBucket.
        //   • ATOMIC: this entire check-and-create happens as a single thread-safe operation.
        TokenBucket bucket = buckets.computeIfAbsent(clientIP,
            ip -> new TokenBucket(bucketCapacity, refillRatePerSecond)
        );

        // ── Delegate the actual token check to the bucket ──
        // The TokenBucket.allowRequest() method handles the thread-safe CAS logic internally.
        return bucket.allowRequest();
    }

    /**
     * Background maintenance task — scans and removes buckets inactive longer than the TTL.
     *
     * <p><strong>WHY this is CRITICAL for production safety:</strong>
     * Without this cleanup, every unique IP that ever connected would leave a permanent entry
     * in the {@code buckets} map. A network scanner running for 24 hours with randomized IPs
     * could create millions of entries, exhausting server heap memory and causing an
     * {@link OutOfMemoryError}. The eviction mechanism bounds the map's maximum size over time.
     *
     * <p><strong>WHAT:</strong>
     * Scans every entry in the {@code buckets} map and removes any whose last access timestamp
     * is older than {@code ttlNanos} nanoseconds from now.
     *
     * <p><strong>HOW — using {@code entrySet().removeIf()}:</strong>
     * {@link ConcurrentHashMap} makes its {@code entrySet().removeIf()} thread-safe:
     * it acquires per-segment locks internally, so we can safely remove entries while
     * other threads may be simultaneously reading/writing other entries. We do NOT need
     * to lock the entire map. The predicate lambda receives each Entry and returns {@code true}
     * to remove it, or {@code false} to keep it.
     *
     * <p><strong>Time comparison:</strong>
     * {@code System.nanoTime() - bucket.getLastAccessTimestamp()} gives the age of the bucket
     * in nanoseconds. We compare this against {@code ttlNanos}. If the age exceeds the TTL,
     * the bucket is considered "expired" and is removed.
     *
     * <p>This method is {@code private} because it should ONLY be called by the internal
     * scheduler — never directly by external code.
     */
    private void evictExpiredBuckets() {
        // Capture "now" ONCE before the loop so all age calculations use a consistent baseline.
        // (System.nanoTime() is very cheap but calling it millions of times in a loop is wasteful.)
        long now = System.nanoTime();

        // Iterate over every (IP, bucket) entry in the map.
        // The removeIf() lambda returns true to delete the entry, false to keep it.
        buckets.entrySet().removeIf(entry -> {
            TokenBucket bucket = entry.getValue();

            // Calculate how many nanoseconds have passed since this bucket was last accessed.
            long idleAgeNanos = now - bucket.getLastAccessTimestamp();

            // If the client has been idle longer than our TTL threshold, evict their bucket.
            // This comparison is in nanoseconds, matching the unit of ttlNanos.
            return idleAgeNanos > ttlNanos;
        });
    }

    /**
     * Gracefully shuts down the background eviction thread pool.
     *
     * <p><strong>WHY this must be called on server shutdown:</strong>
     * Although the eviction thread is a daemon thread (and will be killed when the JVM
     * exits anyway), explicitly shutting it down is considered good practice. It ensures
     * any in-progress eviction task completes before we exit, and it releases the thread's
     * OS resources immediately rather than waiting for GC. In environments with complex
     * lifecycle management (e.g., application containers, test frameworks), this prevents
     * "thread leaked" warnings.
     *
     * <p><strong>WHAT:</strong>
     * Instructs the scheduled executor to stop accepting new tasks and wait for any
     * currently-running task to finish, with a 5-second grace period.
     *
     * <p><strong>HOW — two-phase shutdown:</strong>
     * <ol>
     *   <li>{@code shutdown()} → "Stop scheduling new eviction tasks. Finish the current one."</li>
     *   <li>{@code awaitTermination(5, SECONDS)} → Block for up to 5 seconds waiting for completion.</li>
     *   <li>If still not done after 5 seconds → {@code shutdownNow()} forcibly interrupts
     *       the thread (sends it an interrupt signal) so it stops immediately.</li>
     *   <li>If THIS thread is itself interrupted while waiting → re-interrupt it with
     *       {@code Thread.currentThread().interrupt()} to preserve the interrupt signal
     *       for higher-level callers (this is a Java best practice for interrupt handling).</li>
     * </ol>
     */
    public void shutdown() {
        // Phase 1: Orderly shutdown — no more new tasks, but let the current one finish.
        cleanupScheduler.shutdown();

        try {
            // Phase 2: Wait up to 5 seconds for a graceful finish.
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                // Phase 3: Timeout — force-stop the thread immediately.
                cleanupScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            // If this calling thread was interrupted while waiting, force-stop the scheduler
            // and re-interrupt ourselves so the interrupt signal is not swallowed.
            cleanupScheduler.shutdownNow();
            Thread.currentThread().interrupt(); // Preserve interrupt status for the caller
        }
    }

    /**
     * Returns the number of client IP addresses currently tracked in memory.
     *
     * <p><strong>WHY:</strong>
     * Primarily used for unit tests to verify that eviction actually removes entries,
     * and for operational monitoring/dashboards to observe memory usage trends.
     * If this number grows without bound, it signals that the eviction TTL may be
     * too large or the cleanup task is not running correctly.
     *
     * <p><strong>WHAT:</strong>
     * Returns the current size of the {@code buckets} ConcurrentHashMap.
     *
     * <p><strong>HOW:</strong>
     * Calls {@link ConcurrentHashMap#size()} which returns an approximate count.
     * (In ConcurrentHashMap, the count may be momentarily inaccurate due to
     * concurrent modifications, but is accurate enough for monitoring purposes.)
     *
     * @return The number of tracked client buckets currently in memory.
     */
    public int getRegistrySize() {
        return buckets.size();
    }
}
