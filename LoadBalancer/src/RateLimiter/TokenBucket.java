package RateLimiter;

import java.util.concurrent.atomic.AtomicReference;

/**
 * A lock-free, high-performance Token Bucket rate limiter.
 *
 * <p><strong>WHY:</strong>
 * In server applications, we must prevent any single client (or an attacker) from sending too many requests
 * too quickly, which could overwhelm the server (a Denial of Service attack). A "Token Bucket" is an algorithm
 * that gives each user a "bucket" that holds virtual "tokens". Each request costs one token. If you run out of tokens,
 * your request is blocked.
 *
 * Traditional ways of coding this use "synchronized" blocks or "locks" to prevent multiple threads from interfering
 * with each other. However, locking forces threads to wait in line, slowing down the server. This class uses
 * a "lock-free" approach so threads can safely check and update token counts at extreme speeds without waiting.
 *
 * <p><strong>WHAT:</strong>
 * Represents a single client's virtual bucket. It holds configurations for maximum capacity, how fast it refines tokens,
 * and tracks the current token balance and the last access times.
 *
 * <p><strong>HOW:</strong>
 * It encapsulates the token balance and last refill time inside an immutable {@link State} class. It manages this
 * state using an {@link AtomicReference}. Instead of locking, it uses a Compare-And-Swap (CAS) loop: it reads the current
 * state, calculates the new tokens based on elapsed time, subtracts one token if allowed, and tries to save this new state.
 * If another thread updated the state first, the CAS check fails, and the loop safely retries with the fresh state.
 */
public class TokenBucket {

    /**
     * An immutable snapshot of the bucket's dynamic state.
     *
     * <p><strong>WHY:</strong>
     * To make our bucket thread-safe without locks, we need to update the token count and the timestamp together.
     * If we updated them as separate variables, one thread might update the token count and another update the timestamp
     * at the same time, corrupting the values.
     *
     * <p><strong>WHAT:</strong>
     * A simple data holder (State) that bundles the token count and the last refill timestamp together.
     *
     * <p><strong>HOW:</strong>
     * It declared final variables for the double token count and long timestamp. Because it is immutable,
     * its values can never change once created. To change the state, we must construct a brand new State object
     * and swap it atomically.
     */
    private static class State {
        final double tokens;
        final long lastRefillTimestampNanos;

        State(double tokens, long lastRefillTimestampNanos) {
            this.tokens = tokens;
            this.lastRefillTimestampNanos = lastRefillTimestampNanos;
        }
    }

    private final double capacity;
    private final double refillRatePerSecond;
    
    // The reference to the current State (tokens + timestamp) which we can swap atomically.
    private final AtomicReference<State> state;
    
    // Keeps track of when any request (allowed or blocked) last checked this bucket.
    // This is used to evict inactive buckets from memory.
    private volatile long lastAccessTimestampNanos;

    /**
     * Configures and creates a new Token Bucket.
     *
     * <p><strong>WHY:</strong>
     * We need to establish the limits (capacity) and the recovery rate (refill rate) for a client connection
     * when their bucket is initialized.
     *
     * <p><strong>WHAT:</strong>
     * Initializes the maximum capacity, refill rate, and sets the initial state to a full bucket.
     *
     * <p><strong>HOW:</strong>
     * Assigns the constants and initializes the {@link AtomicReference} with a new {@link State} containing
     * full tokens and the current system nano-time.
     *
     * @param capacity             The maximum number of tokens the bucket can hold (e.g., 10 requests).
     * @param refillRatePerSecond  How many tokens are added back to the bucket each second (e.g., 2 tokens/sec).
     */
    public TokenBucket(double capacity, double refillRatePerSecond) {
        this.capacity = capacity;
        this.refillRatePerSecond = refillRatePerSecond;
        long now = System.nanoTime();
        this.state = new AtomicReference<>(new State(capacity, now));
        this.lastAccessTimestampNanos = now;
    }

    /**
     * Evaluates if a request should be allowed and consumes a token if yes.
     *
     * <p><strong>WHY:</strong>
     * When a client sends a request, we must check if they have at least 1.0 token, deduct it, and let them through,
     * or block them if they have none. This check-and-act sequence must be completely thread-safe.
     *
     * <p><strong>WHAT:</strong>
     * Returns true and deducts 1.0 token if allowed. Returns false immediately if tokens are insufficient.
     *
     * <p><strong>HOW:</strong>
     * 1. Updates the last access timestamp to the current time.
     * 2. Enters an infinite `while(true)` loop to perform Compare-And-Swap (CAS):
     *    a. Reads the current {@link State} (token count and timestamp).
     *    b. Calculates elapsed time in nanoseconds since that timestamp.
     *    c. Computes refilled tokens: `currentTokens + (elapsedSeconds * refillRate)`.
     *    d. Caps the tokens at `capacity`.
     *    e. If tokens are less than 1.0, returns false (no modifications made).
     *    f. If tokens are >= 1.0, creates a new {@code State} with `tokens - 1.0` and the current timestamp.
     *    g. Attempts to swap the old state with the new state using `compareAndSet()`.
     *    h. If `compareAndSet` succeeds, returns true. If it fails (another thread changed the state first),
     *       the loop runs again with the new current state.
     */
    public boolean allowRequest() {
        long now = System.nanoTime();
        this.lastAccessTimestampNanos = now; // Update access mark for the eviction engine

        while (true) {
            State current = state.get();
            long elapsedNanos = now - current.lastRefillTimestampNanos;
            
            // Protect against time anomalies or CPU adjustments
            if (elapsedNanos < 0) {
                elapsedNanos = 0;
            }

            // Convert nanoseconds to seconds for fractional token calculation
            double elapsedSeconds = elapsedNanos / 1_000_000_000.0;
            
            // Calculate refilled tokens based on the time delta
            double refilled = current.tokens + (elapsedSeconds * refillRatePerSecond);
            
            // Cap the accumulated tokens to the bucket's maximum capacity
            double currentTokens = Math.min(capacity, refilled);

            // If client has less than 1 token, deny the request immediately
            if (currentTokens < 1.0) {
                return false;
            }

            // Deduct 1.0 token for this request and update the timestamp to now
            State next = new State(currentTokens - 1.0, now);
            
            // Try to swap the state atomically. If no other thread changed it in the meantime,
            // compareAndSet returns true. If it returns false, loop and try again.
            if (state.compareAndSet(current, next)) {
                return true;
            }
        }
    }

    /**
     * Retrieves the last system nano-time this bucket was accessed.
     *
     * <p><strong>WHY:</strong>
     * The cleaning manager needs to know how long a client has been silent to decide whether to delete their bucket
     * and free up memory.
     *
     * <p><strong>WHAT:</strong>
     * Returns the raw `lastAccessTimestampNanos` timestamp.
     *
     * <p><strong>HOW:</strong>
     * Reads and returns the volatile long value. Volatile ensures that any thread reading this value gets
     * the most up-to-date write from any other thread.
     */
    public long getLastAccessTimestamp() {
        return lastAccessTimestampNanos;
    }

    /**
     * Inspects the current tokens in the bucket, accounting for lazy refills.
     *
     * <p><strong>WHY:</strong>
     * Used for debugging, logging, or testing to view the exact token balance at any given millisecond.
     *
     * <p><strong>WHAT:</strong>
     * Calculates and returns the current token count.
     *
     * <p><strong>HOW:</strong>
     * Reads the current state, computes the time elapsed from that state's timestamp to the current system nano-time,
     * adds the refilled tokens, caps it at capacity, and returns the double value.
     */
    public double getCurrentTokens() {
        State current = state.get();
        long elapsedNanos = System.nanoTime() - current.lastRefillTimestampNanos;
        if (elapsedNanos < 0) elapsedNanos = 0;
        double elapsedSeconds = elapsedNanos / 1_000_000_000.0;
        return Math.min(capacity, current.tokens + (elapsedSeconds * refillRatePerSecond));
    }
}
