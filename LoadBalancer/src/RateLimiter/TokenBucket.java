package RateLimiter;

// ─────────────────────────────────────────────────────────────────────────────
// WHY we need AtomicReference:
//   In a server, many requests can arrive at the exact same millisecond from
//   many different threads. If two threads both try to deduct a token from the
//   bucket at the same time without any safety mechanism, they would both read
//   the same token count (say, 5 tokens), both decide to deduct 1, and both
//   write back 4 — effectively only deducting 1 token instead of 2. This is
//   called a "race condition" and it's a silent, dangerous bug.
//
//   AtomicReference is a special Java container that lets us swap an entire
//   object in one single, uninterruptible CPU instruction (called Compare-And-
//   Swap, or CAS). We use it here to swap the bucket's State object safely
//   without traditional thread locks (synchronized blocks).
// ─────────────────────────────────────────────────────────────────────────────
import java.util.concurrent.atomic.AtomicReference;

/**
 * A lock-free, high-performance Token Bucket rate limiter for a single client.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER PRIMER — What is a Token Bucket?
 * ═══════════════════════════════════════════════════════════════════
 * Imagine a physical bucket that can hold at most 10 coins (tokens).
 *   • Every second, the server drops 2 new coins into your bucket (refill).
 *   • Each time you make a request, 1 coin is taken OUT of the bucket.
 *   • If your bucket is empty (0 coins), your request is REJECTED until
 *     the bucket refills enough for you to make another request.
 *   • The bucket can never hold more than its maximum capacity (10 coins),
 *     so saving up unused tokens is bounded.
 *
 * This allows bursts of traffic (10 requests instantly if the bucket is full)
 * while enforcing a long-term average rate (no more than 2 req/second over time).
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * In server applications, we must prevent any single client (or an attacker)
 * from sending too many requests too quickly, which could overwhelm the server
 * (a Denial of Service / DoS attack). Traditional Java approaches use
 * {@code synchronized} blocks or {@link java.util.concurrent.locks.Lock} objects
 * to prevent concurrent data corruption, but locking forces threads to queue up
 * and wait, adding latency. This class uses a completely lock-free design so
 * multiple threads can safely interact with the same bucket at extreme speed.
 *
 * <p><strong>WHAT this class does:</strong>
 * Represents a single client's virtual "token bucket". It holds:
 * <ul>
 *   <li>The maximum capacity (max tokens allowed to accumulate).</li>
 *   <li>The refill rate (how many tokens are added back per second).</li>
 *   <li>The current dynamic state (current token count + last refill time).</li>
 *   <li>The last access timestamp (so the manager can evict inactive buckets).</li>
 * </ul>
 *
 * <p><strong>HOW the lock-free mechanism works (Compare-And-Swap loop):</strong>
 * <ol>
 *   <li>Read the current immutable {@link State} snapshot from an {@link AtomicReference}.</li>
 *   <li>Calculate how many tokens have refilled since the last access.</li>
 *   <li>If tokens are insufficient, return {@code false} immediately without modifying anything.</li>
 *   <li>If sufficient, create a brand new {@link State} with one fewer token and the current timestamp.</li>
 *   <li>Attempt to atomically swap the old State for the new one using {@code compareAndSet()}.
 *       If another thread changed the State between our read and our write, the swap FAILS,
 *       and we loop back to step 1 to retry with the freshly updated State.</li>
 *   <li>If the swap succeeds, the request is allowed and we return {@code true}.</li>
 * </ol>
 */
public class TokenBucket {

    // ─────────────────────────────────────────────────────────────────────────
    // INNER CLASS: State
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * An immutable snapshot bundling the two values that must change together atomically.
     *
     * <p><strong>WHY we bundle tokens + timestamp into one object:</strong>
     * The token count and the timestamp are logically coupled — you cannot
     * correctly calculate the new token count without knowing the exact time
     * the last count was recorded. If we stored them as two separate
     * {@code AtomicLong} fields, we could never update both in one atomic step.
     * A thread could read the old token count and the new timestamp, producing
     * a completely wrong intermediate value. By wrapping both values inside
     * one immutable object and swapping the entire object atomically via
     * {@link AtomicReference#compareAndSet}, we guarantee they are always
     * consistent — no locks needed.
     *
     * <p><strong>WHAT:</strong>
     * A simple, read-only data holder ("value object") that records the
     * token count and the nanosecond timestamp of the last refill.
     *
     * <p><strong>HOW it is immutable:</strong>
     * Both fields are declared {@code final}. Java guarantees that {@code final}
     * fields are fully written before any other thread can ever read this object,
     * making it inherently thread-safe to read without synchronization.
     * To "change" the state, you must create a completely new {@code State}
     * object and atomically swap the reference inside {@link #state}.
     */
    private static class State {

        // The current number of available tokens in this bucket.
        // This is a double (not int) so we can track fractional tokens that
        // accumulate as time passes (e.g., 0.5 tokens after 250ms at 2 tok/sec).
        final double tokens;

        // The system nanosecond timestamp recorded when this State was created.
        // We subtract this from the current time to know how long has elapsed,
        // which tells us how many tokens should have been refilled since then.
        // We use System.nanoTime() (not currentTimeMillis) because it offers
        // much higher resolution and is unaffected by system clock adjustments.
        final long lastRefillTimestampNanos;

        /**
         * Constructs a new immutable State.
         *
         * @param tokens                   The token count at this moment.
         * @param lastRefillTimestampNanos The nanosecond timestamp of this moment.
         */
        State(double tokens, long lastRefillTimestampNanos) {
            this.tokens = tokens;
            this.lastRefillTimestampNanos = lastRefillTimestampNanos;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIELDS
    // ─────────────────────────────────────────────────────────────────────────

    // The ceiling: no matter how long a client is idle, tokens can never
    // accumulate beyond this limit. This prevents a "thundering herd" scenario
    // where a client that was idle for an hour suddenly has thousands of tokens.
    private final double capacity;

    // How many tokens are added back to the bucket PER SECOND.
    // Example: refillRatePerSecond = 2.0 means 2 new tokens every second,
    // or equivalently 1 new token every 500 milliseconds.
    private final double refillRatePerSecond;

    // The atomic reference wrapping the current State of this bucket.
    // WHY AtomicReference: It allows us to read and swap the State object
    // as a single atomic CPU instruction (CAS), which is the core of our
    // lock-free algorithm. Multiple threads can safely race on this field.
    private final AtomicReference<State> state;

    // The most recent nanosecond timestamp when this bucket was accessed
    // (either for an allowed or a rejected request).
    // WHY volatile: The eviction manager runs on a DIFFERENT thread than the
    // threads making requests. Declaring this field volatile ensures that
    // when the eviction thread reads it, it sees the latest value written by
    // any request-handling thread (no CPU cache staleness).
    // WHY separate from State: We update this on every check, even when the
    // token count is zero (request blocked). The CAS loop only fires when
    // tokens >= 1.0, so we need a separate write path for the access timestamp.
    private volatile long lastAccessTimestampNanos;

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Configures and creates a new Token Bucket starting in a FULL state.
     *
     * <p><strong>WHY start full:</strong>
     * A brand-new client connecting for the first time should receive the
     * maximum number of tokens immediately. They haven't sent any prior requests,
     * so their bucket should be at full capacity. This provides a good burst
     * allowance for legitimate first-time users.
     *
     * <p><strong>WHAT:</strong>
     * Stores the capacity and refill rate constants, and initializes the atomic
     * State reference to a new State object with {@code tokens == capacity} and
     * a timestamp of "right now".
     *
     * <p><strong>HOW:</strong>
     * Captures the current nanosecond time via {@link System#nanoTime()} and
     * wraps a full-capacity {@link State} inside a new {@link AtomicReference}.
     *
     * @param capacity             The maximum number of tokens the bucket can hold.
     *                             Example: {@code 10} → allow up to 10 burst requests.
     * @param refillRatePerSecond  How many tokens are added per second.
     *                             Example: {@code 2.0} → steady-state rate of 2 req/sec.
     */
    public TokenBucket(double capacity, double refillRatePerSecond) {
        this.capacity = capacity;
        this.refillRatePerSecond = refillRatePerSecond;

        // Capture the current nanosecond time for the initial State timestamp.
        long now = System.nanoTime();

        // Start with a full bucket: tokens = capacity, timestamp = now.
        // AtomicReference wraps this initial State so we can perform CAS later.
        this.state = new AtomicReference<>(new State(capacity, now));

        // Also mark the last access as "now" so the eviction scheduler does not
        // immediately consider this fresh bucket as expired.
        this.lastAccessTimestampNanos = now;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The CORE METHOD — evaluates if this request should be allowed or rejected,
     * and atomically consumes one token if allowed.
     *
     * <p><strong>WHY the CAS (Compare-And-Swap) loop is necessary:</strong>
     * Multiple server worker threads may call {@code allowRequest()} for the same
     * client simultaneously (e.g., two requests arriving 1ms apart). Without a
     * lock, we cannot use a simple read-modify-write sequence. Instead, we use
     * an optimistic concurrency approach:
     * <ol>
     *   <li>Read the current state.</li>
     *   <li>Compute the intended new state.</li>
     *   <li>Use CAS to atomically publish the new state ONLY IF the current state
     *       has not been changed by another thread in the meantime.</li>
     *   <li>If it WAS changed by another thread, discard our work and retry.</li>
     * </ol>
     * Under low contention (most cases), this succeeds on the first try. Under
     * extreme contention, it retries a few times — always without any thread
     * sleeping or waiting in a queue.
     *
     * <p><strong>WHAT:</strong>
     * Returns {@code true} and deducts exactly 1.0 token if at least 1.0 token
     * is available after applying time-based refill. Returns {@code false} if
     * tokens are insufficient (the client is throttled).
     *
     * <p><strong>HOW — step by step inside the loop:</strong>
     * <pre>
     *   1. Record the current nanoTime as {@code now}.
     *   2. Update lastAccessTimestampNanos (for the eviction manager).
     *   3. Read the current AtomicReference State snapshot.
     *   4. Compute elapsed nanoseconds since the last refill.
     *   5. Convert to seconds, multiply by refillRatePerSecond → refilled tokens.
     *   6. Add refilled tokens to stored tokens, cap at capacity.
     *   7. If tokens < 1.0 → return false (reject request, no state change).
     *   8. Build a new State with (currentTokens - 1.0, now).
     *   9. Call compareAndSet(current, next):
     *      • SUCCESS → return true (request allowed, new state published).
     *      • FAILURE → another thread changed the state; loop back to step 3.
     * </pre>
     *
     * @return {@code true} if the request is allowed (token consumed),
     *         {@code false} if the client has exceeded their rate limit.
     */
    public boolean allowRequest() {
        // ── Step 1: Capture "now" once for consistent calculations in this iteration ──
        long now = System.nanoTime();

        // ── Step 2: Update the access timestamp regardless of whether we allow ──
        // Even a rejected request counts as an access — it means the client is still
        // active and their bucket should NOT be evicted from memory.
        this.lastAccessTimestampNanos = now;

        // ── Step 3: CAS loop — keeps retrying until we succeed or the request is denied ──
        while (true) {

            // Read the CURRENT immutable State snapshot from the AtomicReference.
            // If another thread just swapped the State, we immediately see the new value.
            State current = state.get();

            // ── Step 4: Calculate elapsed time since the last refill ──
            long elapsedNanos = now - current.lastRefillTimestampNanos;

            // Guard: System.nanoTime() can theoretically go backwards on some JVMs
            // (e.g., after a NTP time adjustment). Clamp to 0 to avoid negative refills.
            if (elapsedNanos < 0) {
                elapsedNanos = 0;
            }

            // ── Step 5: Convert nanoseconds → seconds for the refill formula ──
            // 1 second = 1,000,000,000 nanoseconds.
            // We use a double division to preserve fractional seconds.
            // Example: 250,000,000 ns elapsed → 0.25 seconds.
            double elapsedSeconds = elapsedNanos / 1_000_000_000.0;

            // ── Step 6a: Calculate how many tokens were refilled in the elapsed time ──
            // Example: 0.25 seconds * 2.0 tok/sec = 0.5 tokens refilled.
            double refilled = current.tokens + (elapsedSeconds * refillRatePerSecond);

            // ── Step 6b: Cap to capacity — the bucket cannot overflow ──
            // Example: if capacity = 10.0 and refilled = 12.3, clamp to 10.0.
            double currentTokens = Math.min(capacity, refilled);

            // ── Step 7: DENY the request if tokens are insufficient ──
            // We require at least 1 full token for every request.
            // We do NOT modify the state in this branch — no CAS needed, just return.
            if (currentTokens < 1.0) {
                return false; // Request THROTTLED — client has exceeded their rate limit.
            }

            // ── Step 8: Build the new State after consuming 1 token ──
            // The new state captures:
            //   • tokens:    currentTokens - 1.0  (one token consumed)
            //   • timestamp: now                  (the refill clock resets to now)
            State next = new State(currentTokens - 1.0, now);

            // ── Step 9: Attempt the atomic Compare-And-Swap ──
            // compareAndSet(expectedValue, newValue):
            //   • Checks if the current value of `state` is still the SAME object as `current`.
            //   • If YES → swaps it to `next` and returns true. We are done!
            //   • If NO  → another thread changed `state` between our read and this swap.
            //               Returns false. We loop back to retry with fresh data.
            if (state.compareAndSet(current, next)) {
                return true; // Request ALLOWED — token successfully consumed.
            }

            // If we reach here, compareAndSet returned false.
            // The while(true) loop retries automatically with the new current state.
        }
    }

    /**
     * Returns the nanosecond timestamp of the last time this bucket was accessed.
     *
     * <p><strong>WHY:</strong>
     * The {@link RateLimiterManager}'s eviction scheduler runs on a separate
     * background thread and needs to know how long a bucket has been completely
     * idle (no requests) so it can decide whether to delete it and free memory.
     * This timestamp is updated on EVERY request (even rejected ones), so it
     * accurately represents "the last time this client did anything."
     *
     * <p><strong>WHAT:</strong>
     * Returns the raw {@code lastAccessTimestampNanos} long value.
     *
     * <p><strong>HOW:</strong>
     * Reads the {@code volatile} field. The {@code volatile} keyword guarantees
     * that the eviction thread sees the most up-to-date value written by any
     * request-handling thread, without any explicit synchronization needed.
     *
     * @return The nanosecond timestamp ({@link System#nanoTime()}) of the last access.
     */
    public long getLastAccessTimestamp() {
        return lastAccessTimestampNanos;
    }

    /**
     * Calculates and returns the current effective token count, applying lazy refills.
     *
     * <p><strong>WHY "lazy" refill:</strong>
     * We do NOT maintain a background timer that adds tokens to every bucket every
     * second. That would require N timers for N clients — wasteful. Instead, refill
     * is computed ON DEMAND: we look at how much time has elapsed and calculate
     * what the token count WOULD be right now. This "lazy evaluation" approach is
     * extremely efficient.
     *
     * <p><strong>WHAT:</strong>
     * A read-only inspection method. Does NOT consume a token.
     * Used for debugging, logging, unit tests, or dashboard displays.
     *
     * <p><strong>HOW:</strong>
     * Reads the current {@link State}, computes elapsed time from its timestamp
     * to now, adds the proportional refill, caps at capacity, and returns the result.
     *
     * @return The current effective token count (a double between 0.0 and capacity).
     */
    public double getCurrentTokens() {
        // Read the current state snapshot (this is a non-CAS read, so it is read-only).
        State current = state.get();

        // Compute elapsed nanoseconds since the state was last recorded.
        long elapsedNanos = System.nanoTime() - current.lastRefillTimestampNanos;

        // Same negative-time guard as in allowRequest().
        if (elapsedNanos < 0) elapsedNanos = 0;

        // Convert elapsed nanoseconds to fractional seconds.
        double elapsedSeconds = elapsedNanos / 1_000_000_000.0;

        // Add refilled tokens to the stored count, then cap at capacity.
        return Math.min(capacity, current.tokens + (elapsedSeconds * refillRatePerSecond));
    }
}
