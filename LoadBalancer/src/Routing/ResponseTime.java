package Routing;

// ─────────────────────────────────────────────────────────────────────────────
// IMPORTS — Why each one is needed
// ─────────────────────────────────────────────────────────────────────────────
import java.io.IOException;

// URI: Represents a Uniform Resource Identifier (e.g., "https://localhost:3001/").
// Used to build HttpRequest targets for the HTTP client.
import java.net.URI;

// HttpClient: Java 11+ built-in HTTP client. Used to send HTTP/HTTPS requests
// to backend servers to measure their response time.
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

// BodyHandler is the interface that tells the HttpClient what to do with
// the response body. We use BodyHandlers.discarding() because we only care
// about the TIMING of the response, not its content.
import java.net.http.HttpResponse.BodyHandler;

// Duration: Represents a length of time (e.g., Duration.ofSeconds(5) = 5-second timeout).
import java.time.Duration;

// Collections + ArrayList: Used to create a synchronized list that safely stores
// the rolling history of latency measurements for each server.
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

// ConcurrentHashMap: Thread-safe map used to store latency histories and averages.
// Multiple threads (poller threads) write to this map simultaneously.
import java.util.concurrent.ConcurrentHashMap;

// ScheduledExecutorService: A thread pool that can execute tasks at regular intervals.
// We use it to fire health-check requests to each backend every N seconds.
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

// SSL imports: The backend servers use self-signed TLS certificates (for development).
// A standard Java HttpClient would REJECT self-signed certs. We override certificate
// validation with a "trust all" TrustManager so we can connect anyway.
// WARNING: "Trust all" is only safe for internal/dev environments, NOT production.
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * Background service that periodically probes each backend server and tracks its average latency.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER CONTEXT — Why do we need to measure server latency?
 * ═══════════════════════════════════════════════════════════════════
 * A load balancer's job is to route each new request to the "best" server.
 * But what makes a server "best"? One critical factor is RESPONSE TIME:
 * how long does the server take to reply? A server that is overloaded,
 * has a full garbage collector, or is running on slow hardware will take
 * much longer to respond.
 *
 * If we blindly route traffic to an overloaded server, client requests
 * will time out or experience very slow responses. By continuously measuring
 * each server's response time and feeding that data into the routing
 * algorithm, we can dynamically avoid slow servers.
 *
 * This class is a "health poller" — it sends lightweight HTTP GET requests
 * to each backend server every 5 seconds, measures how long the response
 * takes, and maintains a rolling average of the last 15 measurements.
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * The {@link Routing} class needs up-to-date latency data to compute routing scores.
 * Without a background poller, routing decisions would have to be made with no
 * knowledge of server health, falling back to static weights or round-robin.
 *
 * <p><strong>WHAT this class provides:</strong>
 * <ul>
 *   <li>Shared static maps ({@link #serverLatencies} and {@link #averageLatencies})
 *       that other classes (like {@link Routing}) read for routing decisions.</li>
 *   <li>{@link #startPolling()} — starts the background poller for all servers.</li>
 *   <li>{@link #stopPolling()} — cleanly stops the background scheduler.</li>
 * </ul>
 *
 * <p><strong>HOW it works:</strong>
 * <ol>
 *   <li>For each backend server URL, a scheduled task fires every 5 seconds.</li>
 *   <li>Each task records {@code startTime = System.nanoTime()}, fires an async HTTP GET.</li>
 *   <li>When the response arrives, it computes {@code responseTime = endTime - startTime}.</li>
 *   <li>It appends the measurement to a rolling window list (max 15 entries, oldest discarded).</li>
 *   <li>It recalculates the rolling average and updates {@link #averageLatencies}.</li>
 *   <li>The {@link Routing} class reads {@link #averageLatencies} when computing scores.</li>
 * </ol>
 */
public class ResponseTime {

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTANTS — Server URLs and polling configuration
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The list of backend server URLs to monitor.
     *
     * <p><strong>WHY public static final:</strong>
     * These URLs are shared constants that other classes ({@link Routing}) need to
     * iterate over. Declaring them as a {@code public static final} array ensures
     * there is exactly ONE copy shared across all classes — no duplication.
     *
     * <p><strong>WHY HTTPS on localhost:</strong>
     * Backend servers are also running HTTPS (not plain HTTP) to ensure all traffic
     * is encrypted end-to-end, even within the internal network. This is a "defense
     * in depth" security practice.
     *
     * <p>In a production deployment, these would typically be loaded from a config
     * file or service discovery system (e.g., Consul, Kubernetes), not hardcoded.
     */
    public static final String[] TARGET_URLS = {
        "https://localhost:3001/",
        "https://localhost:3002/",
        "https://localhost:3003/"
    };

    /**
     * How often (in seconds) to send a health check probe to each backend server.
     *
     * <p><strong>WHY 5 seconds:</strong>
     * 5 seconds is a balance between two competing needs:
     * <ul>
     *   <li>Too frequent (e.g., every 100ms): adds unnecessary load to backend servers,
     *       wastes network bandwidth, and creates extra server-side log entries.</li>
     *   <li>Too infrequent (e.g., every 60s): routing data becomes stale; a server that
     *       started struggling 55 seconds ago may still appear healthy.</li>
     * </ul>
     * 5 seconds offers a reasonable middle ground for a development/demo environment.
     */
    private static final int POLL_INTERVAL_SECONDS = 5;

    // ─────────────────────────────────────────────────────────────────────────
    // SHARED STATE — Latency data accessible by the Routing class
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Rolling history of raw latency measurements (in milliseconds) per server URL.
     *
     * <p><strong>WHY a rolling window (max 15 entries):</strong>
     * We don't keep ALL historical measurements because:
     * <ul>
     *   <li>Old measurements are less relevant — server performance can change rapidly.</li>
     *   <li>A rolling average of 15 samples (75 seconds worth at 5s intervals) smooths
     *       out occasional spikes without being overly influenced by ancient history.</li>
     * </ul>
     * When a new measurement arrives and the list already has 15 entries, we remove
     * the oldest one (index 0) before adding the new one (sliding window).
     *
     * <p><strong>WHY volatile on the Map reference:</strong>
     * If this field were reassigned by one thread, other threads must see the new reference
     * immediately. {@code volatile} guarantees cross-thread reference visibility.
     *
     * <p><strong>WHY Collections.synchronizedList(new ArrayList<>()):</strong>
     * {@link ConcurrentHashMap} ensures thread-safe access to the MAP (getting/putting by key),
     * but the VALUE (the List) itself needs separate protection. Multiple polled responses
     * for the same URL could arrive concurrently. {@code Collections.synchronizedList()}
     * wraps the ArrayList with synchronized methods so concurrent add/remove calls
     * on the same list don't corrupt it.
     */
    private static volatile Map<String, List<Long>> serverLatencies = new ConcurrentHashMap<>();

    /**
     * The current rolling average latency (in milliseconds) per server URL.
     *
     * <p><strong>WHY public (not private):</strong>
     * The {@link Routing} class reads this map directly to compute routing scores.
     * Making it public avoids the need for a getter method and keeps the code concise.
     * In a larger system, a getter would be preferable for encapsulation.
     *
     * <p><strong>WHY volatile + ConcurrentHashMap:</strong>
     * Poller threads WRITE to this map. The routing thread READS from it.
     * {@code volatile} ensures the map reference is visible across threads.
     * {@link ConcurrentHashMap} ensures individual put() operations are thread-safe.
     *
     * <p><strong>Key:</strong>   Server URL (e.g., "https://localhost:3001/")
     * <p><strong>Value:</strong> Rolling average latency in milliseconds (e.g., 12.5)
     */
    public static volatile Map<String, Double> averageLatencies = new ConcurrentHashMap<>();

    // ── Static Initializer Block ──
    // Runs once when the class is first loaded. Pre-populates both maps with
    // empty initial values for each server URL so subsequent put() calls never
    // need to handle null entries. averageLatencies is initialized to 0.0
    // (interpreted as "no data yet" until the first real measurement arrives).
    static {
        for (String url : TARGET_URLS) {
            // Create an empty thread-safe list for each server's measurement history.
            serverLatencies.put(url, Collections.synchronizedList(new ArrayList<>()));
            // Initialize average to 0.0 — will be replaced after first poll completes.
            averageLatencies.put(url, 0.0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INSTANCE FIELDS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The reusable Java 11+ HTTP client used to send probes to backend servers.
     *
     * <p><strong>WHY one shared HttpClient (not one per request):</strong>
     * Creating an HttpClient is expensive — it allocates thread pools, SSL sessions,
     * and connection caches internally. By creating ONE client here and reusing it
     * for all polls, we amortize this cost across all requests.
     *
     * <p><strong>WHY the 5-second connection timeout:</strong>
     * If a backend server is completely unreachable (crashed, network partition),
     * without a timeout the HttpClient would block indefinitely waiting for a TCP
     * connection. The 5-second timeout ensures the poller moves on quickly and
     * records the failure rather than hanging.
     */
    private final HttpClient httpClient;

    /**
     * The background scheduler that triggers health-check probes at fixed intervals.
     *
     * <p><strong>WHY ScheduledExecutorService (not java.util.Timer):</strong>
     * {@code ScheduledExecutorService} is the modern replacement for the older
     * {@code java.util.Timer}. Key advantages:
     * <ul>
     *   <li>Uses a thread POOL: can run multiple polls to different servers simultaneously.</li>
     *   <li>Better exception handling: if one task throws, it doesn't kill the scheduler.</li>
     *   <li>Integrates cleanly with Java's {@code ExecutorService} lifecycle ({@code shutdown()}).</li>
     * </ul>
     */
    private final ScheduledExecutorService scheduler;

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initializes the HTTP client (with TLS trust-all for dev) and the scheduler thread pool.
     *
     * <p><strong>WHY the "trust all" TrustManager:</strong>
     * Backend servers likely use self-signed TLS certificates (not purchased from a Certificate
     * Authority like DigiCert or Let's Encrypt). By default, Java's SSL layer rejects self-signed
     * certificates with an {@code SSLHandshakeException}. The {@code X509TrustManager}
     * implementation below bypasses certificate validation entirely.
     *
     * <p><strong>⚠️ SECURITY WARNING:</strong>
     * "Trust all" TrustManagers are ONLY safe in controlled internal networks where you
     * control both the client and server. In production internet-facing systems, you should
     * either:
     * <ul>
     *   <li>Use a real CA-signed certificate on the backend.</li>
     *   <li>Import the self-signed certificate into a custom TrustStore.</li>
     * </ul>
     * Using "trust all" in production makes you vulnerable to Man-In-The-Middle (MITM) attacks.
     *
     * <p><strong>HOW the scheduler pool size is chosen:</strong>
     * {@code Executors.newScheduledThreadPool(TARGET_URLS.length)} creates a pool with exactly
     * as many threads as there are servers. This allows ALL servers to be polled SIMULTANEOUSLY
     * rather than one after another (which would skew timing measurements for later servers).
     */
    public ResponseTime() {
        try {
            // ── Build a "trust all" SSL context for development use ──
            // TrustManager is an interface that decides whether to accept a server's certificate.
            // Our anonymous class implementation accepts ALL certificates by doing nothing.
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    // Return null: "I don't have a list of trusted issuers — I trust everything."
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    // Empty method: "I accept all client certificates without checking."
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    // Empty method: "I accept all server certificates without checking."
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            // Create an SSL context using the "TLS" protocol and initialize it with
            // our trust-all manager. null for key managers (we're the client, not a server).
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());

            // Build the HttpClient with:
            //   - Our custom SSL context (trust all certs)
            //   - A 5-second connection timeout (fail fast if backend is unreachable)
            this.httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        } catch (Exception e) {
            // SSL setup failure is catastrophic — we cannot poll servers without it.
            throw new RuntimeException("Failed to configure SSL for health poller", e);
        }

        // ── Create the scheduler thread pool ──
        // One thread per server URL ensures simultaneous polling of all backends.
        // If we had only 1 thread for 3 servers, polls would be sequential and
        // the measured latencies would include queuing time, not just server response time.
        this.scheduler = Executors.newScheduledThreadPool(TARGET_URLS.length);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LIFECYCLE METHODS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Starts the background polling loop for ALL backend servers simultaneously.
     *
     * <p><strong>WHY scheduleWithFixedDelay (not scheduleAtFixedRate):</strong>
     * {@code scheduleAtFixedRate} fires tasks at fixed clock intervals, regardless of
     * how long the previous task took. If polling takes longer than 5 seconds
     * (e.g., a backend is very slow), tasks would pile up. {@code scheduleWithFixedDelay}
     * waits 5 seconds AFTER the previous task finishes before starting the next one.
     * This prevents task pile-up and ensures a minimum gap between polls.
     *
     * <p><strong>WHY we build one HttpRequest per URL once (outside the lambda):</strong>
     * {@link HttpRequest} objects are immutable and reusable. Building them once outside
     * the scheduled lambda avoids rebuilding the same object on every poll cycle.
     *
     * <p><strong>HOW async polling works:</strong>
     * {@code httpClient.sendAsync()} fires the HTTP request asynchronously and immediately
     * returns a {@link java.util.concurrent.CompletableFuture}. The actual response handling
     * happens in callbacks ({@code .thenAccept()} and {@code .exceptionally()}) when
     * the response arrives, without blocking the scheduler thread.
     */
    public void startPolling() {
        for (String url : TARGET_URLS) {
            // Build a reusable HTTP GET request targeting this specific backend URL.
            // The request is immutable (no state) so it's safe to reuse across all future polls.
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

            // Schedule a health-check task for this specific URL.
            // scheduleWithFixedDelay parameters:
            //   - task:         the lambda below
            //   - initialDelay: 0 → start polling immediately when startPolling() is called
            //   - delay:        POLL_INTERVAL_SECONDS → wait this long after each task completes
            //   - unit:         TimeUnit.SECONDS
            scheduler.scheduleWithFixedDelay(() -> {

                // ── Record the start time BEFORE sending the request ──
                // System.nanoTime() provides nanosecond-resolution monotonic clock,
                // unaffected by system clock changes (NTP adjustments, daylight saving, etc.).
                long startTime = System.nanoTime();

                // ── Send the HTTP request asynchronously ──
                // sendAsync() does NOT block. It returns a CompletableFuture immediately.
                // BodyHandlers.discarding() tells the client to read and discard the response body.
                // WHY discard: We only care about timing, not the content of the response.
                //              Discarding avoids buffering large response bodies unnecessarily.
                httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())

                    // ── SUCCESS CALLBACK — runs when the response arrives ──
                    .thenAccept(response -> {
                        // Record the end time AFTER the full response is received.
                        long endTime = System.nanoTime();

                        // Convert the elapsed time from nanoseconds to milliseconds.
                        // TimeUnit.NANOSECONDS.toMillis() handles the division safely.
                        // This is the round-trip time: from sending the request to receiving the response.
                        long responseTimeMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);

                        // ── Update the rolling window for this server ──
                        List<Long> latencies = serverLatencies.get(url);

                        // Synchronize on the list because multiple threads (if two polled responses
                        // for the same URL arrive simultaneously) could both try to add an entry.
                        synchronized (latencies) {
                            // Add the new measurement to the rolling history.
                            latencies.add(responseTimeMs);

                            // If we have accumulated more than 15 samples, remove the oldest one.
                            // This keeps the list as a fixed-size sliding window.
                            // latencies.remove(0) removes the FIRST element (oldest measurement).
                            if (latencies.size() > 15) {
                                latencies.remove(0);
                            }

                            // ── Recalculate the rolling average ──
                            long sum = 0;
                            for (long latency : latencies) {
                                sum += latency;
                            }
                            // Cast to double before dividing to avoid integer division truncation.
                            double avg = (double) sum / latencies.size();

                            // ── Update the shared averageLatencies map ──
                            // This write is visible to the Routing class which reads this map.
                            averageLatencies.put(url, avg);

                            // Print a timestamped log entry so developers can monitor latency trends.
                            System.out.printf("[%s] [%s] Average Latency: %.2f ms%n",
                                java.time.LocalTime.now(), url, avg);
                        }
                    })

                    // ── FAILURE CALLBACK — runs if the HTTP request fails ──
                    // Examples of failures: backend server is down, connection refused, DNS error.
                    .exceptionally(e -> {
                        // Even on failure, record how long we waited before giving up.
                        long endTime = System.nanoTime();
                        long failureTimeMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);

                        // Log the failure with timing for debugging.
                        // Note: We intentionally do NOT update averageLatencies on failure.
                        // A failed probe is not a valid latency measurement — it doesn't
                        // tell us how fast the server is, only that it's unreachable.
                        // The routing layer will continue using the last known valid average.
                        System.err.printf("[%s] [%s] Request failed after %d ms: %s%n",
                            java.time.LocalTime.now(), url, failureTimeMs, e.getMessage());
                        return null; // CompletableFuture requires a return value; null is acceptable here.
                    });

            }, 0, POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);
        }
    }

    /**
     * Gracefully stops all background polling tasks.
     *
     * <p><strong>WHY call shutdown() at all (since threads are non-daemon):</strong>
     * The scheduler threads are NOT daemon threads by default, meaning the JVM will
     * NOT exit until they finish. Calling {@code shutdown()} signals them to stop
     * accepting new tasks, allowing the JVM to exit cleanly once all in-progress
     * tasks finish.
     *
     * <p><strong>HOW:</strong>
     * {@link ScheduledExecutorService#shutdown()} is a "soft" stop — it completes
     * currently executing tasks and then terminates the thread pool. It does NOT
     * interrupt in-progress HTTP requests immediately.
     */
    public void stopPolling() {
        // Signal the scheduler to stop scheduling new poll tasks.
        // Any currently in-progress poll task (e.g., waiting for a response) will still complete.
        scheduler.shutdown();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DEMO ENTRY POINT
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Standalone demo runner — starts polling, waits 60 seconds, then stops.
     *
     * <p><strong>WHY this main() exists here:</strong>
     * Having a {@code main()} method in this class lets developers test and observe
     * the polling behavior in isolation without needing to run the entire load balancer.
     * It's a "runnable documentation" of how the class is intended to be used.
     *
     * @param args Command-line arguments (not used in this demo).
     */
    public static void main(String[] args) {
        System.out.println("Starting server latency poller...");

        // Create and start the poller.
        ResponseTime poller = new ResponseTime();
        poller.startPolling();

        try {
            // Let the poller run for 60 seconds so we can observe ~12 measurement cycles.
            Thread.sleep(60000); // 60,000 milliseconds = 60 seconds
        } catch (InterruptedException e) {
            // Re-interrupt this thread to signal to the JVM that we were interrupted.
            // This is a best practice: do not swallow InterruptedException without re-interrupting.
            Thread.currentThread().interrupt();
        }

        System.out.println("Stopping poller...");
        poller.stopPolling();
    }
}
