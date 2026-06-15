package Routing;

// ─────────────────────────────────────────────────────────────────────────────
// WHY ConcurrentHashMap for activeConnections:
//   Multiple request-handler threads will increment/decrement the active
//   connection count for servers simultaneously. A regular HashMap would
//   corrupt its internal structure under concurrent writes. ConcurrentHashMap
//   provides thread-safe reads and writes without blocking the whole map for
//   every operation.
// ─────────────────────────────────────────────────────────────────────────────
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Load balancing router that selects the BEST backend server for each incoming request.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER CONTEXT — What is a routing strategy?
 * ═══════════════════════════════════════════════════════════════════
 * A load balancer sits in front of multiple backend servers and must decide
 * which backend to send each incoming client request to. There are many
 * strategies for making this decision:
 *
 *   1. Round-Robin:       Take turns sending to Server 1, 2, 3, 1, 2, 3...
 *   2. Least Connections: Send to the server handling the fewest requests right now.
 *   3. Weighted:          Prefer faster/more powerful servers.
 *   4. IP Hash:           Send the same client IP to the same server every time.
 *   5. Latency-Aware:     Send to the server with the lowest recent response time.
 *
 * This class implements a COMBINED strategy: "Least Connections + Latency".
 * It calculates a SCORE for each server using the formula:
 *
 *   score = (activeConnections + 1) * averageResponseTimeMs
 *
 * The server with the LOWEST score is chosen. This means:
 *   - A server with few connections AND fast responses gets the lowest score → chosen first.
 *   - A server that is slow or overloaded gets a high score → avoided.
 *   - The "+1" ensures a server with 0 connections still uses its latency in the score
 *     (preventing zero-latency servers from always winning due to multiplication by zero).
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * Distributing requests across servers requires a decision function that accounts
 * for both current load (active connections) and server health (response latency).
 * A server that technically has 0 connections but is taking 2000ms to respond
 * should not receive new traffic. This combined scoring formula prevents that mistake.
 *
 * <p><strong>WHAT this class provides:</strong>
 * <ul>
 *   <li>A shared, thread-safe active-connection counter map per server URL.</li>
 *   <li>{@link #getLowestScoreServer()} — the routing decision function.</li>
 *   <li>A {@code main()} demo that shows the routing in action with live polling data.</li>
 * </ul>
 *
 * <p><strong>HOW it integrates with {@link ResponseTime}:</strong>
 * {@link ResponseTime} runs a background HTTP poller that continuously measures
 * each backend's average response latency and stores it in
 * {@link ResponseTime#averageLatencies}. This Routing class reads from that map
 * to include latency in its scoring formula. The two classes share the server
 * URL list via {@link ResponseTime#TARGET_URLS}.
 */
public class Routing {

    /**
     * A thread-safe map tracking how many active connections are currently open to each backend server.
     *
     * <p><strong>WHY volatile Map AND ConcurrentHashMap together:</strong>
     * {@code volatile} on the map REFERENCE means that if someone ever reassigned the map
     * variable itself (e.g., {@code activeConnections = new ConcurrentHashMap<>()}), all
     * threads would immediately see the new reference. {@link ConcurrentHashMap} handles
     * thread-safe access to the MAP CONTENTS (individual key-value pairs). Together they
     * cover both reference visibility and content thread-safety.
     *
     * <p><strong>Key:</strong>   Server URL string (e.g., "https://localhost:3001/").
     * <p><strong>Value:</strong> Integer count of how many requests are currently being
     *                            forwarded to that server (in-flight requests).
     *
     * <p><strong>Usage pattern:</strong>
     * <pre>
     *   // When a request is assigned to a server:
     *   activeConnections.merge(chosenServer, 1, Integer::sum);    // increment by 1
     *
     *   // When the request completes (on the backend):
     *   activeConnections.merge(chosenServer, -1, Integer::sum);   // decrement by 1
     * </pre>
     */
    public static volatile Map<String, Integer> activeConnections = new ConcurrentHashMap<>();

    // ── Static Initializer Block ──
    // This runs ONCE when the Routing class is first loaded by the JVM (before any
    // main() or method call). It pre-populates the activeConnections map with an
    // initial count of 0 for each known server URL.
    //
    // WHY we initialize to 0 here (not lazily):
    //   getOrDefault(url, 0) in getLowestScoreServer() would handle missing keys,
    //   but pre-initializing makes the map state explicit and avoids relying on
    //   getOrDefault() as a correctness crutch. It also ensures that iterating
    //   over TARGET_URLS always finds a corresponding entry in this map.
    static {
        for (String url : ResponseTime.TARGET_URLS) {
            activeConnections.put(url, 0); // All servers start with 0 active connections
        }
    }

    /**
     * Demo entry point — starts the response time poller, waits for initial data,
     * then selects and prints the best server.
     *
     * <p><strong>WHY the 6-second sleep:</strong>
     * The {@link ResponseTime} poller is asynchronous — it fires HTTP requests in the
     * background every 5 seconds. If we call {@link #getLowestScoreServer()} immediately
     * after starting the poller, the {@link ResponseTime#averageLatencies} map will still
     * show all zeros (no data yet). We wait 6 seconds to let at least one full poll cycle
     * complete so the routing decision uses real latency measurements.
     *
     * @param args Command-line arguments (not used in this demo).
     */
    public static void main(String[] args) {
        System.out.println("Starting Load Balancer Routing Strategy...");

        // Step 1: Create the response time poller (it creates the HttpClient and scheduler).
        ResponseTime poller = new ResponseTime();

        // Step 2: Begin the asynchronous background polling.
        // This sends periodic HTTP requests to each backend and updates averageLatencies.
        poller.startPolling();

        System.out.println("Response time poller is running in the background.");

        // Step 3: Wait 6 seconds so at least one poll cycle (5 seconds) can complete.
        // This ensures that when we make our routing decision below, we have real latency data.
        try {
            Thread.sleep(6000); // 6,000 milliseconds = 6 seconds
        } catch (Exception e) {
            // InterruptedException means someone told this thread to stop (rare in a demo).
            // We swallow it here for simplicity, but in production we'd propagate it.
        }

        System.out.println("Simulating an incoming request allocation...");

        // Step 4: Run the routing algorithm and print the chosen server.
        String chosenServer = getLowestScoreServer();
        System.out.println("\nAllocated Best Server: " + chosenServer);
    }

    /**
     * Selects the backend server with the lowest combined load score.
     *
     * <p><strong>WHY this scoring formula:</strong>
     * The formula {@code score = (connections + 1) * avgLatencyMs} elegantly combines
     * two dimensions of server health into one comparable number:
     * <ul>
     *   <li><strong>Connections</strong>: Represents current load. More connections → busier server.</li>
     *   <li><strong>Latency</strong>:     Represents server responsiveness. Higher latency → slower server.</li>
     *   <li><strong>Multiplication</strong>: Creates an interaction effect — a slow server under load is
     *       penalized much more severely than either factor alone would suggest.</li>
     *   <li><strong>The +1 offset</strong>: Without +1, a server with 0 connections would always get
     *       score = 0 regardless of latency (0 * anything = 0). The offset ensures latency still
     *       differentiates between idle servers. Example: Server A (0 conns, 5ms) gets score 5,
     *       Server B (0 conns, 200ms) gets score 200 → A is correctly preferred.</li>
     * </ul>
     *
     * <p><strong>WHAT:</strong>
     * Iterates over all known server URLs, computes a score for each using the formula above,
     * and returns the URL of the server with the minimum score.
     *
     * <p><strong>HOW:</strong>
     * <pre>
     *   Example state:
     *     Server A: 3 active connections, 10ms average latency → score = (3+1)*10  = 40
     *     Server B: 1 active connection,  50ms average latency → score = (1+1)*50  = 100
     *     Server C: 0 active connections, 15ms average latency → score = (0+1)*15  = 15
     *
     *   Server C wins (lowest score = 15) even though Server A has faster latency,
     *   because Server A is already handling 3 connections.
     * </pre>
     *
     * <p><strong>Thread safety note:</strong>
     * Both {@link #activeConnections} and {@link ResponseTime#averageLatencies} are
     * {@link ConcurrentHashMap}s accessed via volatile references. Reading them here
     * is safe without additional locking. However, there is a small window where
     * connections could increment AFTER we read but BEFORE we assign — this is
     * acceptable for approximate routing decisions (perfect precision is not required).
     *
     * @return The URL string of the best available backend server, or {@code null}
     *         if {@link ResponseTime#TARGET_URLS} is empty.
     */
    public static String getLowestScoreServer() {
        String bestServer = null;
        // Initialize with the largest possible double so any real score will be lower.
        double lowestScore = Double.MAX_VALUE;

        // Iterate over every registered backend server URL.
        for (String url : ResponseTime.TARGET_URLS) {

            // ── Get current active connection count ──
            // getOrDefault provides 0 if the server somehow isn't in our map yet.
            int connections = activeConnections.getOrDefault(url, 0);

            // ── Get the most recent average latency from the background poller ──
            // Default of 100.0ms is used if no polling data has arrived yet.
            // WHY 100ms as default: It's a conservative "middle-ground" assumption.
            // A server with no measurements yet is neither assumed fast nor slow,
            // but it won't be totally ignored (not Double.MAX_VALUE).
            double avgLatency = ResponseTime.averageLatencies.getOrDefault(url, 100.0);

            // ── Compute the combined score ──
            // score = (activeConnections + 1) * averageLatencyMs
            // Lower score = better server choice.
            double score = (connections + 1) * avgLatency;

            // Print the scoring breakdown for visibility (useful for debugging/demonstration).
            System.out.printf("Server %s -> Active Conns: %d, Avg Latency: %.2f ms => Score: %.2f%n",
                    url, connections, avgLatency, score);

            // ── Track the server with the minimum score ──
            if (score < lowestScore) {
                lowestScore = score;
                bestServer = url;
            }
        }

        // Return the URL of the best server (or null if no servers are configured).
        return bestServer;
    }
}
