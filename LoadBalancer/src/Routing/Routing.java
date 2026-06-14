package Routing;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Routing {
    // Map to track active connections per server
    public static volatile Map<String, Integer> activeConnections = new ConcurrentHashMap<>();

    static {
        // Initialize active connections count
        for (String url : ResponseTime.TARGET_URLS) {
            activeConnections.put(url, 0);
        }
    }

    public static void main(String[] args) {
        System.out.println("Starting Load Balancer Routing Strategy...");

        // Initialize ResponseTime as a helper
        ResponseTime poller = new ResponseTime();

        // This starts the asynchronous, non-blocking network polling in the background
        poller.startPolling();

        System.out.println("Response time poller is running in the background.");

        // Simulate giving the poller a couple of seconds to get initial latencies
        try {
            Thread.sleep(6000);
        } catch (Exception e) {
        }

        System.out.println("Simulating an incoming request allocation...");
        
        // Get the best server
        String chosenServer = getLowestScoreServer();
        System.out.println("\nAllocated Best Server: " + chosenServer);
    }

    /**
     * Finds the server with the lowest score.
     * Score = (Total Active Connections + 1) * Average Response Time.
     * The +1 ensures that 0 connections still factor in the latency.
     */
    public static String getLowestScoreServer() {
        String bestServer = null;
        double lowestScore = Double.MAX_VALUE;

        for (String url : ResponseTime.TARGET_URLS) {
            int connections = activeConnections.getOrDefault(url, 0);
            // Default to 100ms if not polled yet
            double avgLatency = ResponseTime.averageLatencies.getOrDefault(url, 100.0);

            // Calculate score
            double score = (connections + 1) * avgLatency;
            System.out.printf("Server %s -> Active Conns: %d, Avg Latency: %.2f ms => Score: %.2f%n",
                    url, connections, avgLatency, score);

            if (score < lowestScore) {
                lowestScore = score;
                bestServer = url;
            }
        }
        return bestServer;
    }
}
