package Routing;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class Routing {
    // Map to track active connections per server
    public static final Map<String, Integer> activeConnections = new ConcurrentHashMap<>();
    
    // HttpClient for proxying requests
    private static final HttpClient proxyClient;

    static {
        // Initialize active connections count
        for (String url : ResponseTime.TARGET_URLS) {
            activeConnections.put(url, 0);
        }
        
        // Configure HttpClient for proxying to trust self-signed certs
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            proxyClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SSL for proxy", e);
        }
    }

    public static void main(String[] args) {
        System.out.println("Starting Load Balancer Routing...");
        
        // Initialize ResponseTime as a helper
        ResponseTime poller = new ResponseTime();
        
        // This starts the asynchronous, non-blocking network polling in the background
        poller.startPolling();
        
        System.out.println("Response time poller is running in the background.");
        System.out.println("Routing logic can now proceed here...");
        
        // Simulate an incoming request after giving the poller a couple of seconds to get initial latencies
        try { Thread.sleep(6000); } catch (Exception e) {}
        
        System.out.println("Simulating incoming HTTPS request...");
        routeRequest("api/test-path").join();
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

    /**
     * Takes an incoming dummy HTTPS request and routes it to the lowest score server.
     * Uses CompletableFuture to keep it non-blocking.
     */
    public static CompletableFuture<HttpResponse<String>> routeRequest(String path) {
        String targetServer = getLowestScoreServer();
        System.out.println("Routing request to best server: " + targetServer);
        
        // Increment active connections
        activeConnections.compute(targetServer, (k, v) -> v == null ? 1 : v + 1);
        
        // Create proxy request forwarding to backend server
        HttpRequest proxyRequest = HttpRequest.newBuilder()
            .uri(URI.create(targetServer + path))
            .GET() 
            .build();
            
        return proxyClient.sendAsync(proxyRequest, HttpResponse.BodyHandlers.ofString())
            .whenComplete((response, error) -> {
                // Decrement active connections once the request finishes
                activeConnections.compute(targetServer, (k, v) -> (v == null || v == 0) ? 0 : v - 1);
                
                if (error != null) {
                    System.err.println("Proxy request failed: " + error.getMessage());
                } else {
                    System.out.println("Successfully proxied request to " + targetServer + " with status: " + response.statusCode());
                    System.out.println("Response Body: " + response.body());
                }
            });
    }
}
