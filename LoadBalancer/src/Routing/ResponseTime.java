package Routing;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
// Note: This import was unused in the code but kept to avoid removing existing structures
import java.net.http.HttpResponse.BodyHandler;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * The ResponseTime class connects to a designated server at a regular 
 * interval to measure and log its network latency/response time.
 * 
 * It runs as a background service using a scheduled executor pool.
 */
public class ResponseTime {
    // Array of server URLs to poll simultaneously
    public static final String[] TARGET_URLS = {
        "https://localhost:3001/",
        "https://localhost:3002/",
        "https://localhost:3003/"
    };
    // polling interval set to 5
    private static final int POLL_INTERVAL_SECONDS = 5;

    // Latency histories for each server (max 15 entries)
    private static volatile Map<String, List<Long>> serverLatencies = new ConcurrentHashMap<>();
    
    // Publicly accessible average latencies for use by other components
    public static volatile Map<String, Double> averageLatencies = new ConcurrentHashMap<>();

    static {
        for (String url : TARGET_URLS) {
            serverLatencies.put(url, Collections.synchronizedList(new ArrayList<>()));
            averageLatencies.put(url, 0.0);
        }
    }

    // instantiating the http client to make requests
    private final HttpClient httpClient;
    // This line creates a background thread manager that allows your Java program
    // to execute tasks after a specific delay or repeatedly at fixed intervals.
    private final ScheduledExecutorService scheduler;

    /**
     * Initializes the server poller with a HTTP client configuration 
     * and a dedicated background scheduling thread.
     */
    public ResponseTime() {
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
            
            // here i built a reusable http client with 5 second connection timeout
            this.httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SSL", e);
        }
        // create a thread pool scheduler with threads equal to the number of URLs
        this.scheduler = Executors.newScheduledThreadPool(TARGET_URLS.length);
    }

    /**
     * Starts the periodic background execution to poll the target URL.
     * Calculates and logs response times or connection failures.
     */
    public void startPolling(){
        for (String url : TARGET_URLS) {
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
            scheduler.scheduleWithFixedDelay(()->{
             // FIX: Fixed case-sensitivity typo 'startTIme' and 'nanoTIme' to 'startTime' and 'nanoTime'
             long startTime = System.nanoTime();
             httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                 .thenAccept(response -> {
                     long endTime = System.nanoTime();
                     long responseTimeMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
                     
                     List<Long> latencies = serverLatencies.get(url);
                     synchronized (latencies) {
                         latencies.add(responseTimeMs);
                         if (latencies.size() > 15) {
                             latencies.remove(0);
                         }
                         long sum = 0;
                         for (long latency : latencies) {
                             sum += latency;
                         }
                         double avg = (double) sum / latencies.size();
                         averageLatencies.put(url, avg);
                         System.out.printf("[%s] [%s] Average Latency: %.2f ms%n", java.time.LocalTime.now(), url, avg);
                     }
                 })
                 .exceptionally(e -> {
                     long endTime = System.nanoTime();
                     long failureTimeMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
                     System.err.printf("[%s] [%s] Request failed after %d ms: %s%n", java.time.LocalTime.now(), url, failureTimeMs, e.getMessage());
                     return null;
                 });
            }, 0, POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);
        }
    }

    /**
     * Gracefully stops the background scheduler thread execution.
     */
    public void stopPolling() {
        scheduler.shutdown();
    }

    /**
     * Application entry point. Instantiates the poller, runs it for a fixed duration,
     * and cleans up resources before exiting.
     */
    public static void main(String[] args) {
        System.out.println("starting server latency poller...");
        // FIX: Changed 'ServerPoller' to match your class name 'ResponseTime'
        ResponseTime poller = new ResponseTime();
        poller.startPolling();
        try {
            Thread.sleep(60000);
        } catch (InterruptedException e) {
            // FIX: Fixed case-sensitivity typo 'currentTHread' to 'currentThread'
            Thread.currentThread().interrupt();
        }
        System.out.println("Stopping poller... ");
        poller.stopPolling();
    }
}
