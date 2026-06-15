package Routing;

import Config.ConfigLoader;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
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
 * Dynamic Active Health Checking State Machine.
 * Pings backend /health endpoints and manages Routing Ring evictions.
 */
public class ResponseTime {

    // State machine trackers
    public static final Map<String, String> serverState = new ConcurrentHashMap<>();
    private static final Map<String, Integer> successCount = new ConcurrentHashMap<>();
    private static final Map<String, Integer> failCount = new ConcurrentHashMap<>();

    private final HttpClient httpClient;
    private final ScheduledExecutorService scheduler;

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

            this.httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SSL", e);
        }

        int poolSize = ConfigLoader.getInstance().backends.size();
        this.scheduler = Executors.newScheduledThreadPool(poolSize > 0 ? poolSize : 1);
    }

    public void startPolling() {
        int intervalMs = ConfigLoader.getInstance().healthCheckIntervalMs;

        for (String url : ConfigLoader.getInstance().backends) {
            serverState.put(url, "HEALTHY");
            successCount.put(url, 0);
            failCount.put(url, 0);

            // Ping GET /health
            // Note: If url doesn't end with slash, it might be malformed, but backends here end with /
            String healthUrl = url.endsWith("/") ? url + "health" : url + "/health";
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(healthUrl))
                .GET()
                .build();

            scheduler.scheduleWithFixedDelay(() -> {
                httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .thenAccept(response -> {
                        int status = response.statusCode();
                        if (status >= 200 && status < 400) {
                            handleSuccess(url);
                        } else {
                            handleFailure(url);
                        }
                    })
                    .exceptionally(e -> {
                        handleFailure(url);
                        return null; // CompletableFuture requires return
                    });
            }, 0, intervalMs, TimeUnit.MILLISECONDS);
        }
    }

    private void handleSuccess(String url) {
        String state = serverState.get(url);
        if ("DEAD".equals(state)) {
            int successes = successCount.get(url) + 1;
            successCount.put(url, successes);
            if (successes >= 2) {
                // Transition to HEALTHY
                serverState.put(url, "HEALTHY");
                successCount.put(url, 0);
                failCount.put(url, 0);
                System.out.println("[HealthCheck] " + url + " transitioned to HEALTHY.");
                Routing.addServer(url);
            }
        } else {
            // Already healthy, just reset fails to 0
            failCount.put(url, 0);
        }
    }

    private void handleFailure(String url) {
        String state = serverState.get(url);
        if ("HEALTHY".equals(state)) {
            int fails = failCount.get(url) + 1;
            failCount.put(url, fails);
            if (fails >= 3) {
                // Transition to DEAD
                serverState.put(url, "DEAD");
                successCount.put(url, 0);
                failCount.put(url, 0);
                System.err.println("[HealthCheck] " + url + " transitioned to DEAD!");
                Routing.evictServer(url);
            }
        } else {
            // Already dead, just reset successes to 0
            successCount.put(url, 0);
        }
    }

    public void stopPolling() {
        scheduler.shutdown();
    }
}
