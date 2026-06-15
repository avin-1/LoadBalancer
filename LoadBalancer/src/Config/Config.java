package Config;

import java.util.List;

/**
 * POJO to hold configuration loaded from config.json
 */
public class Config {
    public int proxyPort = 443;
    public int workerPoolSize = 10;
    public int rateLimitCapacity = 100;
    public int rateLimitRefill = 10;
    public int healthCheckIntervalMs = 2000;
    public List<String> backends = List.of(
        "https://localhost:3001/",
        "https://localhost:3002/",
        "https://localhost:3003/"
    );
}
