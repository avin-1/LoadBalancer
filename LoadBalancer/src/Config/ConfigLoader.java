package Config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A lightweight JSON bootstrapper to parse config.json without external libraries.
 */
public class ConfigLoader {
    private static Config instance = new Config(); // Defaults used initially

    public static Config getInstance() {
        return instance;
    }

    /**
     * Reads and parses a minimal JSON configuration file using Regex.
     */
    public static void load(String filePath) {
        try {
            String content = Files.readString(Path.of(filePath));
            Config newConfig = new Config();

            newConfig.proxyPort = extractInt(content, "\"proxyPort\"\\s*:\\s*(\\d+)", newConfig.proxyPort);
            newConfig.workerPoolSize = extractInt(content, "\"workerPoolSize\"\\s*:\\s*(\\d+)", newConfig.workerPoolSize);
            newConfig.rateLimitCapacity = extractInt(content, "\"rateLimitCapacity\"\\s*:\\s*(\\d+)", newConfig.rateLimitCapacity);
            newConfig.rateLimitRefill = extractInt(content, "\"rateLimitRefill\"\\s*:\\s*(\\d+)", newConfig.rateLimitRefill);
            newConfig.healthCheckIntervalMs = extractInt(content, "\"healthCheckIntervalMs\"\\s*:\\s*(\\d+)", newConfig.healthCheckIntervalMs);

            List<String> backends = new ArrayList<>();
            Pattern arrayPattern = Pattern.compile("\"backends\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL);
            Matcher arrayMatcher = arrayPattern.matcher(content);
            if (arrayMatcher.find()) {
                String arrayContent = arrayMatcher.group(1);
                Pattern stringPattern = Pattern.compile("\"([^\"]+)\"");
                Matcher stringMatcher = stringPattern.matcher(arrayContent);
                while (stringMatcher.find()) {
                    backends.add(stringMatcher.group(1));
                }
            }
            if (!backends.isEmpty()) {
                newConfig.backends = backends;
            }

            instance = newConfig;
            System.out.println("[Bootstrapper] Configuration loaded successfully from " + filePath);
        } catch (IOException e) {
            System.err.println("[Bootstrapper] Failed to read config file. Using default configuration.");
        }
    }

    private static int extractInt(String content, String regex, int defaultValue) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return defaultValue;
    }
}
