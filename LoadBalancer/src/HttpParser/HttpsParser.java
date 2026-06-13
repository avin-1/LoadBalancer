package HttpParser;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility parser that converts raw HTTP request plaintext into structured objects.
 *
 * <p><strong>WHY:</strong>
 * Raw HTTP requests arrive as unstructured plain text over raw socket channels. The load balancer
 * needs a structured representation of request attributes (such as the requested path and headers)
 * to perform validation and routing decisions.
 *
 * <p><strong>WHAT:</strong>
 * Provides static parsing logic to translate raw HTTP string data into a structured {@link HttpRequest} model.
 *
 * <p><strong>HOW:</strong>
 * Splices lines by carriage-return line-feeds, processes the Request Line to extract key variables (Method, Path, Version),
 * and parses subsequent header lines into a key-value Map.
 */
public class HttpsParser {

    /**
     * Translates raw HTTP string bytes into a Java-friendly HttpRequest container.
     *
     * <p><strong>WHY:</strong>
     * HTTP protocol dictates a strict format containing a header metadata block separated by colon tokens
     * and carriage returns. The server requires parsing these constraints to retrieve parameters.
     *
     * <p><strong>WHAT:</strong>
     * Parses the HTTP Request Line and maps headers into key-value entries.
     *
     * <p><strong>HOW:</strong>
     * Splices text using {@code \r\n} segments. Reads the first line to populate the method, path, and version fields.
     * Loops through subsequent rows, locating the first colon index to store the trimmed key-value pairs into a map
     * until an empty line is detected.
     *
     * @param raw The raw text of the HTTP request.
     * @return An HttpRequest object containing the method, path, HTTP version, and headers.
     */
    public static HttpRequest parse(String raw) {

        HttpRequest req = new HttpRequest();

        // Step 1: Split the raw request by Carriage Return Line Feed (\r\n) to get individual lines.
        String[] lines = raw.split("\r\n");

        // Step 2: The very first line is the Request Line (e.g. "GET /index.html HTTP/1.1").
        // We split it by space to separate the Method, Path, and HTTP Version.
        String[] requestLine =
                lines[0].split(" ");

        req.method = requestLine[0];  // e.g. "GET", "POST", etc.
        req.path = requestLine[1];    // e.g. "/index.html", "/api/data", etc.
        req.version = requestLine[2]; // e.g. "HTTP/1.1"

        // Step 3: Loop through the remaining lines starting from index 1 to extract the headers.
        for (int i = 1; i < lines.length; i++) {

            String line = lines[i];

            // If we hit an empty line, that means we've reached the end of the HTTP headers.
            if (line.isEmpty())
                break;

            // Headers are formatted as "Key: Value". Find the colon character separating them.
            int idx = line.indexOf(':');

            // If there's no colon on this line, skip it as it's not a valid header.
            if (idx == -1)
                continue;

            // Extract the key (before the colon) and the value (after the colon).
            // We use .trim() to clean up any leading or trailing spaces.
            String key =
                    line.substring(0, idx).trim();

            String value =
                    line.substring(idx + 1).trim();

            // Store the header key-value pair in our request headers map.
            req.headers.put(key, value);
        }

        return req;
    }

    /**
     * Plain Old Java Object (POJO) representing the structured metadata of an HTTP request.
     *
     * <p><strong>WHY:</strong>
     * The server requires a lightweight, reusable container to pass parsed request details through downstream proxy layers.
     *
     * <p><strong>WHAT:</strong>
     * Contains properties for method, path, protocol version, headers map, and optional payload body.
     *
     * <p><strong>HOW:</strong>
     * Exposes public properties and initializes a {@link HashMap} for header indexing.
     */
    public static class HttpRequest {

        // The HTTP method used (e.g. GET, POST, PUT, DELETE)
        public String method;
        
        // The path requested on the server (e.g. "/index.html", "/users")
        public String path;
        
        // The version of the HTTP protocol used (e.g. "HTTP/1.1")
        public String version;

        // A map to store header keys and values (e.g. Host, User-Agent, Content-Type)
        public Map<String, String> headers =
                new HashMap<>();

        // An optional body that might contain data sent to the server (like form entries)
        public String body;
    }
}