package HttpParser;

// ─────────────────────────────────────────────────────────────────────────────
// WHY HashMap:
//   HTTP headers are a collection of key-value pairs (e.g. "Host: example.com").
//   HashMap lets us look up any header by name in O(1) average time, which is
//   perfect for the load balancer's need to quickly read specific headers like
//   "Content-Type" or "Authorization" during routing decisions.
// ─────────────────────────────────────────────────────────────────────────────
import java.util.HashMap;
import java.util.Map;

/**
 * Stateless utility class that converts raw HTTP/HTTPS request text into a structured Java object.
 *
 * ═══════════════════════════════════════════════════════════════════
 * BEGINNER CONTEXT — What does a raw HTTP request look like?
 * ═══════════════════════════════════════════════════════════════════
 * When a browser (or any client) sends an HTTPS request, the server receives a
 * block of text that looks roughly like this (after TLS decryption):
 *
 *   GET /api/users HTTP/1.1\r\n
 *   Host: example.com\r\n
 *   User-Agent: Mozilla/5.0\r\n
 *   Accept: application/json\r\n
 *   \r\n
 *
 * Breaking this down:
 *   Line 1:  "GET /api/users HTTP/1.1"  → the "Request Line"
 *              │     │           │
 *              │     │           └── HTTP protocol version
 *              │     └────────────── the path/resource requested
 *              └──────────────────── the HTTP method (GET, POST, PUT, DELETE)
 *
 *   Lines 2-4: "Key: Value" pairs → HTTP headers
 *
 *   \r\n\r\n:  A blank line marks the END of the headers section.
 *              (If there's a body like JSON, it comes after this blank line.)
 *
 * HttpsParser reads this raw text and translates it into a neat Java object
 * ({@link HttpRequest}) so the rest of the load balancer can use named fields
 * (e.g., request.method, request.path) instead of messy string operations.
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY this class exists:</strong>
 * Raw HTTP requests arrive as a single unstructured {@link String} over the socket.
 * The load balancer needs a structured representation to make routing decisions
 * (e.g., "route all /api/* requests to backend A", "check the Authorization header").
 * Without parsing, every downstream component would have to do its own messy string
 * operations — error-prone and duplicated.
 *
 * <p><strong>WHAT this class provides:</strong>
 * <ul>
 *   <li>A static {@link #parse(String)} method: converts a raw request string → {@link HttpRequest}.</li>
 *   <li>A static inner class {@link HttpRequest}: the structured data container (POJO).</li>
 * </ul>
 *
 * <p><strong>HOW the parser works at a high level:</strong>
 * <ol>
 *   <li>Split the raw string by {@code \r\n} to get individual lines.</li>
 *   <li>Split the first line by space to extract: method, path, version.</li>
 *   <li>Loop through subsequent lines, splitting each by the first colon to get header key-value pairs.</li>
 *   <li>Stop parsing headers when an empty line is encountered.</li>
 *   <li>Return the populated {@link HttpRequest} object.</li>
 * </ol>
 *
 * <p><strong>Design note — why "static" methods only:</strong>
 * This class has no instance state — every parse operation is completely self-contained.
 * Making parse() static means callers don't need to create an HttpsParser instance,
 * which reduces boilerplate and makes the intent clear: this is a utility/tool, not a service.
 */
public class HttpsParser {

    /**
     * Parses a raw HTTP/HTTPS request string into a structured {@link HttpRequest} object.
     *
     * <p><strong>WHY static:</strong>
     * Parsing is a pure function — it takes an input and produces an output with no side effects
     * and no dependency on instance state. Static methods signal this intent clearly and
     * allow callers to use {@code HttpsParser.parse(rawText)} without instantiation overhead.
     *
     * <p><strong>WHAT:</strong>
     * Reads the Request Line (method, path, HTTP version) from the first line,
     * then reads all subsequent "Key: Value" header lines until a blank line is hit,
     * and returns a fully populated {@link HttpRequest} object.
     *
     * <p><strong>HOW:</strong>
     * <pre>
     * Raw text:
     *   "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{...}"
     *
     * Step 1 — split("\r\n") produces:
     *   lines[0] = "POST /submit HTTP/1.1"
     *   lines[1] = "Host: example.com"
     *   lines[2] = "Content-Type: application/json"
     *   lines[3] = ""                              ← blank line = end of headers
     *   lines[4] = "{...}"                         ← body (not parsed here)
     *
     * Step 2 — split first line by " ":
     *   requestLine[0] = "POST"
     *   requestLine[1] = "/submit"
     *   requestLine[2] = "HTTP/1.1"
     *
     * Step 3 — loop from lines[1]:
     *   "Host: example.com" → key="Host", value="example.com"
     *   "Content-Type: application/json" → key="Content-Type", value="application/json"
     *   ""                               → empty line → break out of the loop
     * </pre>
     *
     * @param raw The complete, decrypted raw HTTP request as a {@link String}.
     *            Must contain at least the Request Line followed by {@code \r\n}.
     * @return A populated {@link HttpRequest} containing method, path, version, and headers.
     */
    public static HttpRequest parse(String raw) {

        // Create a new, empty HttpRequest object to populate and return.
        HttpRequest req = new HttpRequest();

        // ── Step 1: Split the raw text by CRLF (Carriage Return + Line Feed) ──
        // HTTP/1.1 specifies that lines MUST be separated by \r\n (not just \n).
        // The split() call creates an array where each element is one line of the request.
        // Example: "GET / HTTP/1.1\r\nHost: x.com\r\n" becomes ["GET / HTTP/1.1", "Host: x.com", ""]
        String[] lines = raw.split("\r\n");

        // ── Step 2: Parse the Request Line (always the very first line, lines[0]) ──
        // The Request Line contains exactly three space-separated tokens:
        //   Token 0: HTTP Method  (e.g., "GET", "POST", "PUT", "DELETE", "PATCH")
        //   Token 1: Request Path (e.g., "/", "/api/users", "/images/logo.png")
        //   Token 2: HTTP Version (e.g., "HTTP/1.1", "HTTP/2.0")
        String[] requestLine = lines[0].split(" ");

        req.method  = requestLine[0]; // e.g., "GET"
        req.path    = requestLine[1]; // e.g., "/api/users"
        req.version = requestLine[2]; // e.g., "HTTP/1.1"

        // ── Step 3: Parse the Header Lines (lines[1] onwards) ──
        // We start at index 1 because index 0 was already consumed as the Request Line.
        for (int i = 1; i < lines.length; i++) {

            String line = lines[i];

            // An empty line signals the end of the headers section.
            // Everything after this line would be the request BODY (e.g., JSON payload).
            // We do not parse the body here, so we break immediately.
            if (line.isEmpty())
                break;

            // HTTP headers follow the format: "Header-Name: header-value"
            // We find the FIRST colon to split key from value.
            // WHY indexOf (not split): A header value can itself contain colons.
            //   Example: "Authorization: Bearer eyJhbGciO..." — we must NOT split on all colons.
            //   Using indexOf(':') gives us the position of the FIRST colon, which is the separator.
            int idx = line.indexOf(':');

            // If there's no colon on this line, it's a malformed header — skip it gracefully.
            if (idx == -1)
                continue;

            // Extract the key: everything BEFORE the colon.
            // .trim() removes any accidental leading/trailing whitespace.
            // Example: "  Host " → "Host"
            String key = line.substring(0, idx).trim();

            // Extract the value: everything AFTER the colon.
            // We add 1 to idx to skip past the colon itself.
            // .trim() handles the standard space after the colon (e.g., "Host: example.com").
            // Example: " example.com " → "example.com"
            String value = line.substring(idx + 1).trim();

            // Store the key-value pair in the headers HashMap.
            // Downstream code can later retrieve specific headers like:
            //   String host = request.headers.get("Host");
            req.headers.put(key, value);
        }

        // Return the fully populated request object.
        return req;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INNER CLASS: HttpRequest
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * A simple Plain Old Java Object (POJO) holding the structured data of one HTTP request.
     *
     * <p><strong>WHY a POJO (not a record or builder):</strong>
     * A public POJO with public fields is the simplest possible data container for a
     * load balancer where multiple downstream components will read and potentially
     * annotate the request object. It has minimal boilerplate, is readable, and
     * requires no getters/setters for a straightforward internal model.
     *
     * <p><strong>WHAT:</strong>
     * Bundles the five key pieces of an HTTP request into one easy-to-pass object:
     * method, path, HTTP version, headers map, and optional body.
     *
     * <p><strong>HOW it is used:</strong>
     * After calling {@link HttpsParser#parse(String)}, the server accesses fields directly:
     * <pre>
     *   HttpRequest req = HttpsParser.parse(rawText);
     *   if (req.method.equals("POST") &amp;&amp; req.path.startsWith("/api")) {
     *       String contentType = req.headers.get("Content-Type");
     *       // route to backend API server...
     *   }
     * </pre>
     */
    public static class HttpRequest {

        /**
         * The HTTP method used for this request.
         *
         * WHY it matters for a load balancer:
         *   Routing rules often differentiate by method. For example:
         *   - GET requests are idempotent and can be routed to any backend replica.
         *   - POST/PUT/DELETE requests may need to be routed to a specific backend
         *     that has the latest data (or supports write operations).
         *
         * Examples: "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
         */
        public String method;

        /**
         * The path (URL) the client is requesting on the server.
         *
         * WHY it matters for a load balancer:
         *   Path-based routing is one of the most common load balancing strategies:
         *   - Requests to "/api/*" → Route to the API backend cluster
         *   - Requests to "/static/*" → Serve directly from a CDN or static server
         *   - Requests to "/admin/*" → Route only to the privileged admin backend
         *
         * Examples: "/", "/index.html", "/api/users/123", "/images/logo.png"
         */
        public String path;

        /**
         * The HTTP protocol version declared by the client.
         *
         * WHY it matters:
         *   HTTP/1.0 connections close after every request (no keep-alive by default).
         *   HTTP/1.1 keeps connections alive for multiple requests (persistent connections).
         *   HTTP/2.0 uses multiplexed binary frames. The load balancer must handle these
         *   differently when deciding whether to reuse backend connections.
         *
         * Examples: "HTTP/1.0", "HTTP/1.1", "HTTP/2.0"
         */
        public String version;

        /**
         * A map of all HTTP request headers, indexed by header name.
         *
         * WHY HashMap:
         *   Headers are accessed by name (e.g., "Host", "Content-Type"), so a Map
         *   provides O(1) average lookup time. The map is pre-initialized here so
         *   the parse() method can call headers.put() without any null check.
         *
         * Examples of common headers and their load balancing significance:
         *   - "Host"           → Which virtual host (domain) the client is targeting
         *   - "Authorization"  → Bearer tokens / API keys for auth-based routing
         *   - "Content-Length" → Request body size (needed before reading the body)
         *   - "Connection"     → Whether the client wants keep-alive or close
         *   - "X-Forwarded-For"→ The original client IP when proxied through multiple layers
         */
        public Map<String, String> headers = new HashMap<>();

        /**
         * The optional request body (payload) sent by the client.
         *
         * WHY optional:
         *   GET and HEAD requests typically have NO body. POST, PUT, and PATCH requests
         *   typically carry a body (JSON, form data, file upload). Since the parse()
         *   method currently only parses headers (not the body), this field remains null
         *   unless populated by the caller after additional reading from the socket.
         *
         * Examples: JSON string, URL-encoded form data, multipart boundary data.
         */
        public String body;
    }
}