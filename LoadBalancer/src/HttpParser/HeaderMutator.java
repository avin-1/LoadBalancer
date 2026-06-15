package HttpParser;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class to efficiently mutate raw HTTP request bytes (strings) 
 * by injecting tracking headers before forwarding to backends.
 */
public class HeaderMutator {

    // Regex to match existing X-Forwarded-For header line
    private static final Pattern XFF_PATTERN = Pattern.compile("(?mi)^X-Forwarded-For\\s*:\\s*(.*?)\\r?$");

    /**
     * Mutates the raw HTTP request string by injecting/appending headers efficiently.
     * 
     * @param rawRequest The complete raw request string including \r\n\r\n
     * @param clientIp The immediate client's IP address
     * @return The mutated request string
     */
    public static String mutate(String rawRequest, String clientIp) {
        int boundaryIdx = rawRequest.indexOf("\r\n\r\n");
        if (boundaryIdx == -1) {
            // Not a complete request, cannot mutate safely
            return rawRequest;
        }

        // Split into headers and body
        String headersPart = rawRequest.substring(0, boundaryIdx);
        String bodyPart = rawRequest.substring(boundaryIdx + 4);

        // 1. Handle X-Forwarded-For
        Matcher xffMatcher = XFF_PATTERN.matcher(headersPart);
        if (xffMatcher.find()) {
            String existing = xffMatcher.group(1).trim();
            // Append the new client IP to the existing chain
            headersPart = xffMatcher.replaceFirst("X-Forwarded-For: " + existing + ", " + clientIp);
        } else {
            // Inject new X-Forwarded-For
            headersPart += "\r\nX-Forwarded-For: " + clientIp;
        }

        // 2. Inject X-Real-IP
        headersPart += "\r\nX-Real-IP: " + clientIp;

        // 3. Inject X-Forwarded-Proto (Hardcoded to https since we terminated TLS)
        headersPart += "\r\nX-Forwarded-Proto: https";

        // Stitch back together
        return headersPart + "\r\n\r\n" + bodyPart;
    }

    public static void main(String[] args) {
        String req1 = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody123";
        System.out.println("--- Without XFF ---");
        System.out.println(mutate(req1, "192.168.1.5"));

        String req2 = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 10.0.0.1\r\n\r\nbody123";
        System.out.println("\n--- With XFF ---");
        System.out.println(mutate(req2, "192.168.1.5"));
    }
}
