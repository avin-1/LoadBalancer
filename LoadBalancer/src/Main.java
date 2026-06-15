// ═══════════════════════════════════════════════════════════════════════════
// FILE: Main.java
//
// WHAT THIS FILE IS:
//   The entry point and heart of the entire HTTPS Load Balancer. This single
//   file bootstraps the server, manages all client connections, and orchestrates
//   the TLS (Transport Layer Security) encryption state machine.
//
// WHY ONE BIG FILE:
//   The ClientHandler inner class lives here alongside Main because it needs
//   direct access to the shared sslContext, workerPool, and selectorTasks fields.
//   In a production codebase, ClientHandler would be refactored into its own file.
//
// HOW THE SERVER WORKS AT A HIGH LEVEL:
//   Traditional "blocking" servers use one OS thread per client connection.
//   If 10,000 clients connect, you need 10,000 threads — each consuming ~1MB of
//   stack memory → 10 GB of RAM just for idle threads. This doesn't scale.
//
//   This server uses Java NIO (Non-blocking I/O) with a Selector:
//     • A SINGLE thread monitors ALL connected client sockets simultaneously.
//     • The Selector notifies the server loop only when a socket has data to read
//       or is ready to accept bytes for writing.
//     • CPU-intensive cryptographic work (TLS handshake) is offloaded to a
//       separate worker thread pool, keeping the selector loop free to process
//       other events.
//
//   This allows ONE thread to handle thousands of concurrent connections efficiently.
// ═══════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// IMPORTS — Why each package is needed
// ─────────────────────────────────────────────────────────────────────────────

// HttpsParser: Our own HTTP request parser from the HttpParser package.
// Used to convert raw decrypted bytes into a structured HttpRequest object.
import HttpParser.HttpsParser;

// javax.net.ssl.*: Java's SSL/TLS API.
//   SSLContext:        The factory for SSLEngine instances (holds the server certificate).
//   SSLEngine:         Performs TLS encryption/decryption for ONE specific connection.
//   SSLEngineResult:   The result object returned after each wrap/unwrap operation,
//                      containing the new handshake status and bytes consumed/produced.
//   SSLException:      Thrown when the TLS negotiation fails (bad certificate, wrong protocol, etc.)
//   SSLSession:        The negotiated TLS session — used to get recommended buffer sizes.
import javax.net.ssl.*;

// java.io.*: For reading the keystore file from disk.
import java.io.*;

// java.net.*: For InetSocketAddress (IP + port) and InetAddress (getting client IP string).
import java.net.*;

// java.nio.*: Java's Non-blocking I/O (NIO) library.
//   ByteBuffer:        A fixed-size buffer for raw bytes. All NIO I/O goes through ByteBuffers.
import java.nio.*;

// java.nio.channels.*: The NIO channel types.
//   Selector:              Monitors multiple channels for readiness events (accept, read, write).
//   ServerSocketChannel:   Listens for incoming TCP connections (like a server socket).
//   SocketChannel:         A connected TCP socket channel for one specific client.
//   SelectionKey:          Represents the registration of one channel with a Selector.
//                          Holds interest-ops (what events to watch) and an attachment object.
import java.nio.channels.*;

// KeyStore: Manages the server's TLS certificate and private key (loaded from keystore.jks).
import java.security.KeyStore;

// Iterator: For safely removing SelectionKeys while iterating the selected-keys set.
import java.util.Iterator;

// Queue + ConcurrentLinkedQueue: Thread-safe FIFO queue used to pass tasks from worker
// threads back to the main Selector thread without locks.
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

// ExecutorService + Executors: For creating the worker thread pool that runs TLS delegated tasks.
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main entry point and event loop driver for the non-blocking HTTPS Load Balancer server.
 *
 * ═══════════════════════════════════════════════════════════════════
 * SYSTEM ARCHITECTURE OVERVIEW
 * ═══════════════════════════════════════════════════════════════════
 *
 *   [Client Browser]
 *       │  TCP + TLS (HTTPS)
 *       ▼
 *   ┌─────────────────────────────────────────────────────┐
 *   │              Main (Selector Thread)                  │
 *   │                                                     │
 *   │  ┌──────────────┐   OP_ACCEPT   ┌───────────────┐  │
 *   │  │ ServerSocket │─────────────▶│  accept()      │  │
 *   │  │    :8443     │               │  creates       │  │
 *   │  └──────────────┘               │  ClientHandler │  │
 *   │                                 └───────┬───────┘  │
 *   │                                         │           │
 *   │       OP_READ / OP_WRITE events          │           │
 *   │       ┌──────────────────────────────────┘           │
 *   │       ▼                                              │
 *   │  ┌────────────────────────────────────────────────┐  │
 *   │  │  ClientHandler (one per client connection)     │  │
 *   │  │                                                │  │
 *   │  │  handleRead()   ──▶  processHandshake()        │  │
 *   │  │                 ──▶  processDataRead()         │  │
 *   │  │  handleWrite()  ──▶  flush myNetData to socket │  │
 *   │  └────────────────────────────────────────────────┘  │
 *   │                          │ NEED_TASK                  │
 *   │                          ▼                            │
 *   │           ┌──────────────────────────┐                │
 *   │           │    Worker Thread Pool    │                │
 *   │           │  (runs delegated TLS     │                │
 *   │           │   CPU-intensive tasks)   │                │
 *   │           └──────────────────────────┘                │
 *   └─────────────────────────────────────────────────────┘
 *
 * ═══════════════════════════════════════════════════════════════════
 *
 * <p><strong>WHY non-blocking I/O (NIO Selector) instead of one-thread-per-connection:</strong>
 * A server handling 10,000 concurrent HTTPS connections would need 10,000 OS threads
 * with the blocking model — consuming ~10GB of RAM just for thread stacks, plus
 * massive context-switching overhead. NIO with a Selector lets ONE thread monitor
 * all sockets simultaneously, consuming memory proportional to actual DATA (not idle threads).
 *
 * <p><strong>WHAT this class sets up:</strong>
 * <ol>
 *   <li>Loads the server's TLS certificate from {@code keystore.jks}.</li>
 *   <li>Initializes an {@link SSLContext} used to create per-connection {@link SSLEngine} instances.</li>
 *   <li>Creates a fixed worker thread pool for CPU-intensive TLS delegated tasks.</li>
 *   <li>Opens a non-blocking {@link ServerSocketChannel} on port 8443.</li>
 *   <li>Runs an infinite event loop: drains queued tasks → wait for Selector events → dispatch.</li>
 * </ol>
 *
 * <p><strong>HOW the four types of events are handled in the loop:</strong>
 * <ul>
 *   <li><strong>OP_ACCEPT</strong>: A new client is connecting → call {@link #accept}.</li>
 *   <li><strong>OP_READ</strong>:   A client sent data → call {@link ClientHandler#handleRead()}.</li>
 *   <li><strong>OP_WRITE</strong>:  A client socket is ready to receive our response → call {@link ClientHandler#handleWrite()}.</li>
 *   <li><strong>selectorTasks queue</strong>: Worker threads post callbacks here to resume
 *       handshakes on the Selector thread after finishing CPU-heavy delegated tasks.</li>
 * </ul>
 */
public class Main {

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTANTS
    // ─────────────────────────────────────────────────────────────────────────

    // The HTTPS port the load balancer listens on.
    // WHY 8443 (not 443): Port 443 is the standard HTTPS port, but binding to it
    // requires root/administrator privileges on most operating systems. Port 8443
    // is the standard development alternative that doesn't require elevated privileges.
    private static final int PORT = 8443;

    // Primary path to the keystore file (relative to the current working directory).
    // The keystore contains the server's TLS certificate and private key.
    private static final String KEYSTORE_FILE = "keystore.jks";

    // Fallback path used when running from an IDE where the working directory
    // may be the project root rather than the src/ directory.
    private static final String KEYSTORE_FALLBACK = "HttpParser/keystore.jks";

    // The password protecting the keystore file and its private key entries.
    // WHY "password": This is a development default. In production, this must be
    // loaded from environment variables, a secrets manager (HashiCorp Vault, AWS Secrets Manager),
    // or a secure configuration file — NEVER hardcoded in source code.
    private static final String KEYSTORE_PASSWORD = "password";

    // ─────────────────────────────────────────────────────────────────────────
    // SHARED STATE (accessed by both the Selector thread and worker threads)
    // ─────────────────────────────────────────────────────────────────────────

    // The SSL context holds the server's certificate and creates SSLEngine instances.
    // It is initialized once in main() and then used by accept() for every new connection.
    // WHY static: The context is shared across all connections on the same server process.
    private static SSLContext sslContext;

    // The thread pool for CPU-intensive TLS delegated tasks (e.g., RSA key decryption).
    // WHY static: Shared across all ClientHandler instances so we don't create a new pool
    // for every connection (pool creation is expensive).
    private static ExecutorService workerPool;

    /**
     * Thread-safe bridge between worker threads and the Selector thread.
     *
     * <p><strong>WHY this queue exists (the "cross-thread callback" problem):</strong>
     * The TLS handshake state machine has a {@code NEED_TASK} state where the SSLEngine
     * requires a CPU-intensive delegated task (e.g., certificate chain validation, RSA
     * private key operations). We offload these to the worker pool to keep the Selector
     * thread free. BUT when the task finishes, we need to RESUME the handshake on the
     * Selector thread (because modifying SSLEngine and ByteBuffer state from multiple
     * threads simultaneously would be a race condition).
     *
     * <p>The solution: the worker thread, after completing its CPU task, adds a lambda
     * (Runnable) to this queue that says "resume the handshake for connection X". The
     * Selector thread drains this queue at the TOP of every loop iteration and runs
     * those lambdas before processing new I/O events.
     *
     * <p><strong>WHY ConcurrentLinkedQueue:</strong>
     * Multiple worker threads may complete their tasks simultaneously and try to add
     * to this queue at the same time. ConcurrentLinkedQueue is a lock-free, thread-safe
     * FIFO queue that supports concurrent producers (worker threads) and a single consumer
     * (the Selector thread).
     */
    private static final Queue<Runnable> selectorTasks = new ConcurrentLinkedQueue<>();

    // ─────────────────────────────────────────────────────────────────────────
    // MAIN METHOD — THE SERVER BOOTSTRAP
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The JVM entry point — bootstraps and runs the server until interrupted.
     *
     * <p><strong>WHY each step is in this specific order:</strong>
     * SSL context must be ready before creating any SSLEngine. Worker pool must exist
     * before any NEED_TASK event can be submitted. The channel must be bound before
     * registering with the Selector. The event loop must run last (it's an infinite loop).
     *
     * <p><strong>WHAT:</strong>
     * Sets up all resources (keystore, SSLContext, thread pool, server channel, Selector)
     * and runs the central NIO event dispatch loop indefinitely.
     *
     * <p><strong>HOW — the event loop in detail:</strong>
     * <pre>
     * EVERY ITERATION:
     *   1. Drain selectorTasks queue (run any pending handshake-resume callbacks)
     *   2. selector.select() — BLOCK until at least one channel has a ready event
     *   3. For each ready SelectionKey:
     *      a. Remove it from the selected-keys set (prevent double-processing)
     *      b. Skip if invalid (channel was closed)
     *      c. Route to: accept() / handleRead() / handleWrite()
     * </pre>
     *
     * @param args Command-line arguments (not used in this implementation).
     * @throws Exception If keystore loading, SSL initialization, or channel binding fails.
     */
    public static void main(String[] args) throws Exception {

        // ════════════════════════════════════════════════════════════════
        // STEP 1: Load the TLS Certificate Keystore from disk
        // ════════════════════════════════════════════════════════════════
        //
        // WHY a keystore: HTTPS requires the server to prove its identity to clients
        // by presenting a digital certificate (think of it as the server's "passport").
        // The certificate and its corresponding private key are stored in a .jks file
        // (Java KeyStore format). The private key is protected by the keystore password.
        //
        // WHY check two paths: Depending on whether you run the server from the command
        // line (working dir = src/) or from an IDE (working dir = project root/), the
        // relative path to keystore.jks differs. We check both and fall back gracefully.

        KeyStore ks = KeyStore.getInstance("JKS"); // "JKS" = Java KeyStore format

        // Try primary path first (src/keystore.jks), then fallback (src/HttpParser/keystore.jks)
        File keystoreFile = new File(KEYSTORE_FILE);
        if (!keystoreFile.exists()) {
            keystoreFile = new File(KEYSTORE_FALLBACK);
        }

        // If neither path has the keystore, print an error and exit immediately.
        // The server CANNOT start without its TLS certificate — HTTPS is impossible.
        if (!keystoreFile.exists()) {
            System.err.println("Error: Keystore file 'keystore.jks' not found.");
            System.exit(1);
        }

        // Load the keystore from the file. The try-with-resources block ensures the
        // FileInputStream is closed automatically even if ks.load() throws an exception.
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ks.load(fis, KEYSTORE_PASSWORD.toCharArray()); // toCharArray() for security (char[] is erasable; String is not)
        }

        // ════════════════════════════════════════════════════════════════
        // STEP 2: Initialize the SSLContext with the server's certificate
        // ════════════════════════════════════════════════════════════════
        //
        // WHY KeyManagerFactory:
        //   SSLContext doesn't directly accept a KeyStore. KeyManagerFactory is the adapter
        //   that reads the certificate + private key from the KeyStore and provides it to
        //   the SSLContext in the format it expects. The algorithm "SunX509" (or the JVM default)
        //   specifies which key management algorithm to use.
        //
        // WHY sslContext.init(kmf.getKeyManagers(), null, null):
        //   - First arg (KeyManagers): Provides the server certificate to clients.
        //   - Second arg (TrustManagers): null = use JVM default (trust public CAs).
        //     We don't need custom trust on the SERVER side for client verification here.
        //   - Third arg (SecureRandom): null = JVM picks the best available SecureRandom.

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        // ════════════════════════════════════════════════════════════════
        // STEP 3: Create the Worker Thread Pool
        // ════════════════════════════════════════════════════════════════
        //
        // WHY a thread pool for TLS tasks:
        //   During the TLS handshake, the SSLEngine may generate a NEED_TASK status.
        //   These delegated tasks perform CPU-intensive operations like:
        //     - RSA private key decryption (key exchange)
        //     - Certificate chain validation
        //   Running these on the Selector thread would BLOCK the entire server from
        //   accepting or reading any other events for the duration of the computation.
        //
        // WHY availableProcessors() * 2:
        //   A common heuristic for CPU-bound work: use N threads per CPU core (where N=2
        //   here) to allow one thread to be "active" while another waits for CPU cache or
        //   memory, improving overall CPU utilization. For I/O-bound tasks, a higher
        //   multiplier would be used.

        workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);

        // ════════════════════════════════════════════════════════════════
        // STEP 4: Create and configure the NIO Selector and Server Channel
        // ════════════════════════════════════════════════════════════════
        //
        // WHY Selector.open():
        //   The Selector is the multiplexer — it monitors multiple channels at once.
        //   A single call to selector.select() can block until ANY of the registered
        //   channels is ready, regardless of how many there are.
        //
        // WHY ServerSocketChannel.open():
        //   ServerSocketChannel is the NIO equivalent of java.net.ServerSocket.
        //   It listens for incoming TCP connection requests.
        //
        // WHY configureBlocking(false):
        //   In blocking mode, serverChannel.accept() would BLOCK the thread until a
        //   client connects. We need non-blocking mode so the Selector can manage
        //   timing — it tells us WHEN a connection is ready to accept.
        //
        // WHY register with OP_ACCEPT:
        //   This tells the Selector: "I care about incoming connection requests on this channel."
        //   The Selector will include this key in selectedKeys() only when a client is ready
        //   to be accepted.

        Selector selector = Selector.open();
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);                       // Non-blocking mode
        serverChannel.bind(new InetSocketAddress(PORT));              // Bind to port 8443
        serverChannel.register(selector, SelectionKey.OP_ACCEPT);    // Listen for connections

        System.out.println("Java NIO Selector-based HTTPS Server Running on port " + PORT);

        // ════════════════════════════════════════════════════════════════
        // STEP 5: THE MAIN EVENT LOOP
        // ════════════════════════════════════════════════════════════════
        //
        // WHY !Thread.currentThread().isInterrupted():
        //   This is the standard Java idiom to keep a loop running "forever" while still
        //   being interruptible. When the server needs to shut down (e.g., Ctrl+C sends
        //   SIGINT, which sets the interrupt flag), the loop exits cleanly.

        while (!Thread.currentThread().isInterrupted()) {

            // ── Phase A: Drain the Cross-Thread Task Queue ──────────────────
            //
            // WHY drain the queue FIRST (before selector.select()):
            //   Worker threads post callbacks here to resume handshakes on this thread.
            //   If we called selector.select() FIRST, we might block on it before ever
            //   processing a handshake-resume callback, causing the handshake to stall.
            //   Draining first guarantees pending callbacks run in the current iteration.
            //
            // WHY poll() in a while loop (not a for-each):
            //   poll() removes and returns the head element, or returns null if empty.
            //   This loop runs all pending tasks atomically until the queue is drained.

            Runnable task;
            while ((task = selectorTasks.poll()) != null) {
                try {
                    task.run(); // Execute the handshake-resume callback on this (Selector) thread
                } catch (Exception e) {
                    System.err.println("Error running selector task: " + e.getMessage());
                }
            }

            // ── Phase B: Wait for I/O Events ────────────────────────────────
            //
            // selector.select() BLOCKS until at least one registered channel is ready.
            // It returns the NUMBER of channels that became ready.
            // After it returns, selector.selectedKeys() contains those ready keys.
            //
            // WHY not select(timeout): A timeout would cause unnecessary wakeups even
            // when no events occurred. We use selector.wakeup() explicitly from worker
            // threads when they post to selectorTasks, which unblocks select() exactly
            // when needed.

            selector.select();

            // ── Phase C: Dispatch Ready Events ──────────────────────────────
            //
            // WHY use an Iterator with keys.remove():
            //   The Selector does NOT automatically remove processed keys from the
            //   selectedKeys set. If we don't remove each key after processing it,
            //   it will appear AGAIN in the next iteration of the outer loop, causing
            //   us to try to read/accept the same key infinitely. keys.remove() removes
            //   it from the CURRENT iteration's set (the selectedKeys set), not from
            //   the selector itself (the channel remains registered).

            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove(); // CRITICAL: always remove before processing to prevent re-triggering

                // Skip keys that have been cancelled (e.g., channel was closed since last select).
                if (!key.isValid()) continue;

                try {
                    if (key.isAcceptable()) {
                        // ── A new client is trying to connect ──────────────────────────
                        // The ServerSocketChannel has a pending incoming connection.
                        // Call accept() to create a new SocketChannel for this client.
                        accept(key, selector);

                    } else if (key.isReadable()) {
                        // ── An existing client sent data we can now read ───────────────
                        // The key's attachment is the ClientHandler object for this client.
                        // We cast key.attachment() to ClientHandler and call handleRead().
                        ClientHandler handler = (ClientHandler) key.attachment();
                        handler.handleRead();

                    } else if (key.isWritable()) {
                        // ── An existing client's output buffer has space for our response ──
                        // The key's attachment is the ClientHandler for this client.
                        // We call handleWrite() to flush pending encrypted response bytes.
                        ClientHandler handler = (ClientHandler) key.attachment();
                        handler.handleWrite();
                    }
                } catch (Exception e) {
                    // Any unhandled exception on a specific key means the connection is broken.
                    // Close it to release the socket and remove it from the Selector.
                    // We catch broadly here so one broken connection can't crash the entire server.
                    System.err.println("Error handling connection key: " + e.getMessage());
                    closeKey(key);
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SERVER-LEVEL HELPER METHODS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Accepts a new incoming TCP client connection and prepares it for TLS.
     *
     * <p><strong>WHY a separate accept() method:</strong>
     * Keeping the accept logic separate from the event loop body makes the loop
     * readable (3 clear event types) and the accept logic testable in isolation.
     *
     * <p><strong>WHAT:</strong>
     * Accepts the TCP connection, configures it as non-blocking, creates a per-connection
     * SSLEngine, builds a {@link ClientHandler} to manage this connection's state,
     * registers the socket with the Selector for read events, and starts the TLS handshake.
     *
     * <p><strong>HOW:</strong>
     * <ol>
     *   <li>{@code server.accept()} → accepts the pending connection, returns the client {@link SocketChannel}.</li>
     *   <li>{@code configureBlocking(false)} → switches to non-blocking mode for NIO operations.</li>
     *   <li>{@code sslContext.createSSLEngine()} → creates a new SSLEngine for THIS connection's TLS session.</li>
     *   <li>{@code engine.setUseClientMode(false)} → we are the SERVER, not the initiating CLIENT.</li>
     *   <li>{@code engine.beginHandshake()} → primes the SSLEngine to start generating handshake messages.</li>
     *   <li>{@code new ClientHandler(...)} → creates the per-connection state machine object.</li>
     *   <li>{@code client.register(selector, OP_READ, handler)} → registers the client socket with the
     *       Selector and attaches the handler so we can retrieve it in the event loop.</li>
     *   <li>{@code handler.processHandshake()} → kicks off the first step of the TLS handshake.</li>
     * </ol>
     *
     * @param key      The SelectionKey for the ServerSocketChannel (already flagged isAcceptable).
     * @param selector The Selector to register the new client channel with.
     * @throws IOException If accepting or configuring the channel fails.
     */
    private static void accept(SelectionKey key, Selector selector) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();

        // Accept the pending connection. Returns null if no connection is pending
        // (can happen in rare race conditions with non-blocking accept).
        SocketChannel client = server.accept();
        if (client == null) return;

        // Switch the client channel to non-blocking mode.
        // WHY: The Selector requires non-blocking channels. In blocking mode, read()
        // and write() would block the Selector thread indefinitely.
        client.configureBlocking(false);

        // Create a unique SSLEngine for this specific connection.
        // WHY unique per connection: Each SSLEngine holds the cryptographic state
        // (session keys, sequence numbers, handshake progress) for ONE TLS session.
        // Sharing an engine between connections would corrupt both sessions.
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(false); // We are the SERVER receiving this TLS connection
        engine.beginHandshake();        // Prime the engine to begin the handshake sequence

        // Create the per-connection state manager and register it with the selector.
        // The third argument to register() is the "attachment" — an arbitrary object
        // stored on the SelectionKey. We store the ClientHandler here so the event loop
        // can retrieve it via key.attachment() and call handleRead()/handleWrite().
        ClientHandler handler = new ClientHandler(client, engine);
        SelectionKey clientKey = client.register(selector, SelectionKey.OP_READ, handler);
        handler.setKey(clientKey); // Give the handler a reference to its own key (for interest-op changes)

        // Begin the first step of the TLS handshake (likely NEED_WRAP → server sends ClientHello response)
        handler.processHandshake();
    }

    /**
     * Safely closes a SelectionKey and its associated channel.
     *
     * <p><strong>WHY a centralized close helper:</strong>
     * Proper cleanup requires both cancelling the SelectionKey AND closing the SocketChannel.
     * If we only cancel the key, the OS socket file descriptor leaks. If we only close the
     * channel, the cancelled key might still appear in selectedKeys causing NPEs. Centralizing
     * this in one method ensures we always do both steps together.
     *
     * <p><strong>WHAT:</strong>
     * Delegates to {@link ClientHandler#close()} if a handler is attached (which handles
     * both channel.close() and key.cancel() gracefully), otherwise closes the raw channel.
     *
     * @param key The SelectionKey to close (may be null).
     */
    private static void closeKey(SelectionKey key) {
        if (key == null) return;
        ClientHandler handler = (ClientHandler) key.attachment();
        if (handler != null) {
            handler.close(); // ClientHandler.close() handles both channel close and key cancellation
        } else {
            // No handler attached (shouldn't happen, but handle defensively)
            try {
                key.channel().close();
            } catch (IOException ignored) {}
            key.cancel();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INNER CLASS: ClientHandler
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encapsulates ALL state and logic for a SINGLE client connection's lifecycle.
     *
     * ═══════════════════════════════════════════════════════════════
     * BEGINNER CONTEXT — Why does each connection need its own object?
     * ═══════════════════════════════════════════════════════════════
     * In an NIO server, reads and writes happen in small chunks — there is NO
     * guarantee that a single call to channel.read() gives you the ENTIRE HTTP
     * request. The data may arrive in multiple separate read events.
     *
     * Between those events, the server is handling other clients. So we need
     * a PERSISTENT STATE OBJECT per client that holds:
     *   - The ByteBuffers accumulating data between events
     *   - The SSLEngine with the TLS session state
     *   - Whether the TLS handshake is complete
     *   - The partial raw HTTP request text received so far
     *
     * The ClientHandler is that state object. It is created in accept(),
     * stored as the SelectionKey's attachment, and retrieved by the event loop
     * on every subsequent read/write event for this client.
     * ═══════════════════════════════════════════════════════════════
     *
     * <p><strong>WHY an inner class (not a top-level class):</strong>
     * ClientHandler needs access to {@code workerPool} and {@code selectorTasks}
     * — both declared as private static fields of {@code Main}. As a static inner class,
     * it has direct access to these. Making it top-level would require passing these
     * as constructor parameters or making them public.
     *
     * <p><strong>WHAT this class manages:</strong>
     * <ul>
     *   <li>The {@link SocketChannel} for raw TCP byte I/O.</li>
     *   <li>The {@link SSLEngine} for TLS encryption/decryption.</li>
     *   <li>Four {@link ByteBuffer}s for the four data directions (see below).</li>
     *   <li>The accumulated raw HTTP request string.</li>
     *   <li>The handshake state machine via {@link #processHandshake()}.</li>
     *   <li>Post-handshake data reading via {@link #processDataRead()}.</li>
     * </ul>
     *
     * <p><strong>HOW the four ByteBuffers are organized:</strong>
     * <pre>
     *   INCOMING PATH (client → server):
     *   [Network]──raw TLS bytes──▶[peerNetData]──SSLEngine.unwrap()──▶[peerAppData]──▶ HTTP parser
     *
     *   OUTGOING PATH (server → client):
     *   HTTP response ──▶[myAppData]──SSLEngine.wrap()──▶[myNetData]──encrypted bytes──▶[Network]
     * </pre>
     * <ul>
     *   <li>{@code peerNetData}: Encrypted bytes received FROM the client (raw TLS records).</li>
     *   <li>{@code peerAppData}: Decrypted plaintext AFTER the SSLEngine processes peerNetData.</li>
     *   <li>{@code myAppData}:   Plaintext bytes WE want to send TO the client (HTTP response).</li>
     *   <li>{@code myNetData}:   Encrypted bytes AFTER wrapping myAppData — sent to the client.</li>
     * </ul>
     */
    static class ClientHandler {

        private final SocketChannel channel; // The TCP socket for this specific client
        private final SSLEngine engine;      // The TLS session engine for this connection
        private SelectionKey key;            // This connection's registration with the Selector

        // ── The four ByteBuffers ──────────────────────────────────────────────
        //
        // WHY ByteBuffer and not byte[]:
        //   ByteBuffer is the standard container for NIO I/O. It tracks position, limit,
        //   and capacity, making it safe to partially read/write without manual index tracking.
        //   flip() switches it from write-mode to read-mode; compact() keeps unread bytes and
        //   switches back to write-mode — critical for streaming protocol parsing.

        private final ByteBuffer myNetData;   // Encrypted outgoing data (ready to write to socket)
        private final ByteBuffer peerNetData; // Encrypted incoming data (just read from socket)
        private final ByteBuffer myAppData;   // Plaintext outgoing data (to be encrypted)
        private final ByteBuffer peerAppData; // Plaintext incoming data (just decrypted)

        // Accumulates the raw HTTP request text across multiple read events.
        // WHY StringBuilder (not String): String is immutable — appending to it creates a new
        // String object on every append. StringBuilder is a mutable buffer that appends efficiently.
        private final StringBuilder rawRequest = new StringBuilder();

        // Tracks whether we've completed the TLS handshake for this connection.
        // Before this is true, we route all read events to processHandshake().
        // After this is true, we route read events to processDataRead().
        private boolean handshakeComplete = false;

        // Prevents close() from being called multiple times (which would throw on the second
        // channel.close() call and the second key.cancel() call).
        private boolean isClosing = false;

        // A shared lock object for the handshake state machine.
        // WHY needed: When we offload a NEED_TASK to the worker pool, the worker thread
        // posts a lambda to selectorTasks. That lambda calls processHandshake() from the
        // Selector thread. We synchronize on this lock to ensure only ONE thread (either
        // the Selector thread or a callback) is inside the handshake state machine at a time.
        private final Object handshakeLock = new Object();

        /**
         * Constructs a new ClientHandler for an accepted connection.
         *
         * <p><strong>WHY use SSLSession buffer sizes (not arbitrary sizes):</strong>
         * The SSLEngine has specific requirements on buffer sizes based on the negotiated
         * TLS parameters (cipher suite, record size limits). Using
         * {@code session.getPacketBufferSize()} for network buffers and
         * {@code session.getApplicationBufferSize()} for app buffers guarantees that
         * no "BUFFER_OVERFLOW" results occur due to under-sized buffers during normal operation.
         *
         * @param channel The accepted, non-blocking {@link SocketChannel} for this client.
         * @param engine  The {@link SSLEngine} configured as server-mode for this connection.
         */
        public ClientHandler(SocketChannel channel, SSLEngine engine) {
            this.channel = channel;
            this.engine = engine;

            // Query the SSL session for recommended buffer sizes.
            // getPacketBufferSize():       Maximum size of a raw TLS record (encrypted).
            // getApplicationBufferSize():  Maximum size of decrypted application data per record.
            SSLSession session = engine.getSession();
            this.myNetData   = ByteBuffer.allocate(session.getPacketBufferSize());
            this.peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
            this.myAppData   = ByteBuffer.allocate(session.getApplicationBufferSize());
            this.peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        }

        /**
         * Sets the SelectionKey for this handler (called after channel.register()).
         *
         * <p><strong>WHY this is set AFTER construction:</strong>
         * The SelectionKey is created during {@code client.register(selector, ops, handler)}.
         * We need the handler object to exist BEFORE registering (as the attachment), but the
         * key only exists AFTER registration. This setter resolves the chicken-and-egg problem.
         */
        public void setKey(SelectionKey key) {
            this.key = key;
        }

        /**
         * Releases all OS resources held by this connection.
         *
         * <p><strong>WHY the isClosing guard:</strong>
         * close() can be triggered from multiple code paths simultaneously (e.g., an SSLException
         * during handleRead() while a write is being processed). The boolean flag ensures we
         * execute the cleanup logic exactly ONCE — channel.close() on an already-closed channel
         * throws IOException, and key.cancel() on an already-cancelled key is a no-op (harmless)
         * but could cause confusing log messages.
         *
         * <p><strong>WHY catch IOException with ignored:</strong>
         * If the channel is ALREADY closed (e.g., the remote peer closed it first), channel.close()
         * throws an IOException. We don't care — the intent (releasing resources) is achieved either
         * way. There's nothing meaningful to do with this exception.
         */
        public void close() {
            if (isClosing) return; // Already closing — prevent duplicate cleanup
            isClosing = true;
            try {
                channel.close(); // Release OS socket file descriptor
            } catch (IOException ignored) {}
            if (key != null) {
                key.cancel(); // Remove from Selector's registered-keys set
            }
        }

        /**
         * Called by the event loop when this client's channel has data ready to read.
         *
         * <p><strong>WHY check {@code handshakeComplete} here:</strong>
         * In the early life of a connection, all incoming bytes are TLS handshake messages,
         * not application data. Only after the handshake completes do we start receiving
         * actual HTTP request bytes. By checking this flag, we route incoming bytes to the
         * appropriate handler:
         * <ul>
         *   <li>Handshake not done → {@link #processHandshake()} to advance the TLS state machine.</li>
         *   <li>Handshake done     → {@link #processDataRead()} to decrypt and parse HTTP.</li>
         * </ul>
         *
         * <p><strong>HOW bytes flow in this method:</strong>
         * <pre>
         * channel.read(peerNetData) → fills peerNetData with raw encrypted bytes
         *   If read returns -1 → client closed connection → close()
         *   Otherwise → route to processHandshake() or processDataRead()
         * </pre>
         *
         * <p><strong>WHY peerNetData stays in WRITE-mode by default:</strong>
         * channel.read() writes INTO the buffer (requires write-mode: position < limit = capacity).
         * The methods that decrypt peerNetData (processHandshake, processDataRead) are responsible
         * for flipping it to read-mode before passing to engine.unwrap(), then compacting back.
         */
        public void handleRead() {
            try {
                // Read encrypted bytes from the socket into peerNetData (write-mode = ready to receive).
                // Returns the number of bytes read, or -1 if the client closed the connection (EOF).
                int read = channel.read(peerNetData);
                if (read < 0) {
                    close(); // End-of-stream — client closed their side of the connection
                    return;
                }

                if (!handshakeComplete) {
                    // TLS handshake is still in progress — feed these bytes to the handshake processor.
                    processHandshake();
                } else {
                    // Handshake done — these bytes are encrypted HTTP data — decrypt and parse.
                    processDataRead();
                }
            } catch (IOException e) {
                System.err.println("Read error: " + e.getMessage());
                close();
            }
        }

        /**
         * Called by the event loop when this client's channel is ready to RECEIVE bytes from us.
         *
         * <p><strong>WHY a separate write handler is needed:</strong>
         * TCP has a finite send buffer. If we call channel.write() and the send buffer is full
         * (the client is reading slowly), channel.write() may only write SOME of the bytes.
         * We cannot retry immediately (that would block the Selector thread). Instead, we
         * register {@code OP_WRITE} interest on the key, which tells the Selector: "Wake me up
         * when the send buffer has room." handleWrite() is then called when there's room.
         *
         * <p><strong>HOW the write flow works:</strong>
         * <pre>
         *   myNetData (contains encrypted response, in WRITE-mode by default)
         *   │
         *   ▼ flip() → switch to READ-mode (ready to drain)
         *   channel.write(myNetData) → sends bytes to client
         *   │
         *   ├─ If hasRemaining() = true (not all bytes written):
         *   │    compact() → save unwritten bytes, switch back to WRITE-mode
         *   │    interestOps(OP_WRITE) → register for more write events
         *   │
         *   └─ If hasRemaining() = false (all bytes written):
         *        clear() → buffer fully consumed
         *        handshakeComplete? → close() (send response once then disconnect)
         *        otherwise → processHandshake() (continue handshake)
         * </pre>
         */
        public void handleWrite() {
            try {
                // Flip myNetData to read-mode so we can drain its encrypted bytes to the socket.
                myNetData.flip();
                channel.write(myNetData); // May write less than all bytes if send buffer is full

                if (myNetData.hasRemaining()) {
                    // Some bytes couldn't be written yet — save them and request another write event.
                    // compact() copies the remaining bytes to the front of the buffer and resets position.
                    myNetData.compact();
                    // Register OP_WRITE: Selector will call handleWrite() again when buffer has room.
                    key.interestOps(SelectionKey.OP_WRITE);
                    // wakeup() ensures the Selector's next select() call processes this interest change immediately.
                    key.selector().wakeup();
                } else {
                    // All bytes written successfully!
                    myNetData.clear(); // Reset buffer for reuse
                    if (handshakeComplete) {
                        // For a simple request-response model, we close after sending the response.
                        // (HTTP/1.0 style: one request → one response → close.)
                        // A persistent HTTP/1.1 or HTTP/2 server would instead register OP_READ here.
                        close();
                    } else {
                        // We were in the middle of a handshake write (e.g., sent ServerHello).
                        // Continue the handshake state machine to produce the next message.
                        processHandshake();
                    }
                }
            } catch (IOException e) {
                System.err.println("Write error: " + e.getMessage());
                close();
            }
        }

        /**
         * Executes the TLS handshake state machine — the most complex method in the server.
         *
         * ═══════════════════════════════════════════════════════════════
         * BEGINNER CONTEXT — The TLS Handshake State Machine
         * ═══════════════════════════════════════════════════════════════
         * TLS is a multi-step protocol. The SSLEngine models it as a state machine.
         * You call engine.getHandshakeStatus() and it tells you what to do next:
         *
         *   NEED_WRAP   → "I have data to send to the client. Call engine.wrap()
         *                   to encrypt it, then write the bytes to the channel."
         *
         *   NEED_UNWRAP → "I need data from the client. Read bytes from the channel
         *                   and call engine.unwrap() to decrypt and process them."
         *
         *   NEED_TASK   → "I need to run a CPU-intensive task (RSA decryption, cert
         *                   validation) before I can proceed. Get tasks via
         *                   engine.getDelegatedTask() and run them."
         *
         *   FINISHED    → "The handshake is complete! We can now exchange app data."
         *
         *   NOT_HANDSHAKING → "Same as FINISHED — no active handshake."
         *
         * The state machine loops through these states until FINISHED/NOT_HANDSHAKING.
         * ═══════════════════════════════════════════════════════════════
         *
         * <p><strong>WHY synchronized on handshakeLock:</strong>
         * This method can be called from two code paths:
         * <ol>
         *   <li>The Selector thread (via handleRead() or handleWrite()).</li>
         *   <li>The selectorTasks queue callback (posted by a worker thread after a NEED_TASK completes).</li>
         * </ol>
         * While callbacks from selectorTasks ARE executed on the Selector thread (we call task.run()
         * in the selector loop), the synchronization here provides an additional safety guarantee
         * and documents the intent clearly.
         *
         * <p><strong>HOW each state is handled:</strong>
         * <ul>
         *   <li><strong>FINISHED/NOT_HANDSHAKING</strong>: Mark handshake complete. Check if any app
         *       data arrived piggy-backed with the final handshake message (common in TLS 1.3).
         *       If yes, process it immediately; if no, register OP_READ to wait for the HTTP request.</li>
         *
         *   <li><strong>NEED_TASK</strong>: Pause the Selector for this channel (interestOps(0)),
         *       submit all delegated tasks to the worker pool, then post a lambda to selectorTasks
         *       that will call processHandshake() again once the tasks finish. Call selector.wakeup()
         *       to unblock the Selector's select() so it can drain the task queue.</li>
         *
         *   <li><strong>NEED_WRAP</strong>: Clear myNetData, call engine.wrap(myAppData, myNetData)
         *       to encrypt a handshake message, flip myNetData, write to channel. If not all bytes
         *       written, register OP_WRITE. If all written, clear and loop to the next state.</li>
         *
         *   <li><strong>NEED_UNWRAP</strong>: Flip peerNetData to read-mode. If empty (no data yet),
         *       compact and register OP_READ — we need more data from the client before proceeding.
         *       If data is present, call engine.unwrap(peerNetData, peerAppData) and compact.
         *       Handle BUFFER_UNDERFLOW (incomplete TLS record) by registering OP_READ for more data.</li>
         * </ul>
         */
        public void processHandshake() {
            synchronized (handshakeLock) {
                try {
                    // Loop until the state machine requires waiting for an I/O event or a task.
                    while (true) {
                        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
                        switch (status) {

                            // ── HANDSHAKE COMPLETE ────────────────────────────────────────────
                            case FINISHED:
                            case NOT_HANDSHAKING:
                                handshakeComplete = true;

                                // Check if any application data arrived along with the final handshake message.
                                // (In TLS 1.3 "0-RTT" / early data, the client can send the first HTTP
                                //  request inside the same flight as the final handshake message.)
                                // We flip peerNetData temporarily to check if it has bytes, then compact it back.
                                peerNetData.flip();
                                boolean hasData = peerNetData.hasRemaining();
                                peerNetData.compact(); // ALWAYS compact immediately to restore write-mode

                                if (hasData) {
                                    // Application data arrived — process it right now.
                                    processDataRead();
                                } else {
                                    // No data yet — register to receive the client's HTTP request.
                                    key.interestOps(SelectionKey.OP_READ);
                                    key.selector().wakeup();
                                }
                                return; // Exit processHandshake — handshake is done

                            // ── CPU-INTENSIVE TASK NEEDED ─────────────────────────────────────
                            case NEED_TASK:
                                // Pause all selector events for this channel while the task runs.
                                // WHY interestOps(0): Setting interest ops to 0 means "don't notify me
                                // about ANYTHING for this channel until I re-register". This prevents the
                                // selector from firing phantom read/write events while we're processing.
                                key.interestOps(0);

                                // Submit the delegated tasks to the worker thread pool.
                                workerPool.submit(() -> {
                                    try {
                                        // Drain all pending delegated tasks for this engine.
                                        // There may be multiple tasks in sequence (rare but possible).
                                        Runnable delegatedTask;
                                        while ((delegatedTask = engine.getDelegatedTask()) != null) {
                                            delegatedTask.run(); // Execute CPU-intensive TLS task
                                        }

                                        // Once all tasks are done, schedule handshake resumption
                                        // back on the Selector thread via the cross-thread queue.
                                        // WHY MUST run on Selector thread: SSLEngine and ByteBuffer
                                        // access is NOT thread-safe. The Selector thread is the
                                        // designated "owner" of this connection's state.
                                        selectorTasks.add(() -> {
                                            synchronized (handshakeLock) {
                                                processHandshake(); // Resume the handshake state machine
                                            }
                                        });

                                        // Unblock the selector's select() call so it immediately
                                        // drains the selectorTasks queue and runs our callback.
                                        key.selector().wakeup();
                                    } catch (Exception e) {
                                        System.err.println("Handshake task error: " + e.getMessage());
                                        close();
                                    }
                                });
                                return; // Exit while loop — wait for worker task to complete

                            // ── ENGINE NEEDS TO SEND DATA TO CLIENT ───────────────────────────
                            case NEED_WRAP:
                                // The engine wants to send a TLS handshake message (e.g., ServerHello,
                                // Certificate, ServerHelloDone). We encrypt it into myNetData.
                                myNetData.clear(); // Start fresh for this wrap operation
                                SSLEngineResult wrapResult = engine.wrap(myAppData, myNetData);

                                if (wrapResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                                    // myNetData is too small for the encrypted message (shouldn't happen
                                    // if we sized it with getPacketBufferSize(), but handle defensively).
                                    close();
                                    return;
                                }

                                // Flip myNetData to read-mode (from write-mode), then write to channel.
                                myNetData.flip();
                                channel.write(myNetData);

                                if (myNetData.hasRemaining()) {
                                    // Not all bytes written — TCP send buffer was full.
                                    // compact() preserves the unwritten bytes and restores write-mode.
                                    myNetData.compact();
                                    // Register OP_WRITE: handleWrite() will be called when there's room.
                                    key.interestOps(SelectionKey.OP_WRITE);
                                    key.selector().wakeup();
                                    return; // Wait for write-ready event
                                } else {
                                    myNetData.clear(); // Fully sent — clear for next use
                                    // Don't return — loop back to check the NEXT state in the handshake.
                                }
                                break; // Continue the while(true) loop

                            // ── ENGINE NEEDS DATA FROM CLIENT ─────────────────────────────────
                            case NEED_UNWRAP:
                                // The engine wants to process incoming bytes from the client
                                // (e.g., ClientHello, client certificate, Finished message).
                                peerNetData.flip(); // Switch to read-mode to inspect contents

                                if (!peerNetData.hasRemaining()) {
                                    // No bytes in the buffer — the client hasn't sent their next
                                    // handshake message yet. Wait for a read event.
                                    peerNetData.compact(); // Restore write-mode immediately
                                    key.interestOps(SelectionKey.OP_READ);
                                    key.selector().wakeup();
                                    return; // Exit — handleRead() will call processHandshake() when data arrives
                                }

                                // Decrypt the incoming TLS record.
                                peerAppData.clear();
                                SSLEngineResult unwrapResult = engine.unwrap(peerNetData, peerAppData);
                                peerNetData.compact(); // ALWAYS compact immediately after unwrap to restore write-mode

                                if (unwrapResult.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                    // A partial TLS record arrived — we need MORE bytes before we can decrypt it.
                                    // Register for another read event and wait for the rest of the record.
                                    key.interestOps(SelectionKey.OP_READ);
                                    key.selector().wakeup();
                                    return;
                                } else if (unwrapResult.getStatus() == SSLEngineResult.Status.CLOSED) {
                                    // The client sent a TLS close_notify — they want to terminate TLS.
                                    close();
                                    return;
                                }
                                // Successful unwrap — loop back to check NEXT handshake state.
                                break;
                        }
                    }
                } catch (SSLException e) {
                    // TLS negotiation failure (e.g., mismatched cipher suites, expired cert).
                    System.err.println("SSL Handshake failed: " + e.getMessage());
                    close();
                } catch (IOException e) {
                    // Network I/O error during handshake (e.g., client disconnected mid-handshake).
                    System.err.println("Handshake IO failed: " + e.getMessage());
                    close();
                }
            }
        }

        /**
         * Decrypts post-handshake data, parses the HTTP request, and sends an HTTPS response.
         *
         * <p><strong>WHY this is separate from processHandshake():</strong>
         * After the TLS handshake, the connection enters a completely different operating mode:
         * instead of processing TLS negotiation messages, we now process application data
         * (the actual HTTP request). Separating the two concerns keeps each method focused
         * and readable.
         *
         * <p><strong>WHAT:</strong>
         * <ol>
         *   <li>Unwraps (decrypts) all available bytes from peerNetData into peerAppData.</li>
         *   <li>Appends decrypted bytes to the rawRequest StringBuilder.</li>
         *   <li>Checks if the full HTTP headers have arrived (indicated by {@code \r\n\r\n}).</li>
         *   <li>If complete: parses the request, builds an HTTP 200 response, encrypts it, and sends it.</li>
         *   <li>If incomplete: registers OP_READ to wait for more data from the client.</li>
         * </ol>
         *
         * <p><strong>HOW the decryption loop works:</strong>
         * <pre>
         *   peerNetData (write-mode by default, filled by handleRead)
         *     │ flip()
         *     ▼
         *   peerNetData (read-mode)
         *     │ while hasRemaining():
         *     │   engine.unwrap(peerNetData, peerAppData)
         *     │   peerAppData.flip() → read decrypted bytes → append to rawRequest
         *     │   (loop until BUFFER_UNDERFLOW or all data consumed)
         *     │ compact()
         *     ▼
         *   peerNetData (write-mode, restored for next handleRead call)
         * </pre>
         *
         * <p><strong>HOW the response is encrypted and sent:</strong>
         * <pre>
         *   HTTP response string → ByteBuffer (appResponse)
         *     │ engine.wrap(appResponse, myNetData)
         *     ▼
         *   myNetData (encrypted response bytes)
         *     │ flip() → channel.write(myNetData)
         *     ▼
         *   Client receives encrypted HTTPS response
         * </pre>
         */
        private void processDataRead() {
            try {
                // ── Step 1: Flip peerNetData to read-mode for decryption ──
                peerNetData.flip();

                // ── Step 2: Decrypt loop — unwrap all available TLS records ──
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear(); // Prepare peerAppData to receive decrypted bytes

                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);

                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        // peerNetData has a partial TLS record — not enough bytes to decrypt yet.
                        // Break out of the loop and restore write-mode below. handleRead() will
                        // be called again when more bytes arrive.
                        break;
                    } else if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                        // Client sent TLS close_notify during data transfer.
                        peerNetData.compact(); // Restore write-mode before closing
                        close();
                        return;
                    }

                    // ── Collect the decrypted bytes into the raw request accumulator ──
                    peerAppData.flip(); // Switch to read-mode to drain decrypted bytes
                    byte[] bytes = new byte[peerAppData.remaining()];
                    peerAppData.get(bytes); // Copy decrypted bytes into a temporary array
                    rawRequest.append(new String(bytes)); // Append to the rolling request buffer
                    // (WHY new String(bytes): Converts raw bytes to a String using the platform's
                    //  default charset. In production, use StandardCharsets.UTF_8 explicitly.)
                }

                // ── Step 3: Restore peerNetData to write-mode ──
                // compact() copies any remaining (partially read) bytes to the front of the buffer
                // and sets position = remaining bytes, capacity = end. Ready for the next read event.
                peerNetData.compact();

                // ── Step 4: Check if the HTTP headers are complete ──
                // HTTP headers end with a blank line, represented as "\r\n\r\n" (CRLF CRLF).
                // Until we see this sentinel, we haven't received the complete request headers yet.
                String reqStr = rawRequest.toString();
                if (reqStr.contains("\r\n\r\n")) {

                    // ── Step 5: Parse the HTTP request ──
                    // HttpsParser.parse() converts the raw text into a structured HttpRequest object.
                    HttpsParser.HttpRequest request = HttpsParser.parse(reqStr);

                    // Log the request details for debugging/monitoring.
                    InetAddress addr = channel.socket().getInetAddress();
                    String clientIp = (addr != null) ? addr.getHostAddress() : "unknown";
                    System.out.println("Client IP: " + clientIp);
                    System.out.println("Method:    " + request.method);
                    System.out.println("Path:      " + request.path);
                    System.out.println("Headers:   " + request.headers);
                    System.out.println();

                    // ── Step 6: Build the HTTP response ──
                    // This is a minimal HTTP/1.1 200 OK response. In a real load balancer,
                    // this would be the PROXIED response from the backend server.
                    // "Connection: close" tells the client not to expect keep-alive (HTTP/1.0 style).
                    String response = "HTTP/1.1 200 OK\r\n" +
                                      "Content-Type: text/plain\r\n" +
                                      "Content-Length: 2\r\n" +      // Length of the body "OK"
                                      "Connection: close\r\n\r\n" +  // End of headers (blank line)
                                      "OK";                          // The response body

                    // ── Step 7: Encrypt the response using TLS ──
                    // engine.wrap() takes plaintext (appResponse) and encrypts it into myNetData.
                    ByteBuffer appResponse = ByteBuffer.wrap(response.getBytes());
                    myNetData.clear(); // Prepare for new encrypted output
                    SSLEngineResult wrapResult = engine.wrap(appResponse, myNetData);

                    if (wrapResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        // myNetData is too small (shouldn't happen with proper sizing, but handle defensively).
                        close();
                        return;
                    }

                    // ── Step 8: Send the encrypted response to the client ──
                    myNetData.flip(); // Switch to read-mode to drain bytes to the channel
                    channel.write(myNetData);

                    if (myNetData.hasRemaining()) {
                        // TCP send buffer was full — couldn't write everything. Save remainder
                        // and register OP_WRITE so handleWrite() can send the rest later.
                        myNetData.compact();
                        key.interestOps(SelectionKey.OP_WRITE);
                        key.selector().wakeup();
                    } else {
                        // All response bytes written! Clear the buffer and close the connection.
                        myNetData.clear();
                        close(); // Connection: close — we're done with this client for this request
                    }

                } else {
                    // ── Headers not complete yet — wait for more data ──
                    // Register OP_READ: handleRead() will be called again when more bytes arrive.
                    key.interestOps(SelectionKey.OP_READ);
                    key.selector().wakeup();
                }
            } catch (IOException e) {
                System.err.println("Data processing error: " + e.getMessage());
                close();
            }
        }
    }
}