import HttpParser.HttpsParser;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main entry point of the non-blocking secure HTTPS server.
 *
 * <p><strong>WHY:</strong>
 * HTTPS requires managing multiple secure encrypted TCP connections concurrently. Blocking I/O models waste OS threads
 * by parking them while waiting for bytes. An event-driven, non-blocking architecture allows handling thousands of
 * connections efficiently using a single thread.
 *
 * <p><strong>WHAT:</strong>
 * An HTTPS server using Java NIO Selector multiplexing and SSLEngine for asynchronous TLS encryption.
 *
 * <p><strong>HOW:</strong>
 * Binds a non-blocking {@link ServerSocketChannel} to a port, registers it with a {@link Selector} for accept events,
 * polls ready events in a single loop, and delegates CPU-intensive TLS tasks to a worker pool.
 */
public class Main {

    private static final int PORT = 8443;
    private static final String KEYSTORE_FILE = "keystore.jks";
    private static final String KEYSTORE_FALLBACK = "HttpParser/keystore.jks";
    private static final String KEYSTORE_PASSWORD = "password";

    private static SSLContext sslContext;
    private static ExecutorService workerPool;

    // Thread-safe queue to pass tasks from worker threads back to the main Selector thread.
    // This ensures that all operations modifying ByteBuffer and SSLEngine states are serialized
    // on the Selector thread, avoiding critical race conditions.
    private static final Queue<Runnable> selectorTasks = new ConcurrentLinkedQueue<>();

    /**
     * Entry point to configure, bootstrap, and execute the server event loop.
     *
     * <p><strong>WHY:</strong>
     * A startup driver is needed to load SSL/TLS certificates, initialize the worker pool,
     * register channels with the Selector, and run the server event loop.
     *
     * <p><strong>WHAT:</strong>
     * Configures the SSLContext, starts a fixed thread pool for crypto operations, sets up the server channel,
     * and runs the continuous event selection loop.
     *
     * <p><strong>HOW:</strong>
     * Loads the keystore from disk, initializes KeyManagerFactory, binds ServerSocketChannel,
     * runs a loop that processes the queue tasks first, waits for selector triggers, and routes ready channels
     * to connection lifecycle methods.
     */
    public static void main(String[] args) throws Exception {
        // Step 1: Load the server certificate Keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        File keystoreFile = new File(KEYSTORE_FILE);
        if (!keystoreFile.exists()) {
            keystoreFile = new File(KEYSTORE_FALLBACK);
        }

        if (!keystoreFile.exists()) {
            System.err.println("Error: Keystore file 'keystore.jks' not found in current directory or fallback path.");
            System.exit(1);
        }

        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }

        // Step 2: Initialize the SSLContext with certificates
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        // Step 3: Create a Worker Pool (fixed thread pool) for CPU-heavy SSL handshake tasks
        // This keeps the primary Selector loop fast and responsive.
        workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);

        // Step 4: Open the Selector and ServerSocketChannel
        Selector selector = Selector.open();
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        
        // Make the channel non-blocking
        serverChannel.configureBlocking(false);
        
        // Bind the server to the port
        serverChannel.bind(new InetSocketAddress(PORT));
        
        // Register the server socket with the selector to listen for "accept" events
        serverChannel.register(selector, SelectionKey.OP_ACCEPT);

        System.out.println("Java NIO Selector-based HTTPS Server Running on " + PORT);

        // Step 5: Start the main Event loop
        while (!Thread.currentThread().isInterrupted()) {
            // Run any pending tasks scheduled by worker threads (e.g. resuming handshake)
            Runnable task;
            while ((task = selectorTasks.poll()) != null) {
                try {
                    task.run();
                } catch (Exception e) {
                    System.err.println("Error running selector task: " + e.getMessage());
                }
            }

            // Block until at least one registered event (accept, read, write) occurs on a channel
            selector.select();

            // Iterate over all keys that are ready for processing
            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove(); // Remove the key from the selected set so we don't process it twice

                if (!key.isValid()) continue;

                try {
                    if (key.isAcceptable()) {
                        // A new client is trying to connect to the server
                        accept(key, selector);
                    } else if (key.isReadable()) {
                        // Data is available to read from a client socket
                        ClientHandler handler = (ClientHandler) key.attachment();
                        handler.handleRead();
                    } else if (key.isWritable()) {
                        // The client socket's output buffer is ready to receive data
                        ClientHandler handler = (ClientHandler) key.attachment();
                        handler.handleWrite();
                    }
                } catch (Exception e) {
                    System.err.println("Error handling connection key: " + e.getMessage());
                    closeKey(key);
                }
            }
        }
    }

    /**
     * Accepts and configures a new incoming TCP client connection.
     *
     * <p><strong>WHY:</strong>
     * New incoming network connections must be accepted, set to non-blocking mode, and associated
     * with an independent TLS encryption engine before any client exchange can begin.
     *
     * <p><strong>WHAT:</strong>
     * Accepts the socket connection, creates the client handler, binds an SSLEngine, and begins the TLS handshake.
     *
     * <p><strong>HOW:</strong>
     * Calls {@link ServerSocketChannel#accept()}, configures blocking to false, builds an {@link SSLEngine} configured
     * for server mode, instantiates {@link ClientHandler}, registers it with the selector for {@code OP_READ}, and calls
     * {@link ClientHandler#processHandshake()}.
     */
    private static void accept(SelectionKey key, Selector selector) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel client = server.accept();
        if (client == null) return;
        
        client.configureBlocking(false);
        
        // Create an SSLEngine for handling TLS wrapping/unwrapping
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(false); // We are a server, not a client
        engine.beginHandshake();

        // Create the connection state handler and attach it to the key
        ClientHandler handler = new ClientHandler(client, engine);
        SelectionKey clientKey = client.register(selector, SelectionKey.OP_READ, handler);
        handler.setKey(clientKey);
        
        // Begin the initial TLS handshake sequence
        handler.processHandshake();
    }

    /**
     * Safely closes client socket keys and reclaims allocation resources.
     *
     * <p><strong>WHY:</strong>
     * Broken, timed-out, or terminated connection keys must be removed from Selector event loops and
     * closed to prevent socket descriptor leaks.
     *
     * <p><strong>WHAT:</strong>
     * Closes the client SocketChannel and cancels its SelectionKey.
     *
     * <p><strong>HOW:</strong>
     * Resolves the {@link ClientHandler} attached to the key and calls {@link ClientHandler#close()} on it,
     * falling back to closing the underlying channel directly if the handler attachment is absent.
     */
    private static void closeKey(SelectionKey key) {
        if (key == null) return;
        ClientHandler handler = (ClientHandler) key.attachment();
        if (handler != null) {
            handler.close();
        } else {
            try {
                key.channel().close();
            } catch (IOException ignored) {}
            key.cancel();
        }
    }

    /**
     * Manages client connection states, ByteBuffers, and encryption operations.
     *
     * <p><strong>WHY:</strong>
     * Non-blocking connections must parse raw packets incrementally. This class isolates the state,
     * encryption context, buffers, and request strings for a single connection.
     *
     * <p><strong>WHAT:</strong>
     * Holds the channel, SSLEngine, handshake locks, buffers, and read string states. It executes I/O reads/writes,
     * decryption wrapping/unwrapping, and HTTP response dispatching.
     *
     * <p><strong>HOW:</strong>
     * Allocates session-sized net and app buffers, listens to events routed by the selector, flips/compacts buffers
     * during decryption, and runs handshakes using worker threads.
     */
    static class ClientHandler {
        private final SocketChannel channel;
        private final SSLEngine engine;
        private SelectionKey key;

        // ByteBuffers for managing network data (encrypted) and application data (plain text)
        private final ByteBuffer myNetData;    // Outgoing encrypted data
        private final ByteBuffer peerNetData;  // Incoming encrypted data (always kept in write-mode by default)
        private final ByteBuffer myAppData;    // Outgoing plain text
        private final ByteBuffer peerAppData;  // Incoming plain text

        private final StringBuilder rawRequest = new StringBuilder();
        private boolean handshakeComplete = false;
        private boolean isClosing = false;
        
        // Lock to ensure only one thread performs handshake/engine operations at a time
        private final Object handshakeLock = new Object();

        public ClientHandler(SocketChannel channel, SSLEngine engine) {
            this.channel = channel;
            this.engine = engine;

            // Allocate buffer sizes recommended by the SSL Session configurations
            SSLSession session = engine.getSession();
            this.myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
            this.peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
            this.myAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
            this.peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        }

        public void setKey(SelectionKey key) {
            this.key = key;
        }

        /**
         * Cleans up channel descriptors and cancels selector registration.
         *
         * <p><strong>WHY:</strong>
         * Connections that have served their request or run into errors must release underlying OS resources.
         *
         * <p><strong>WHAT:</strong>
         * Closes the client SocketChannel and invalidates the SelectionKey.
         *
         * <p><strong>HOW:</strong>
         * Sets a closing flag to prevent duplicate closures, terminates the channel, and calls cancel on the key.
         */
        public void close() {
            if (isClosing) return;
            isClosing = true;
            try {
                channel.close();
            } catch (IOException ignored) {}
            if (key != null) {
                key.cancel();
            }
        }

        /**
         * Reads raw encrypted bytes from the socket channel.
         *
         * <p><strong>WHY:</strong>
         * Encrypted network bytes sent by the client must be read into JVM buffers asynchronously when ready.
         *
         * <p><strong>WHAT:</strong>
         * Pulls incoming TLS record data from the socket into the peer net byte buffer.
         *
         * <p><strong>HOW:</strong>
         * Invokes {@link SocketChannel#read(ByteBuffer)}. Closes on EOF. Routes processing to either
         * the TLS handshake sequence or the HTTP request processor depending on session state.
         */
        public void handleRead() {
            try {
                // Read incoming encrypted bytes from the socket into peerNetData (currently in write-mode)
                int read = channel.read(peerNetData);
                if (read < 0) {
                    close(); // End of stream (client disconnected)
                    return;
                }
                
                // Trigger handshake or data parsing. Both methods will handle flipping peerNetData to read-mode
                // to decrypt and then compact it back to write-mode.
                if (!handshakeComplete) {
                    processHandshake();
                } else {
                    processDataRead();
                }
            } catch (IOException e) {
                System.err.println("Read error: " + e.getMessage());
                close();
            }
        }

        /**
         * Writes pending encrypted output bytes back to the socket channel.
         *
         * <p><strong>WHY:</strong>
         * If the TCP buffer fills up, writing response bytes directly will block. We must write
         * bytes asynchronously when the selector indicates the channel is ready to write.
         *
         * <p><strong>WHAT:</strong>
         * Flushes the outgoing net buffer (`myNetData`) out to the client socket.
         *
         * <p><strong>HOW:</strong>
         * Flips `myNetData` to read-mode, writes to the channel, and compacts it if any bytes remain
         * while registering {@code OP_WRITE}. Clears the buffer and terminates/resumes handshakes if fully written.
         */
        public void handleWrite() {
            try {
                // Switch myNetData buffer to read-mode so we can write its contents to the channel
                myNetData.flip();
                channel.write(myNetData);
                
                if (myNetData.hasRemaining()) {
                    // Not all bytes were written. Compact myNetData and wait for the next OP_WRITE event.
                    myNetData.compact();
                    key.interestOps(SelectionKey.OP_WRITE);
                    key.selector().wakeup();
                } else {
                    // All bytes successfully written. Clear the buffer.
                    myNetData.clear();
                    if (handshakeComplete) {
                        // For a simple load balancer, close the connection after the response is sent.
                        close();
                    } else {
                        // Continue handshake processing
                        processHandshake();
                    }
                }
            } catch (IOException e) {
                System.err.println("Write error: " + e.getMessage());
                close();
            }
        }

        /**
         * Executes the security state machine for SSL/TLS handshaking.
         *
         * <p><strong>WHY:</strong>
         * Secure communication requires a multi-step cryptographic handshake (certificates, public/private keys)
         * that must be negotiated before exchanging application data.
         *
         * <p><strong>WHAT:</strong>
         * Governs the TLS negotiation states (wrap, unwrap, run delegated CPU tasks) step-by-step.
         *
         * <p><strong>HOW:</strong>
         * Checks the engine's handshake status in a loop:
         * <ul>
         *   <li>{@code NEED_TASK}: Submits heavy calculations to the worker pool and schedules resumption on the selectorTasks queue.</li>
         *   <li>{@code NEED_WRAP}: Encrypts empty/handshake messages and writes them to the channel.</li>
         *   <li>{@code NEED_UNWRAP}: Flips {@code peerNetData}, unwraps TLS records, and compacts.</li>
         * </ul>
         */
        public void processHandshake() {
            synchronized (handshakeLock) {
                try {
                    while (true) {
                        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
                        switch (status) {
                            case FINISHED:
                            case NOT_HANDSHAKING:
                                handshakeComplete = true;
                                // Temporarily flip peerNetData to read-mode to check for any application data
                                peerNetData.flip();
                                boolean hasData = peerNetData.hasRemaining();
                                peerNetData.compact(); // Restore to write-mode immediately
                                
                                if (hasData) {
                                    processDataRead();
                                } else {
                                    key.interestOps(SelectionKey.OP_READ);
                                    key.selector().wakeup();
                                }
                                return;

                            case NEED_TASK:
                                // CPU-intensive task (like generating public/private keys) needs to run.
                                // We delegate this to the worker pool so we don't freeze the Selector loop.
                                key.interestOps(0); // Pause selector notifications for this socket
                                workerPool.submit(() -> {
                                    try {
                                        Runnable delegatedTask;
                                        while ((delegatedTask = engine.getDelegatedTask()) != null) {
                                            delegatedTask.run();
                                        }
                                        // Once tasks are finished, schedule handshake resumption back on the selector thread
                                        selectorTasks.add(() -> {
                                            synchronized (handshakeLock) {
                                                processHandshake();
                                            }
                                        });
                                        key.selector().wakeup();
                                    } catch (Exception e) {
                                        System.err.println("Handshake task error: " + e.getMessage());
                                        close();
                                    }
                                });
                                return;

                            case NEED_WRAP:
                                // The engine needs to produce data to send to the client (e.g. Server Hello).
                                myNetData.clear();
                                SSLEngineResult wrapResult = engine.wrap(myAppData, myNetData);
                                if (wrapResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                                    close();
                                    return;
                                }
                                
                                // Attempt to write the wrapped handshake bytes to the client
                                myNetData.flip();
                                channel.write(myNetData);
                                if (myNetData.hasRemaining()) {
                                    // Could not write all bytes immediately, register for OP_WRITE
                                    myNetData.compact();
                                    key.interestOps(SelectionKey.OP_WRITE);
                                    key.selector().wakeup();
                                    return;
                                } else {
                                    myNetData.clear();
                                }
                                break;

                            case NEED_UNWRAP:
                                // The engine needs to decrypt incoming data sent by the client.
                                // Flip peerNetData to read-mode to check available bytes and unwrap
                                peerNetData.flip();
                                if (!peerNetData.hasRemaining()) {
                                    // No bytes available to decrypt. Restore to write-mode and register OP_READ.
                                    peerNetData.compact();
                                    key.interestOps(SelectionKey.OP_READ);
                                    key.selector().wakeup();
                                    return;
                                }
                                
                                peerAppData.clear();
                                SSLEngineResult unwrapResult = engine.unwrap(peerNetData, peerAppData);
                                peerNetData.compact(); // Restore to write-mode immediately
                                
                                if (unwrapResult.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                    // A complete TLS packet was not received yet. Ask selector for more data.
                                    key.interestOps(SelectionKey.OP_READ);
                                    key.selector().wakeup();
                                    return;
                                } else if (unwrapResult.getStatus() == SSLEngineResult.Status.CLOSED) {
                                    close();
                                    return;
                                }
                                break;
                        }
                    }
                } catch (SSLException e) {
                    System.err.println("SSL Handshake failed: " + e.getMessage());
                    close();
                } catch (IOException e) {
                    System.err.println("Handshake IO failed: " + e.getMessage());
                    close();
                }
            }
        }

        /**
         * Decrypts network buffers and processes the completed HTTP Request.
         *
         * <p><strong>WHY:</strong>
         * Once the handshake is done, client communication arrives encrypted. We must decrypt it into plaintext,
         * wait until we have parsed the complete set of HTTP headers, and write back a formatted secure response.
         *
         * <p><strong>WHAT:</strong>
         * Unwraps incoming network buffer bytes, updates the raw request string builder,
         * triggers HTTP parsing on headers completion (`\r\n\r\n`), wraps response payload, and writes it to socket.
         *
         * <p><strong>HOW:</strong>
         * Flips {@code peerNetData}, unwraps all available segments into {@code peerAppData}, compiles to string, and compacts.
         * If the string has {@code \r\n\r\n}, calls {@link HttpsParser#parse(String)}, wraps response text into {@code myNetData},
         * writes to client channel, and closes the connection.
         */
        private void processDataRead() {
            try {
                // Flip peerNetData to read-mode for decryption
                peerNetData.flip();
                
                // Decrypt all incoming network data until there are no remaining bytes or a complete packet is not ready
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                    
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        break;
                    } else if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                        peerNetData.compact(); // Restore to write-mode before closing
                        close();
                        return;
                    }
                    
                    // Convert decrypted application bytes to string and append to raw request buffer
                    peerAppData.flip();
                    byte[] bytes = new byte[peerAppData.remaining()];
                    peerAppData.get(bytes);
                    rawRequest.append(new String(bytes));
                }
                
                // Restore peerNetData to write-mode for subsequent reads
                peerNetData.compact();

                String reqStr = rawRequest.toString();
                // Check if the HTTP headers are completely read (separated by \r\n\r\n)
                if (reqStr.contains("\r\n\r\n")) {
                    // Parse the HTTP Request metadata
                    HttpsParser.HttpRequest request = HttpsParser.parse(reqStr);
                    
                    InetAddress addr = channel.socket().getInetAddress();
                    String clientIp = (addr != null) ? addr.getHostAddress() : "unknown";
                    
                    System.out.println("Client IP: " + clientIp);
                    System.out.println("Method: " + request.method);
                    System.out.println("Path: " + request.path);
                    System.out.println("Headers: " + request.headers);
                    System.out.println();

                    // Formulate a simple plaintext response
                    String response = "HTTP/1.1 200 OK\r\n" +
                                      "Content-Type: text/plain\r\n" +
                                      "Content-Length: 2\r\n" +
                                      "Connection: close\r\n\r\n" +
                                      "OK";
                    
                    ByteBuffer appResponse = ByteBuffer.wrap(response.getBytes());
                    myNetData.clear();
                    
                    // Encrypt the response plain text
                    SSLEngineResult wrapResult = engine.wrap(appResponse, myNetData);
                    if (wrapResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        close();
                        return;
                    }
                    
                    // Write the encrypted response back to the client channel
                    myNetData.flip();
                    channel.write(myNetData);
                    
                    if (myNetData.hasRemaining()) {
                        myNetData.compact();
                        key.interestOps(SelectionKey.OP_WRITE);
                        key.selector().wakeup();
                    } else {
                        myNetData.clear();
                        close(); // Close connection (HTTP Connection: close)
                    }
                } else {
                    // Headers not complete yet, register to receive more network data
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