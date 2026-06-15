# 🚀 High-Performance Layer 7 Java Load Balancer

![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=java&logoColor=white)
![Networking](https://img.shields.io/badge/Java_NIO-Non--Blocking-blue?style=for-the-badge)
![Performance](https://img.shields.io/badge/Throughput-1000%2B_RPS-brightgreen?style=for-the-badge)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-red?style=for-the-badge)

A fully asynchronous, non-blocking Layer 7 HTTP/HTTPS reverse proxy and load balancer built entirely from scratch in raw Java. 

This project intentionally avoids heavy web frameworks (like Spring Boot) and third-party libraries (like Netty or Jackson) to demonstrate a deep, ground-up understanding of low-level socket programming, memory management, thread-safety, and distributed systems architecture.

---

## ✨ Core Features

*   ⚡ **Event-Driven Reactor Pattern:** Utilizes Java NIO (`Selector`, `SocketChannel`) to multiplex thousands of concurrent connections on a single thread, bypassing the memory-heavy Thread-Per-Connection anti-pattern.
*   🔒 **Edge TLS/SSL Termination:** A custom cryptographic state machine leveraging `SSLEngine` to decrypt incoming HTTPS traffic at the proxy edge. RSA/AES handshakes are offloaded to a separate worker thread pool to prevent blocking the main event loop.
*   🔄 **Consistent Hashing with Virtual Nodes:** A `TreeMap`-based dynamic routing ring that ensures mathematically uniform traffic distribution (O(log N) lookups), guarded by a `ReentrantReadWriteLock` for massive read-concurrency.
*   🚦 **Lock-Free Rate Limiting:** A custom Token Bucket algorithm using `ConcurrentHashMap` and `AtomicReference` Compare-And-Swap (CAS) loops, capable of processing rate-limit checks in <1ms without synchronization bottlenecks.
*   🏥 **Active Health Checking:** An asynchronous background polling subsystem utilizing `CompletableFuture`. Dead nodes are instantaneously evicted from the routing ring and seamlessly restored upon recovery.
*   📝 **Layer 7 Header Mutation:** Dynamically intercepts and mutates raw byte streams to inject distributed tracing headers (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`).

---

## 🏗️ Architecture Flow

```mermaid
graph TD
    Client1[Client App] -->|HTTPS Request| Selector(Main NIO Selector)
    Client2[Client Browser] -->|HTTPS Request| Selector
    
    subgraph Reactor Core Event Loop
        Selector -->|OP_READ| TLS[TLS State Machine]
        TLS -->|Decrypt| Mutator[L7 Header Mutator]
        Mutator -->|Inject Headers| Limiter[Lock-Free Rate Limiter]
        Limiter --> Router[Consistent Hashing Ring]
    end
    
    subgraph Crypto Thread Pool
        TLS -.->|Offload RSA/AES| Workers[Worker Threads]
    end
    
    subgraph Physical Backends
        Router -->|Proxy| B1(Backend Node: 3001)
        Router -->|Proxy| B2(Backend Node: 3002)
        Router -->|Proxy| B3(Backend Node: 3003)
    end
    
    subgraph Background Subsystems
        HC[Async Health Checker] -.->|HTTP GET /health| B1
        HC -.->|HTTP GET /health| B2
        HC -.->|HTTP GET /health| B3
        HC -.->|Evict / Restore| Router
    end
    
    classDef core fill:#2b2b2b,stroke:#00ffcc,stroke-width:2px,color:#fff;
    classDef client fill:#1e1e1e,stroke:#fff,stroke-width:1px,color:#fff;
    classDef backend fill:#1a3a3a,stroke:#00ffcc,stroke-width:1px,color:#fff;
    
    class Selector,TLS,Mutator,Limiter,Router core;
    class Client1,Client2 client;
    class B1,B2,B3 backend;
```

---

## 🚀 Getting Started

### 1. Prerequisites
*   Java Development Kit (JDK) 17 or higher.
*   Apache JMeter (optional, for load testing).

### 2. Configuration
The proxy is configured via `config.json` in the root directory. It features a custom regex-based parser (no Gson/Jackson required).
```json
{
  "listeningPort": 443,
  "rateLimitCapacity": 100,
  "rateLimitRefillPerSecond": 10
}
```

### 3. Build & Run
Compile the source code using the `src` directory as the source path:
```bash
javac -sourcepath src src/Main.java
```

Start the Load Balancer:
```bash
java -cp src Main
```

---

## 📊 Performance Benchmarks
This architecture has been load-tested locally using **Apache JMeter**.

*   **Throughput:** Sustained **1,000+ Requests Per Second (RPS)** (Extrapolated capacity of 3.6 Million requests per hour on a single machine).
*   **Concurrency:** Handled **100 fully active, encrypted concurrent connections** seamlessly.
*   **Stability:** Achieved a **0% internal failure rate** with zero memory leaks during maximum pressure tests, proving the thread-safety of the custom lock-free structures.

To replicate the load test, open the provided `LoadTest_1k_RPS.jmx` file in Apache JMeter and hit Start.

---
*Designed and engineered from the ground up to demonstrate mastery of low-level Java networking and high-concurrency design patterns.*
