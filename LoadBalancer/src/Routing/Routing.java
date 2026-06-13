package Routing;

public class Routing {
    public static void main(String[] args) {
        System.out.println("Starting Load Balancer Routing...");
        
        // Initialize ResponseTime as a helper
        ResponseTime poller = new ResponseTime();
        
        // This starts the asynchronous, non-blocking network polling in the background
        poller.startPolling();
        
        System.out.println("Response time poller is running in the background.");
        System.out.println("Routing logic can now proceed here...");
        
        // The JVM will remain running because the ScheduledExecutorService 
        // in ResponseTime creates non-daemon threads.
        // You can later add your Load Balancer's ServerSocket listener here.
    }
}
