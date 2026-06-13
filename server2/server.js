const express = require('express');
const app = express();
const PORT = process.env.PORT || 3002;

// Documenting with WHY, WHAT, HOW structure:
// WHY: We need to see which server in the pool is handling the request to verify the load balancer's routing.
// WHAT: Logs incoming requests and returns a JSON response containing server ID, request method, path, and headers.
// HOW: Uses Express routing to match all paths (*), logs to console, and sends a JSON payload.
app.all('*', (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Request Received: ${req.method} ${req.url}`);
    console.log('Headers:', req.headers);
    console.log('---');

    res.json({
        server: "Backend Server 2",
        port: PORT,
        url: req.url,
        method: req.method,
        headers: req.headers,
        timestamp: timestamp
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Backend Server 2 is running on port ${PORT}`);
});
