// 1. Import Express
const express = require('express');

const PORT = 3000;

const app = express();

app.use(express.json());

app.post('/api/webhook', (req, res) => {
    
    // --- THIS IS OUR "SERVER OUTPUT" DELIVERABLE ---
    console.log('--- 🔔 New Alert Received! ---');
    console.log('Timestamp:', new Date().toISOString());
    console.log('Headers:', req.headers); // Good for debugging auth
    console.log('Payload:', req.body);     // This is the data from Groups Watcher
    console.log('---------------------------------');
    // ------------------------------------------------

    // It's crucial to send a 200 OK response back.
    // This tells Groups Watcher "We got it, thank you."
    // If you don't send this, it might think delivery failed and keep retrying.
    res.status(200).send('Alert received successfully');
});

app.get('/', (req, res) => {
    res.send('Webhook server is alive and listening! Send POST requests to /api/webhook');
});

app.listen(PORT, () => {
    console.log(`🚀 Webhook server listening on http://localhost:${PORT}`);
});