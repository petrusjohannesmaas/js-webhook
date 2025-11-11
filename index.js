// 1. Imports
const express = require('express');
const fs = require('fs').promises; // Keep for now, though we're moving away
const path = require('path');
const basicAuth = require('basic-auth');
require('dotenv').config(); // Load variables from .env
const { createClient } = require('redis'); // <-- NEW: Import Redis

// 2. App & Environment Config
const app = express();
const PORT = 3000;
// We keep this to know where the *old* log file was, but it's not the primary store
const LEGACY_LOG_FILE = path.join(__dirname, process.env.LOG_FILE || 'webhook_logs.jsonl');
// --- NEW: Redis Client Setup ---

// --- NEW: Redis Client Setup ---
// Use the REDIS_URL from .env, or fallback to the default if it's missing
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
});

redisClient.on('error', (err) => {
  console.error('Redis Client Error', err);
  console.log('---!!! REDIS IS NOT CONNECTED. LOGS ARE NOT BEING SAVED. !!!---');
  console.log('---!!! Ensure redis-server is installed and running. !!!---');
});

// We must connect the client. We use an IIFE (Immediately Invoked Function) to do this.
(async () => {
  try {
    await redisClient.connect();
    console.log('✅ Successfully connected to Redis.');
  } catch (err) {
    console.error('---!!! FAILED TO CONNECT TO REDIS !!!---', err);
  }
})();
// --- End Redis Setup ---

// --- Middleware ---
app.use(express.json());

const webhookWhitelist = (req, res, next) => {
  const sentFrom = req.headers['x-sent-from'];
  if (sentFrom === 'GroupsWatcher.com') {
    next();
  } else {
    console.warn(`[FORBIDDEN] Blocked request from ${req.ip}. Header 'x-sent-from' was: ${sentFrom}`);
    res.status(403).send('Forbidden: Invalid Source');
  }
};

const adminAuth = (req, res, next) => {
  const user = basicAuth(req);
  if (user && 
      user.name === process.env.ADMIN_USER && 
      user.pass === process.env.ADMIN_PASS) {
    return next();
  }
  res.setHeader('WWW-Authenticate', 'Basic realm="Admin Dashboard"');
  res.status(401).send('Authentication required.');
};

// --- Helper Functions ---

/**
 * REPLACED: logWebhookToFile() is now logWebhookToDb()
 *
 * Asynchronously logs a webhook entry to Redis.
 * 1. Creates a Hash for the log data.
 * 2. Adds the log's ID to a Set called 'logs:unreviewed'.
 */
const logWebhookToDb = async (req) => {
  // Generate a unique ID for the log entry
  const logId = `log:${Date.now()}:${Math.random().toString(36).substring(2, 7)}`;
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    sourceIp: req.ip,
    headers: JSON.stringify(req.headers),
    payload: JSON.stringify(req.body),
    status: 'unreviewed'
  };

  try {
    const multi = redisClient.multi();
    
    // 1. Create the Hash. Use HSET (not hSetAll) and pass the object
    multi.HSET(logId, logEntry); // <-- CHANGED
    
    // 2. Add the ID of this log. Use SADD (not sAdd)
    multi.SADD('logs:unreviewed', logId); // <-- CHANGED
    
    // Execute the transaction
    await multi.exec();
    
    console.log(`[Redis] Log saved: ${logId}`);

  } catch (err) {
    console.error('Failed to write log to Redis:', err);
  }
};

/**
 * REWRITTEN: getLogsAsHtml()
 *
 * Reads all "unreviewed" log IDs from Redis, fetches each log's
 * data, and formats it as HTML for the dashboard.
 */
const getLogsAsHtml = async () => {
  let unreviewedIds;
  try {
    // 1. Get all members. Use SMEMBERS (not sMembers)
    unreviewedIds = await redisClient.SMEMBERS('logs:unreviewed'); // <-- CHANGED
  } catch (err) {
    console.error('Redis error getting unreviewed logs:', err);
    return '<p>Error connecting to Redis.</p>';
  }

  if (unreviewedIds.length === 0) {
    return '<div class="log-entry"><p>No unreviewed logs. All clear!</p></div>';
  }

  // Sort IDs to show newest first
  unreviewedIds.sort((a, b) => {
    const timeA = a.split(':')[1];
    const timeB = b.split(':')[1];
    return timeB - timeA;
  });

  // 2. Fetch all log data
  const multi = redisClient.multi();
  unreviewedIds.forEach(id => {
    multi.HGETALL(id); // <-- CHANGED (use HGETALL, not hGetAll)
  });
  
  let logs;
  try {
    logs = await multi.exec();
  } catch (err) {
    console.error('Redis error fetching log details:', err);
    return '<p>Error fetching log details.</p>';
  }

  // 3. Map each log object to an HTML block
  return logs.map((log, index) => {
    if (!log) {
      return `<div class="log-entry"><p>Error parsing log: ${unreviewedIds[index]}</p></div>`;
    }
    
    try {
      // We must parse the JSON strings back into objects
      const payload = JSON.parse(log.payload);
      const headers = JSON.parse(log.headers);
      
      return `
        <div class="log-entry">
          <p><strong>Timestamp:</strong> ${log.timestamp}</p>
          <p><strong>Status:</strong> ${log.status}</p>
          <p><strong>Message:</strong> ${payload.message || 'N/A'}</p>
          <p><strong>Post Text:</strong> ${payload.data?.post_text || 'N/A'}</p>
          <details>
            <summary>View Full Payload</summary>
            <pre>${JSON.stringify(payload, null, 2)}</pre>
          </details>
          <details>
            <summary>View Headers</summary>
            <pre>${JSON.stringify(headers, null, 2)}</pre>
          </details>
        </div>
      `;
    } catch (parseErr) {
      return `<div class="log-entry"><p>Error parsing log entry: ${unreviewedIds[index]}</p></div>`;
    }
  }).join('');
};

// --- Routes ---

/**
 * The main dashboard page.
 * No changes here, it still just serves the HTML shell.
 */
app.get('/', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Server Logs</title>
      <script src="https://unpkg.com/htmx.org@1.9.10"></script>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f4f7f6; }
        header { background-color: #333; color: white; padding: 1rem; text-align: center; }
        main { max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
        h1 { margin: 0; }
        .log-entry { 
          background-color: #fff; 
          border: 1px solid #ddd; 
          border-radius: 8px; 
          padding: 1rem; 
          margin-bottom: 1rem; 
          box-shadow: 0 2px 4px rgba(0,0,0,0.05); 
        }
        .log-entry p { margin: 0.5rem 0; }
        pre { background-color: #eee; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        details { margin-top: 1rem; }
        summary { cursor: pointer; font-weight: bold; }
      </style>
    </head>
    <body>
      <header>
        <h1>Connect50 - GroupsWatcher Alerts</h1>
      </header>
      <main>
        <div id="log-container" 
             hx-get="/logs" 
             hx-trigger="load, every 2s" 
             hx-swap="innerHTML">
          <p>Loading logs...</p>
        </div>
      </main>
    </body>
    </html>
  `);
});

/**
 * The data endpoint for HTMX.
 * No change here, it just calls the rewritten getLogsAsHtml().
 */
app.get('/logs', adminAuth, async (req, res) => {
  const logsHtml = await getLogsAsHtml();
  res.send(logsHtml);
});

/**
 * The Webhook endpoint.
 * This now calls logWebhookToDb() instead of logWebhookToFile().
 */
app.post('/api/webhook', webhookWhitelist, (req, res) => {
  // Log to console (still useful)
  console.log('--- 🔔 New Alert Received! ---');
  
  // Log to REDIS (fire-and-forget, no need to await)
  logWebhookToDb(req);

  res.status(200).send('Alert received successfully');
});

// --- Server Start ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Webhook server listening on http://0.0.0.0:${PORT}`);
  console.log(`📡 Ready for Tailscale Funnel on port ${PORT}`);
  console.log(`🔑 Admin dashboard available on your Tailscale URL`);
  console.log(`💾 Logging data to: Redis (${process.env.REDIS_URL})`);
});
