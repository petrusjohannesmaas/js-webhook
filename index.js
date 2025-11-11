// 1. Imports
const express = require('express');
const fs = require('fs').promises; // Use promises for async file I/O
const path = require('path');
const basicAuth = require('basic-auth');
require('dotenv').config(); // Load variables from .env

// 2. App & Environment Config
const app = express();
const PORT = 3000;
const LOG_FILE_PATH = path.join(__dirname, process.env.LOG_FILE || 'webhook_logs.jsonl');

// --- Middleware ---

// This middleware parses incoming JSON payloads
app.use(express.json());

// Middleware to whitelist GroupsWatcher requests
const webhookWhitelist = (req, res, next) => {
  const sentFrom = req.headers['x-sent-from'];
  
  if (sentFrom === 'GroupsWatcher.com') {
    next(); // Request is allowed, continue to the route handler
  } else {
    // Request is from an unknown source
    console.warn(`[FORBIDDEN] Blocked request from ${req.ip}. Header 'x-sent-from' was: ${sentFrom}`);
    res.status(403).send('Forbidden: Invalid Source');
  }
};

// Middleware for Basic Authentication on the dashboard
const adminAuth = (req, res, next) => {
  const user = basicAuth(req);

//   // --- ADD THESE TWO LINES FOR DEBUGGING ---
//   console.log('ENV VARS (SERVER):', { user: process.env.ADMIN_USER, pass: process.env.ADMIN_PASS });
//   console.log('AUTH ATTEMPT (BROWSER):', user);
  // ------------------------------------------

  // Check if credentials are provided and match .env
  if (user && 
      user.name === process.env.ADMIN_USER && 
      user.pass === process.env.ADMIN_PASS) {
    return next(); // Authorized
  }

  // Not authorized. Send 401 and request credentials
  res.setHeader('WWW-Authenticate', 'Basic realm="Admin Dashboard"');
  res.status(401).send('Authentication required.');
};

// --- Helper Functions ---

/**
 * Asynchronously appends a log entry to the JSONL file.
 * We use JSON Lines (JSONL) format (one JSON object per line)
 * as it's the best way to manage a log file.
 */
const logWebhookToFile = async (req) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    sourceIp: req.ip,
    headers: req.headers,
    payload: req.body
  };

  try {
    // Append the log entry as a new line
    await fs.appendFile(LOG_FILE_PATH, JSON.stringify(logEntry) + '\n');
  } catch (err) {
    console.error('Failed to write to log file:', err);
  }
};

/**
 * Reads the log file and formats it as HTML for the dashboard.
 */
const getLogsAsHtml = async () => {
  let fileContent;
  try {
    fileContent = await fs.readFile(LOG_FILE_PATH, 'utf8');
  } catch (err) {
    // If file doesn't exist (e.g., no logs yet), return a message
    if (err.code === 'ENOENT') {
      return '<div class="log-entry"><p>No logs received yet.</p></div>';
    }
    console.error('Failed to read log file:', err);
    return '<p>Error reading log file.</p>';
  }

  const lines = fileContent.trim().split('\n');
  
  // Reverse the lines to show the newest logs first
  // Then map each JSON line to an HTML block
  return lines.reverse().map(line => {
    try {
      const log = JSON.parse(line);
      // Format the HTML. Using <pre> preserves JSON formatting.
      return `
        <div class="log-entry">
          <p><strong>Timestamp:</strong> ${log.timestamp}</p>
          <p><strong>Message:</strong> ${log.payload.message || 'N/A'}</p>
          <p><strong>Post Text:</strong> ${log.payload.data?.post_text || 'N/A'}</p>
          <details>
            <summary>View Full Payload</summary>
            <pre>${JSON.stringify(log.payload, null, 2)}</pre>
          </details>
          <details>
            <summary>View Headers</summary>
            <pre>${JSON.stringify(log.headers, null, 2)}</pre>
          </details>
        </div>
      `;
    } catch (parseErr) {
      return '<div class="log-entry"><p>Error parsing log entry.</p></div>'; // Handle corrupt lines
    }
  }).join('');
};


// --- Routes ---

/**
 * The main dashboard page.
 * This route is protected by admin authentication.
 */
app.get('/', adminAuth, (req, res) => {
  // This HTML document includes the HTMX script and the polling mechanism
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
 * This route is also protected. It returns only the HTML fragment
 * containing the formatted logs.
 */
app.get('/logs', adminAuth, async (req, res) => {
  const logsHtml = await getLogsAsHtml();
  res.send(logsHtml);
});

/**
 * The Webhook endpoint.
 * This route is protected by the GroupsWatcher whitelist.
 */
app.post('/api/webhook', webhookWhitelist, (req, res) => {
  // Log to console (optional, but good for debugging)
  console.log('--- 🔔 New Alert Received! ---');
  console.log('Timestamp:', new Date().toISOString());
  console.log('Payload:', req.body);
  console.log('---------------------------------');
  
  // Log to file (fire-and-forget, no need to await)
  logWebhookToFile(req);

  // Send the 200 OK response immediately
  res.status(200).send('Alert received successfully');
});

// --- Server Start ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Webhook server listening on http://0.0.0.0:${PORT}`);
  console.log(`📡 Ready for Tailscale Funnel on port ${PORT}`);
  console.log(`🔑 Admin dashboard available on your Tailscale URL (e.g., http://connect50.tailcf844f.ts.net)`);
  console.log(`💾 Logging data to: ${LOG_FILE_PATH}`);
});