// 1. Imports
const express = require('express');
const path = require('path'); // <-- Added for serving files
const basicAuth = require('basic-auth');
require('dotenv').config();
const { createClient } = require('redis');

// 2. App & Environment Config
const app = express();
const PORT = 3000;

// --- Serve static files from 'public' directory ---
app.use(express.static(path.join(__dirname, 'public')));

// --- Redis Client Setup ---
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
});

redisClient.on('error', (err) => {
  console.error('Redis Client Error', err);
});

(async () => {
  try {
    await redisClient.connect();
    console.log('✅ Successfully connected to Redis.');
  } catch (err) {
    console.error('---!!! FAILED TO CONNECT TO REDIS !!!---', err);
  }
})();

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
 * logWebhookToDb()
 * No changes needed here.
 */
const logWebhookToDb = async (req) => {
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
    multi.HSET(logId, logEntry);
    multi.SADD('logs:unreviewed', logId);
    await multi.exec();
    console.log(`[Redis] Log saved: ${logId}`);
  } catch (err) {
    console.error('Failed to write log to Redis:', err);
  }
};

/**
 * REFACTORED: getLogsByStatus()
 *
 * This function is now much simpler. It only returns the log grid.
 * All polling and button-swapping logic has been REMOVED and
 * now lives in the static HTML files, which is more robust.
 */
const getLogsByStatus = async (status) => {
  const redisSet = `logs:${status}`; // 'logs:unreviewed' or 'logs:reviewed'
  let logIds;

  try {
    logIds = await redisClient.SMEMBERS(redisSet);
  } catch (err) {
    console.error(`Redis error getting ${status} logs:`, err);
    return '<p>Error connecting to Redis.</p>';
  }

  // Handle the case of no logs
  if (logIds.length === 0) {
    return `<div class="log-entry"><p>No ${status} logs found.</p></div>`;
  }

  // Sort IDs to show newest first
  logIds.sort((a, b) => b.split(':')[1] - a.split(':')[1]);

  const multi = redisClient.multi();
  logIds.forEach(id => multi.HGETALL(id));
  
  let logs;
  try {
    logs = await multi.exec();
  } catch (err) {
    console.error('Redis error fetching log details:', err);
    return '<p>Error fetching log details.</p>';
  }

  // Get timestamp of the newest log for notification script
  const newestTimestamp = logIds[0] ? logIds[0].split(':')[1] : 0;
  
  // Map each log object to the new HTML card
  const logCards = logs.map((log, index) => {
    if (!log) return ''; // Handle potential null entry
    try {
      const payload = JSON.parse(log.payload);
      const logId = logIds[index]; // <-- NEW: Get the unique Redis key
      
      // Helper function for safe links
      const createLink = (url, text) => {
        if (!url) return 'N/A';
        // Ensure URL has a protocol
        let safeUrl = url.startsWith('http') ? url : `https://${url}`;
        return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${text || url}</a>`;
      };

      // --- NEW: Add a review button only if the status is 'unreviewed' ---
      let reviewButton = '';
      if (log.status === 'unreviewed') {
        reviewButton = `
          <button 
            class="review-button"
            hx-post="/log/${logId}/review"
            hx-target="closest .log-entry"
            hx-swap="outerHTML"
            hx-confirm="Are you sure you want to mark this log as reviewed?"
          >
            Mark as Reviewed
          </button>
        `;
      }
      // -----------------------------------------------------------------

      // UPDATED HTML card
      return `
        <div class="log-entry" id="log-${logId}">
          <div class="log-header">
            <span class="log-message">${payload.message || 'N/A'}</span>
            <span class="status-badge status-${log.status}">${log.status}</span>
          </div>
          
          <p><strong>Timestamp:</strong> ${payload.data?.time_posted || 'N/A'}</p>
          <p><strong>Post Text:</strong> ${payload.data?.post_text || 'N/A'}</p>
          <p><strong>Profile:</strong> ${createLink(payload.data?.profile_url, payload.data?.profile_name)}</p>
          <p><strong>Post URL:</strong> ${createLink(payload.data?.post_url, 'View Post')}</p>
          <p><strong>Group URL:</strong> ${createLink(payload.data?.group_url, 'View Group')}</p>

          ${reviewButton} </div>
      `;
    } catch (parseErr) {
      return `<div class="log-entry"><p>Error parsing log entry: ${logIds[index]}</p></div>`;
    }
  }).join('');
  
  // Return the full HTML block.
  return `
    <div 
      class="log-grid" 
      data-newest-timestamp="${newestTimestamp}"
    >
      ${logCards}
    </div>
  `;
};

// --- Routes ---

/**
 * Root route
 * Serves the static index.html file (Unreviewed logs)
 */
app.get('/', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/**
 * NEW: Reviewed Logs Route
 * Serves the static reviewed.html file
 */
app.get('/reviewed', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reviewed.html'));
});

/**
 * HTMX: Unreviewed Logs Endpoint
 * Serves the HTML fragment for unreviewed logs.
 */
app.get('/logs/unreviewed', adminAuth, async (req, res) => {
  const logsHtml = await getLogsByStatus('unreviewed');
  res.send(logsHtml);
});

/**
 * HTMX: Reviewed Logs Endpoint
 * Serves the HTML fragment for reviewed logs.
 */
app.get('/logs/reviewed', adminAuth, async (req, res) => {
  const logsHtml = await getLogsByStatus('reviewed');
  res.send(logsHtml);
});

/**
 * Webhook endpoint
 */
app.post('/api/webhook', webhookWhitelist, (req, res) => {
  console.log('--- 🔔 New Alert Received! ---');
  logWebhookToDb(req);
  res.status(200).send('Alert received successfully');
});

/**
 * NEW: Mark a log as reviewed
 * This endpoint is called by the HTMX button from the 'unreviewed' page.
 */
app.post('/log/:id/review', adminAuth, async (req, res) => {
  const logId = req.params.id;
  
  // Basic validation to prevent bad requests
  if (!logId || !logId.startsWith('log:')) {
    return res.status(400).send('<p>Invalid Log ID.</p>');
  }

  try {
    console.log(`[Redis] Marking as reviewed: ${logId}`);
    
    // Use a MULTI transaction to do this atomically
    const multi = redisClient.multi();
    
    // 1. Set the 'status' field of the hash to 'reviewed'
    multi.HSET(logId, 'status', 'reviewed');
    
    // 2. Move the ID from the unreviewed set to the reviewed set
    multi.SMOVE('logs:unreviewed', 'logs:reviewed', logId);
    
    // Execute the transaction
    await multi.exec();
    
    // Send an empty 200 OK. 
    // Because the button has hx-target="closest .log-entry" and hx-swap="outerHTML",
    // HTMX will replace the entire card with this empty string, making it disappear.
    res.status(200).send(''); 

  } catch (err) {
    console.error('Redis error marking log as reviewed:', err);
    res.status(500).send('<p>Server error. Could not update log.</p>');
  }
});

// --- Server Start ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Webhook server listening on http://0.0.0.0:${PORT}`);
  console.log(`📡 Ready for Tailscale Funnel on port ${PORT}`); // <-- FIXED LINE
  console.log(`🔑 Admin dashboard available on your Tailscale URL`);
  console.log(`💾 Logging data to: Redis (${process.env.REDIS_URL || 'redis://127.0.0.1:6379'})`);
});