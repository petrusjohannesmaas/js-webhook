// 1. Imports
const express = require('express');
const path = require('path'); // <-- Added for serving files
const basicAuth = require('basic-auth');
require('dotenv').config();
const { createClient } = require('redis');

// 2. App & Environment Config
const app = express();
const PORT = 3000;

// --- NEW: Serve static files from 'public' directory ---
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
 * REWRITTEN: logWebhookToDb()
 * No changes needed here, this function is still correct.
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
 * Replaces getLogsAsHtml(). It now fetches logs based on status
 * and builds the new HTML card component.
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
  // We use the raw timestamp from the ID for comparison
  const newestTimestamp = logIds[0] ? logIds[0].split(':')[1] : 0;
  
  // -- Polling & View Swap Logic --
  // We dynamically add the polling trigger ONLY to the 'unreviewed' view.
  // We also include the HTMX snippet to swap the button text.
  let pollingTrigger = '';
  let buttonSwapHtml = '';
  
  if (status === 'unreviewed') {
    pollingTrigger = 'hx-trigger="every 2s"'; // Poll only this view
    buttonSwapHtml = `
      <div id="swap-to-reviewed" hx-swap-oob="innerHTML:#view-toggle">
        <svg class="icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m2.25 15.75 5.159-5.159a2.25 2.25 0 0 1 3.182 0l5.159 5.159m-1.5-1.5 1.409-1.409a2.25 2.25 0 0 1 3.182 0l1.409 1.409m-7.5 7.5h.008v.008h-.008v-.008Zm0 0h.008v.008h-.008v-.008Zm-3.75 0h.008v.008h-.008v-.008Zm0 0h.008v.008h-.008v-.008Z" /></svg>
        View Reviewed
      </div>
    `;
  } else {
    // This is the 'reviewed' view
    buttonSwapHtml = `
      <div id="swap-to-unreviewed" hx-swap-oob="innerHTML:#view-toggle"
           hx-get="/logs/unreviewed"
           hx-target="#log-container"
           hx-swap="innerHTML"
           hx-push-url="true"
           hx-indicator="#log-container">
        <svg class="icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m19.5 14.25-6.22-6.22a2.25 2.25 0 0 0-3.18 0l-6.22 6.22m15 0H3.75" /></svg>
        View Unreviewed
      </div>
    `;
  }
  
  // Map each log object to the new HTML card
  const logCards = logs.map((log, index) => {
    if (!log) return '';
    try {
      const payload = JSON.parse(log.payload);
      const headers = JSON.parse(log.headers); // We still parse it, though not used in UI
      
      // Helper function for safe links
      const createLink = (url, text) => {
        if (!url) return 'N/A';
        return `<a href="${url}" target="_blank" rel="noopener noreferrer">${text || url}</a>`;
      };

      // UPDATED HTML card based on your 'Params'
      return `
        <div class="log-entry">
          <div class="log-header">
            <span class="log-message">${payload.message || 'N/A'}</span>
            <span class="status-badge status-${log.status}">${log.status}</span>
          </div>
          
          <p><strong>Timestamp:</strong> ${payload.data?.time_posted || 'N/A'}</p>
          <p><strong>Post Text:</strong> ${payload.data?.post_text || 'N/A'}</p>
          <p><strong>Profile:</strong> ${createLink(payload.data?.profile_url, payload.data?.profile_name)}</p>
          <p><strong>Post URL:</strong> ${createLink(payload.data?.post_url, 'View Post')}</p>
          <p><strong>Group URL:</strong> ${createLink(payload.data?.group_url, 'View Group')}</p>

          </div>
      `;
    } catch (parseErr) {
      return `<div class="log-entry"><p>Error parsing log entry: ${logIds[index]}</p></div>`;
    }
  }).join('');
  
  // Return the full HTML block, including the grid wrapper
  // We add the buttonSwapHtml here, which HTMX will process using 'hx-swap-oob'
  return `
    ${buttonSwapHtml} 
    <div 
      class="log-grid" 
      data-newest-timestamp="${newestTimestamp}"
      ${pollingTrigger}
    >
      ${logCards}
    </div>
  `;
};

// --- Routes ---

/**
 * REFACTORED: Root route
 * Serves the static index.html file.
 */
app.get('/', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/**
 * NEW: Unreviewed Logs Route
 * Serves the HTML fragment for unreviewed logs.
 */
app.get('/logs/unreviewed', adminAuth, async (req, res) => {
  const logsHtml = await getLogsByStatus('unreviewed');
  res.send(logsHtml);
});

/**
 * NEW: Reviewed Logs Route
 * Serves the HTML fragment for reviewed logs.
 */
app.get('/logs/reviewed', adminAuth, async (req, res) => {
  const logsHtml = await getLogsByStatus('reviewed');
  res.send(logsHtml);
});

/**
 * Webhook endpoint
 * No change here, it still calls logWebhookToDb()
 */
app.post('/api/webhook', webhookWhitelist, (req, res) => {
  console.log('--- 🔔 New Alert Received! ---');
  logWebhookToDb(req);
  res.status(200).send('Alert received successfully');
});

// --- Server Start ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Webhook server listening on http://0.0.0.0:${PORT}`);
  console.log(`📡 Ready for Tailscale Funnel on port ${PORT}`);
  console.log(`🔑 Admin dashboard available on your Tailscale URL`);
  console.log(`💾 Logging data to: Redis (${process.env.REDIS_URL || 'redis://127.0.0.1:6379'})`);
});