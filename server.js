// server.js
// Simple Express server that uses the firewall middleware from firewallSimulator.js
// Uses dotenv for env config, morgan for request logging, and express-rate-limit for basic DoS protection

require('dotenv').config(); // Load .env values
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { firewallMiddleware, decisionLog } = require('./firewallSimulator');

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limit config from environment (window in minutes)
const windowMinutes = Number(process.env.RATE_LIMIT_WINDOW) || 1; // minutes
const maxRequests = Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 20;
const windowMs = windowMinutes * 60 * 1000;

// Basic rate limiter: blocks excessive requests with 429
const limiter = rateLimit({
  windowMs: windowMs,
  max: maxRequests,
  message: { status: 'ERROR', reason: 'Too many requests - slow down' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Trust proxy so req.ip and x-forwarded-for work behind proxies (safe for demos)
app.set('trust proxy', true);

// Request logging: helps investigate incidents and trace requests
// Morgan logs method, path and status quickly. Useful for security auditing.
app.use(morgan('tiny'));

// Apply firewall middleware first so policies are enforced for every request
app.use(firewallMiddleware);

// Apply rate limiter globally (after firewall in this demo flow)
app.use(limiter);

// Basic routes
app.get('/public', (req, res) => {
  res.json({ status: 'ALLOWED', message: 'Public resource reached' });
});

app.get('/admin', (req, res) => {
  res.json({ status: 'ALLOWED', message: 'Admin area (should be blocked by firewall)' });
});

app.post('/data', express.json(), (req, res) => {
  res.json({ status: 'ALLOWED', message: 'Data accepted' });
});

// View recent firewall decisions (demo auditing)
app.get('/firewall-log', (req, res) => {
  return res.json({ entries: decisionLog });
});

app.listen(PORT, () => {
  console.log(`\nServer running at http://localhost:${PORT}`);
  console.log('Make requests: GET /public, GET /admin, POST /data, GET /firewall-log');
});
