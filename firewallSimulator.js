/*
Firewall = traffic allow/block system
Simulates firewall rules with priority & direction
NOT real networking — only logic (beginner)
*/

// Config-driven firewall (single source of rules)
const firewallConfig = {
  // Default policy: DENY (default deny and least privilege)
  defaultAction: 'DENY', // default deny ensures least privilege

  // Low-level prioritized rules (can be extended)
  rules: [
    // Keep a few example prioritized rules
    { priority: 5, action: 'ALLOW', port: 80, protocol: 'TCP', direction: 'INBOUND', reason: 'Allow HTTP inbound' },
    { priority: 10, action: 'ALLOW', port: 443, protocol: 'TCP', direction: 'INBOUND', reason: 'Allow HTTPS inbound' }
  ],

  // Higher-level config lists (kept in same config for clarity)
  blockedIPs: ['192.168.1.200'],
  allowedIPs: ['127.0.0.1', '::1', '192.168.1.10'], // localhost allowed for demo
  allowedMethods: ['GET', 'POST'],
  blockedPaths: ['/admin'],
  allowedProtocols: ['HTTP', 'HTTPS']
};

// Decision log to store decisions for analysis
const decisionLog = [];

// --- Helper checkers (small and clear) ---
function checkIP(ruleIP, ip) {
  if (!ruleIP) return true; // rule does not restrict IP
  return ruleIP === ip; // exact match only (simple)
}

function checkMethod(ruleMethod, method) {
  if (!ruleMethod) return true;
  return ruleMethod.toUpperCase() === method.toUpperCase();
}

function checkPath(rulePath, path) {
  if (!rulePath) return true;
  // Simple match: exact or prefix (e.g., '/admin' matches '/admin' and '/admin/settings')
  return path === rulePath || path.startsWith(rulePath + '/');
}

function checkProtocol(ruleProtocol, protocol) {
  if (!ruleProtocol) return true;
  return ruleProtocol.toUpperCase() === protocol.toUpperCase();
}

function checkPort(rulePort, port) {
  if (!rulePort) return true;
  return rulePort === port;
}

// Convert high-level lists into rule objects so everything uses priority logic
function buildEffectiveRules() {
  const listRules = [];

  // Blocked IPs -> high priority DENY
  for (let i = 0; i < firewallConfig.blockedIPs.length; i++) {
    const ip = firewallConfig.blockedIPs[i];
    listRules.push({ priority: 1, action: 'DENY', ip: ip, reason: `Blocked IP ${ip}` });
  }

  // Blocked paths -> high priority DENY
  for (let i = 0; i < firewallConfig.blockedPaths.length; i++) {
    const p = firewallConfig.blockedPaths[i];
    listRules.push({ priority: 2, action: 'DENY', path: p, reason: `Blocked path ${p}` });
  }

  // Allow specific methods (lower priority)
  for (let i = 0; i < firewallConfig.allowedMethods.length; i++) {
    const m = firewallConfig.allowedMethods[i];
    listRules.push({ priority: 50, action: 'ALLOW', method: m, reason: `Allow method ${m}` });
  }

  // Allow specific protocols (lower priority)
  for (let i = 0; i < firewallConfig.allowedProtocols.length; i++) {
    const pr = firewallConfig.allowedProtocols[i];
    listRules.push({ priority: 60, action: 'ALLOW', protocol: pr, reason: `Allow protocol ${pr}` });
  }

  // Allow IPs (lower priority than deny lists)
  for (let i = 0; i < firewallConfig.allowedIPs.length; i++) {
    const ip = firewallConfig.allowedIPs[i];
    listRules.push({ priority: 40, action: 'ALLOW', ip: ip, reason: `Allow IP ${ip}` });
  }

  // Merge with explicit rules
  return listRules.concat(firewallConfig.rules.slice());
}

// Check a single rule against a request object (supports ip, method, path, protocol, port)
function matchesRuleObj(rule, req) {
  if (!checkIP(rule.ip, req.ip)) return false;
  if (!checkMethod(rule.method, req.method)) return false;
  if (!checkPath(rule.path, req.path)) return false;
  if (!checkProtocol(rule.protocol, req.protocol)) return false;
  if (!checkPort(rule.port, req.port)) return false;
  if (rule.direction && rule.direction.toUpperCase() !== req.direction.toUpperCase()) return false;
  return true;
}

// Generic evaluator used by both middleware and simulation routes
function evaluateFirewallRequest(reqObj) {
  const rules = buildEffectiveRules().slice().sort((a, b) => a.priority - b.priority);

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    if (matchesRuleObj(rule, reqObj)) {
      const outcome = rule.action === 'ALLOW' ? 'ALLOWED' : 'BLOCKED';
      const reason = rule.reason || (rule.action === 'ALLOW' ? 'Allowed by rule' : 'Blocked by rule');
      const entry = {
        timestamp: new Date().toISOString(),
        ip: reqObj.ip,
        method: reqObj.method || null,
        path: reqObj.path || null,
        decision: outcome,
        reason: reason
      };
      decisionLog.push(entry);
      return { decision: outcome, reason: reason, rulePriority: rule.priority };
    }
  }

  // No matching rule: default deny
  const entry = {
    timestamp: new Date().toISOString(),
    ip: reqObj.ip,
    method: reqObj.method || null,
    path: reqObj.path || null,
    decision: 'BLOCKED',
    reason: 'Default deny'
  };
  decisionLog.push(entry);
  return { decision: 'BLOCKED', reason: 'Default deny', rulePriority: null };
}

// Keep original simulateFirewall for backward compatibility (simulation using ip/port/protocol)
function simulateFirewall(ip, port, protocol, direction = 'INBOUND') {
  const reqObj = { ip: ip, port: port, protocol: String(protocol).toUpperCase(), direction: String(direction).toUpperCase() };
  return evaluateFirewallRequest(reqObj);
}

// --- Test simulation cases (simple) ---
console.log('\nSimulation Test 1: Allowed HTTP (local)');
let s1 = simulateFirewall('127.0.0.1', 80, 'TCP', 'INBOUND');
console.log('Result:', s1.decision, '-', s1.reason);

console.log('\nSimulation Test 2: Blocked by blocked IP');
let s2 = simulateFirewall('192.168.1.200', 22, 'TCP', 'INBOUND');
console.log('Result:', s2.decision, '-', s2.reason);

console.log('\nSimulation Test 3: Blocked path');
let s3 = (() => {
  const req = { ip: '127.0.0.1', method: 'GET', path: '/admin', protocol: 'HTTP', direction: 'INBOUND' };
  return evaluateFirewallRequest(req);
})();
console.log('Result:', s3.decision, '-', s3.reason);

// --- Application-level firewall middleware & server routes ---
/*
Middleware-based application firewall (Layer 7 demo)
- Runs for every incoming request before route handlers
- Examines IP, method, path and protocol
- Simple, readable: suitable for interviews and demos
*/

// Minimal Express server to demo the middleware-based firewall
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Helper: normalize client IP (handle ::ffff:127.0.0.1)
function normalizeIp(raw) {
  if (!raw) return '';
  const first = String(raw).split(',')[0].trim();
  if (first.indexOf('::ffff:') !== -1) return first.split('::ffff:').pop();
  return first;
}

// Firewall middleware: inspects real incoming HTTP requests
function firewallMiddleware(req, res, next) {
  const clientIp = normalizeIp(req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.ip);
  const method = req.method;
  const path = req.path;
  const protocol = (req.protocol || 'http').toUpperCase();
  const direction = 'INBOUND'; // application-level requests are inbound

  const result = evaluateFirewallRequest({ ip: clientIp, method: method, path: path, protocol: protocol, direction: direction });

  if (result.decision === 'ALLOWED') {
    // request proceeds to the route handler
    return next();
  } else {
    // request blocked at application layer
    return res.status(403).json({ status: 'BLOCKED', reason: result.reason });
  }
}

// Apply middleware globally so all routes are protected
app.use(firewallMiddleware);

// Protected routes
app.get('/public', (req, res) => {
  res.json({ status: 'ALLOWED', message: 'Public resource reached' });
});

app.get('/admin', (req, res) => {
  res.json({ status: 'ALLOWED', message: 'Admin area (should be blocked by firewall)' });
});

// POST /data: allow only from certain IPs (add a specific rule here for demo)
// Adding an explicit rule: allow POST /data from localhost with medium priority
firewallConfig.rules.push({ priority: 20, action: 'ALLOW', method: 'POST', path: '/data', ip: '127.0.0.1', reason: 'Allow local POST /data' });

app.post('/data', express.json(), (req, res) => {
  res.json({ status: 'ALLOWED', message: 'Data accepted' });
});

// Route to view recent firewall decisions (for demo/audit)
app.get('/firewall-log', (req, res) => {
  res.json({ entries: decisionLog });
});

// Example simulation endpoint (keeps previous behavior; still passes middleware)
app.get('/check-traffic', (req, res) => {
  const { ip, port, protocol, direction } = req.query;
  if (!ip || !port || !protocol) {
    return res.status(400).json({ status: 'ERROR', reason: 'Missing ip, port, or protocol query parameter' });
  }
  const portNum = Number(port);
  if (Number.isNaN(portNum)) {
    return res.status(400).json({ status: 'ERROR', reason: 'Port must be a number' });
  }
  const result = simulateFirewall(ip, portNum, protocol, direction || 'INBOUND');
  return res.json({ status: result.decision, reason: result.reason });
});

app.listen(PORT, () => {
  console.log(`\nApplication-level firewall server running: http://localhost:${PORT}`);
  console.log('Try: http://localhost:' + PORT + '/public  (should be allowed)');
  console.log('Try: http://localhost:' + PORT + '/admin   (should be blocked)');
  console.log('POST: curl -X POST http://localhost:' + PORT + '/data  (allowed only from localhost)');
});

// Notes:
// - Middleware is used so every request is checked before reaching routes.
// - This is an application-layer demo (Layer 7). It does not inspect raw packets.
// - Limitations: in-memory logs, simple exact/prefix matches, no rate-limiting.
