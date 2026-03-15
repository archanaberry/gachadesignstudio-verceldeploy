// serverdeploy/api/test.js
import { createHash } from 'crypto';

// Security Configuration
const SECURITY = {
  // Rate limiting per IP
  RATE_LIMIT_WINDOW: 60000, // 1 minute
  RATE_LIMIT_MAX: 10, // requests per window
  // Internal network only
  ALLOWED_IP_RANGES: [
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '100.64.0.0/10', // Tailscale/WireGuard
  ],
  // Secret token for additional layer
  INTERNAL_TOKEN: process.env.INTERNAL_TOKEN || 'gacha-internal-2026',
};

// In-memory store (use Redis in production)
const requestStore = new Map();

// IP validation helper
function isAllowedIP(ip) {
  if (!ip) return false;
  // Check localhost
  if (ip === '127.0.0.1' || ip === '::1') return true;
  // Check private ranges (simplified)
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./,
  ];
  return privateRanges.some(range => range.test(ip));
}

// Rate limit checker
function checkRateLimit(clientId) {
  const now = Date.now();
  const windowStart = now - SECURITY.RATE_LIMIT_WINDOW;
  
  if (!requestStore.has(clientId)) {
    requestStore.set(clientId, []);
  }
  
  const requests = requestStore.get(clientId).filter(time => time > windowStart);
  
  if (requests.length >= SECURITY.RATE_LIMIT_MAX) {
    return { allowed: false, retryAfter: Math.ceil((requests[0] + SECURITY.RATE_LIMIT_WINDOW - now) / 1000) };
  }
  
  requests.push(now);
  requestStore.set(clientId, requests);
  return { allowed: true };
}

// Generate fingerprint for logging
function generateFingerprint(req) {
  const data = `${req.headers['user-agent'] || ''}${req.headers['accept-language'] || ''}${Date.now()}`;
  return createHash('sha256').update(data).digest('hex').substring(0, 16);
}

export default async function handler(req, res) {
  const startTime = Date.now();
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                   req.headers['x-real-ip'] || 
                   req.socket?.remoteAddress || 
                   'unknown';
  
  const fingerprint = generateFingerprint(req);
  
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Internal-Token');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  // Security Layer 1: IP Whitelist (Internal Only)
  if (!isAllowedIP(clientIP)) {
    console.warn(`[BLOCKED] External access attempt from ${clientIP} [${fingerprint}]`);
    res.setHeader('X-Blocked-Reason', 'External IP not allowed');
    return res.status(403).send(`⛔ ACCESS DENIED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Timestamp: ${new Date().toISOString()}
Request ID: ${fingerprint}
Client IP: ${clientIP}
Status: FORBIDDEN - External access prohibited
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This resource is only accessible from internal network.
Contact administrator if you believe this is an error.`);
  }
  
  // Security Layer 2: Token Validation (Optional but recommended)
  const internalToken = req.headers['x-internal-token'] || req.query.token;
  if (internalToken !== SECURITY.INTERNAL_TOKEN) {
    console.warn(`[BLOCKED] Invalid token from ${clientIP} [${fingerprint}]`);
    res.setHeader('X-Blocked-Reason', 'Invalid authentication token');
    return res.status(401).send(`🔒 AUTHENTICATION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Timestamp: ${new Date().toISOString()}
Request ID: ${fingerprint}
Client IP: ${clientIP}
Status: UNAUTHORIZED - Valid internal token required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Security Layer 3: Rate Limiting
  const rateCheck = checkRateLimit(clientIP);
  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', rateCheck.retryAfter);
    res.setHeader('X-RateLimit-Limit', SECURITY.RATE_LIMIT_MAX);
    res.setHeader('X-RateLimit-Remaining', 0);
    return res.status(429).send(`⏳ RATE LIMITED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Timestamp: ${new Date().toISOString()}
Request ID: ${fingerprint}
Client IP: ${clientIP}
Status: TOO MANY REQUESTS
Retry After: ${rateCheck.retryAfter} seconds
Limit: ${SECURITY.RATE_LIMIT_MAX} requests per ${SECURITY.RATE_LIMIT_WINDOW/1000}s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Success Response (Curl-style)
  const responseTime = Date.now() - startTime;
  const remainingRequests = SECURITY.RATE_LIMIT_MAX - (requestStore.get(clientIP)?.length || 0);
  
  res.setHeader('X-Response-Time', `${responseTime}ms`);
  res.setHeader('X-RateLimit-Limit', SECURITY.RATE_LIMIT_MAX);
  res.setHeader('X-RateLimit-Remaining', remainingRequests);
  res.setHeader('X-Request-ID', fingerprint);
  res.setHeader('X-Internal-Status', 'VERIFIED');
  
  console.log(`[ALLOWED] ${clientIP} [${fingerprint}] - ${responseTime}ms`);
  
  res.status(200).send(`✅ API STATUS: OPERATIONAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎨 Gacha Design Studio - Internal API
📋 Endpoint: /api/test
🔐 Security: Internal Network + Token Verified

⏱️  Performance Metrics:
   Response Time: ${responseTime}ms
   Request ID: ${fingerprint}
   Timestamp: ${new Date().toISOString()}

🔒 Security Headers:
   Client IP: ${clientIP}
   Rate Limit: ${remainingRequests}/${SECURITY.RATE_LIMIT_MAX} remaining
   Token Status: VALID

💡 Usage:
   curl -H "X-Internal-Token: ${SECURITY.INTERNAL_TOKEN}" \\
        https://your-domain.com/api/test

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌸 Stay kawaii, stay secure! 🌸`);
}
