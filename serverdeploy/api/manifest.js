// serverdeploy/api/manifest.js
import { createHash } from 'crypto';

const SECURITY = {
  RATE_LIMIT_WINDOW: 30000, // 30 seconds (stricter for manifest)
  RATE_LIMIT_MAX: 20,
  ALLOWED_IP_RANGES: ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'],
  INTERNAL_TOKEN: process.env.INTERNAL_TOKEN || 'gacha-internal-2026',
  HOMELAB_URL: process.env.HOMELAB_MANIFEST_URL || 'http://100.101.102.103:3000/manifest.json',
};

const requestStore = new Map();

function isAllowedIP(ip) {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === '::1') return true;
  const privateRanges = [/^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./, /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./];
  return privateRanges.some(range => range.test(ip));
}

function checkRateLimit(clientId) {
  const now = Date.now();
  const windowStart = now - SECURITY.RATE_LIMIT_WINDOW;
  if (!requestStore.has(clientId)) requestStore.set(clientId, []);
  const requests = requestStore.get(clientId).filter(time => time > windowStart);
  if (requests.length >= SECURITY.RATE_LIMIT_MAX) {
    return { allowed: false, retryAfter: Math.ceil((requests[0] + SECURITY.RATE_LIMIT_WINDOW - now) / 1000) };
  }
  requests.push(now);
  requestStore.set(clientId, requests);
  return { allowed: true, remaining: SECURITY.RATE_LIMIT_MAX - requests.length };
}

function generateFingerprint(req) {
  const data = `${req.headers['user-agent'] || ''}${req.headers['accept-language'] || ''}${Date.now()}`;
  return createHash('sha256').update(data).digest('hex').substring(0, 16);
}

export default async function handler(req, res) {
  const startTime = Date.now();
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  const fingerprint = generateFingerprint(req);
  
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Security checks
  if (!isAllowedIP(clientIP)) {
    console.warn(`[MANIFEST-BLOCKED] External IP: ${clientIP}`);
    return res.status(403).send(`ERROR 403: External access denied\nRequest ID: ${fingerprint}\nTimestamp: ${new Date().toISOString()}`);
  }
  
  const internalToken = req.headers['x-internal-token'] || req.query.token;
  if (internalToken !== SECURITY.INTERNAL_TOKEN) {
    return res.status(401).send(`ERROR 401: Invalid token\nRequest ID: ${fingerprint}`);
  }
  
  const rateCheck = checkRateLimit(clientIP);
  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', rateCheck.retryAfter);
    return res.status(429).send(`ERROR 429: Rate limited. Retry after ${rateCheck.retryAfter}s\nRequest ID: ${fingerprint}`);
  }
  
  try {
    // Fetch from homelab with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    
    const homelabRes = await fetch(SECURITY.HOMELAB_URL, {
      signal: controller.signal,
      headers: { 'X-Internal-Request': 'true' }
    });
    clearTimeout(timeout);
    
    if (!homelabRes.ok) {
      throw new Error(`Homelab returned ${homelabRes.status}`);
    }
    
    const manifestText = await homelabRes.text();
    const responseTime = Date.now() - startTime;
    
    // Raw text response (curl-style)
    res.setHeader('X-Response-Time', `${responseTime}ms`);
    res.setHeader('X-Request-ID', fingerprint);
    res.setHeader('X-RateLimit-Remaining', rateCheck.remaining);
    res.setHeader('Cache-Control', 'private, max-age=60'); // Cache 1 minute
    
    console.log(`[MANIFEST-OK] ${clientIP} [${fingerprint}] - ${manifestText.length} bytes`);
    
    res.status(200).send(manifestText);
    
  } catch (err) {
    console.error(`[MANIFEST-ERROR] ${err.message}`);
    res.status(502).send(`ERROR 502: Failed to fetch manifest\nDetails: ${err.message}\nRequest ID: ${fingerprint}`);
  }
}
