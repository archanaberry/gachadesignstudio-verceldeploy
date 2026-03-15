// serverdeploy/api/download.js
import { createHash } from 'crypto';
import { PassThrough } from 'stream';

const SECURITY = {
  // Keringanan untuk download: window lebih besar, limit lebih tinggi
  RATE_LIMIT_WINDOW: 300000, // 5 menit
  RATE_LIMIT_MAX: 5, // 5 download per 5 menit (lebih longgar tapi tetap terbatas)
  ALLOWED_IP_RANGES: ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'],
  INTERNAL_TOKEN: process.env.INTERNAL_TOKEN || 'gacha-internal-2026',
  HOMELAB_BASE: process.env.HOMELAB_DOWNLOAD_URL || 'http://100.101.102.103:3000/download',
  MAX_FILE_SIZE: 500 * 1024 * 1024, // 500MB max
  ALLOWED_EXTENSIONS: ['.gds', '.gdp', '.zip', '.png', '.gda'],
};

const requestStore = new Map();
const activeDownloads = new Map();

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

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export default async function handler(req, res) {
  const startTime = Date.now();
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
  const fingerprint = generateFingerprint(req);
  
  // Parse filename dari query ?filename= atau path /filename
  let filename = req.query.filename || req.query.file || '';
  if (!filename && req.url.includes('/')) {
    const parts = req.url.split('/');
    filename = parts[parts.length - 1].split('?')[0];
  }
  
  // Set headers awal
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  
  // Security Layer 1: IP Check
  if (!isAllowedIP(clientIP)) {
    console.warn(`[DL-BLOCKED] External IP: ${clientIP} attempting ${filename}`);
    return res.status(403).send(`⛔ DOWNLOAD BLOCKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: FORBIDDEN
Reason: External access not allowed
File: ${filename || 'N/A'}
Client IP: ${clientIP}
Request ID: ${fingerprint}
Timestamp: ${new Date().toISOString()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Security Layer 2: Token
  const internalToken = req.headers['x-internal-token'] || req.query.token;
  if (internalToken !== SECURITY.INTERNAL_TOKEN) {
    return res.status(401).send(`🔒 AUTHENTICATION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: UNAUTHORIZED
Request ID: ${fingerprint}
Timestamp: ${new Date().toISOString()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Security Layer 3: Rate Limit (khusus download, lebih longgar)
  const rateCheck = checkRateLimit(clientIP);
  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', rateCheck.retryAfter);
    return res.status(429).send(`⏳ DOWNLOAD RATE LIMITED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: TOO MANY REQUESTS
Retry After: ${rateCheck.retryAfter} seconds
Limit: ${SECURITY.RATE_LIMIT_MAX} downloads per ${SECURITY.RATE_LIMIT_WINDOW/60000} minutes
Request ID: ${fingerprint}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Validasi filename
  if (!filename) {
    return res.status(400).send(`❌ BAD REQUEST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: MISSING FILENAME
Usage: /api/download?filename=GachaDesignStudio.gds
Request ID: ${fingerprint}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Validasi extension
  const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  if (!SECURITY.ALLOWED_EXTENSIONS.includes(ext)) {
    return res.status(400).send(`❌ INVALID FILE TYPE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: FILE TYPE NOT ALLOWED
Extension: ${ext}
Allowed: ${SECURITY.ALLOWED_EXTENSIONS.join(', ')}
Request ID: ${fingerprint}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
  
  // Sanitasi filename (basic)
  const sanitizedFilename = filename.replace(/[<>:"/\\|?*]/g, '_');
  
  try {
    const downloadId = `${fingerprint}-${Date.now()}`;
    const url = `${SECURITY.HOMELAB_BASE}/${encodeURIComponent(sanitizedFilename)}`;
    
    console.log(`[DL-START] ${clientIP} [${fingerprint}] -> ${sanitizedFilename}`);
    
    // Fetch dengan progress tracking
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout
    
    const homelabRes = await fetch(url, {
      signal: controller.signal,
      headers: { 'X-Internal-Request': 'true' }
    });
    clearTimeout(timeout);
    
    if (homelabRes.status === 404) {
      return res.status(404).send(`❌ FILE NOT FOUND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: 404 NOT FOUND
File: ${sanitizedFilename}
Source: Homelab storage
Request ID: ${fingerprint}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    }
    
    if (!homelabRes.ok) {
      throw new Error(`Homelab returned ${homelabRes.status}`);
    }
    
    const contentLength = homelabRes.headers.get('content-length');
    const totalSize = contentLength ? parseInt(contentLength) : null;
    
    if (totalSize && totalSize > SECURITY.MAX_FILE_SIZE) {
      return res.status(413).send(`❌ FILE TOO LARGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: PAYLOAD TOO LARGE
File: ${sanitizedFilename}
Size: ${formatBytes(totalSize)}
Max Allowed: ${formatBytes(SECURITY.MAX_FILE_SIZE)}
Request ID: ${fingerprint}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    }
    
    // Setup response headers untuk download
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizedFilename}"`);
    res.setHeader('X-Download-ID', downloadId);
    res.setHeader('X-Request-ID', fingerprint);
    res.setHeader('X-RateLimit-Remaining', rateCheck.remaining);
    
    // Track progress
    let downloadedBytes = 0;
    const reader = homelabRes.body.getReader();
    const stream = new PassThrough();
    
    // Progress logging
    const logInterval = setInterval(() => {
      const progress = totalSize ? ((downloadedBytes / totalSize) * 100).toFixed(1) : 'unknown';
      console.log(`[DL-PROGRESS] ${downloadId}: ${formatBytes(downloadedBytes)} / ${totalSize ? formatBytes(totalSize) : '?'} (${progress}%)`);
    }, 2000);
    
    // Pipe dengan progress tracking
    const pump = async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          downloadedBytes += value.length;
          stream.write(Buffer.from(value));
        }
        stream.end();
      } catch (err) {
        stream.destroy(err);
      }
    };
    
    pump();
    
    // Handle stream events
    stream.on('finish', () => {
      clearInterval(logInterval);
      const duration = Date.now() - startTime;
      const speed = duration > 0 ? (downloadedBytes / (duration / 1000)) : 0;
      console.log(`[DL-COMPLETE] ${downloadId}: ${formatBytes(downloadedBytes)} in ${duration}ms (${formatBytes(speed)}/s)`);
      activeDownloads.delete(downloadId);
    });
    
    stream.on('error', (err) => {
      clearInterval(logInterval);
      console.error(`[DL-ERROR] ${downloadId}: ${err.message}`);
      activeDownloads.delete(downloadId);
    });
    
    activeDownloads.set(downloadId, {
      filename: sanitizedFilename,
      startTime,
      clientIP,
      fingerprint
    });
    
    // Pipe ke response
    stream.pipe(res);
    
  } catch (err) {
    console.error(`[DL-ERROR] ${fingerprint}: ${err.message}`);
    res.status(500).send(`❌ DOWNLOAD ERROR
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: INTERNAL SERVER ERROR
Details: ${err.message}
File: ${sanitizedFilename}
Request ID: ${fingerprint}
Timestamp: ${new Date().toISOString()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  }
}
