'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { createApp } = require('./lib/microExpress');
const { DatabaseAdapter } = require('./db');
const { UnifiedWebSocketServer } = require('./lib/wsServer');
const {
  ACCESS_SECRET,
  REFRESH_SECRET,
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  sha256Hex,
  encryptBuffer,
  decryptBuffer,
  computeWaveformPeaks,
  haversineMeters
} = require('./lib/cryptoAuth');

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function validateAudioMagicBytes(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return false;
  // WAV: "RIFF" .... "WAVE"
  const isWav = buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WAVE';
  // WebM / Matroska: 0x1A 0x45 0xDF 0xA3
  const isWebm = buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3;
  // OGG: "OggS"
  const isOgg = buf.subarray(0, 4).toString('ascii') === 'OggS';
  return isWav || isWebm || isOgg;
}

function createPlatformServer(options = {}) {
  const db = options.db || new DatabaseAdapter(options.dbOptions || {});
  const storageDir = options.storageDir || process.env.STORAGE_DIR || path.join(__dirname, '../storage/audio');
  fs.mkdirSync(storageDir, { recursive: true });

  const app = createApp();
  const rateLimitBuckets = new Map();
  const maxRequestsPerWindow = Number(options.rateLimitMax || process.env.RATE_LIMIT_MAX_REQUESTS || 180);
  const windowMs = Number(options.rateLimitWindowMs || process.env.RATE_LIMIT_WINDOW_MS || 60000);
  const csrfTokens = new Set();

  // 1. Security Headers, CORS & Rate Limiting Middleware
  app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
    res.set('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Device-Token');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    const now = Date.now();
    const key = `${req.ip}:${req.path.startsWith('/api/auth/login') ? 'auth' : 'general'}`;
    const limit = key.endsWith(':auth') ? Math.min(25, maxRequestsPerWindow) : maxRequestsPerWindow;
    let bucket = rateLimitBuckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      rateLimitBuckets.set(key, bucket);
    }
    bucket.count += 1;
    res.set('X-RateLimit-Limit', String(limit));
    res.set('X-RateLimit-Remaining', String(Math.max(0, limit - bucket.count)));

    if (bucket.count > limit) {
      return res.status(429).json({
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests, please retry later.'
      });
    }

    // Optional CSRF Enforcement if client opts into X-Enforce-CSRF
    if (req.headers['x-enforce-csrf'] === 'true' && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      const token = req.headers['x-csrf-token'];
      if (!token || !csrfTokens.has(token)) {
        return res.status(403).json({ error: 'CSRF_TOKEN_INVALID' });
      }
    }

    next();
  });

  // Authentication helper middleware
  const requireAuth = (allowedRoles = ['admin', 'owner', 'viewer', 'auditor']) => async (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    const payload = verifyJwt(token, ACCESS_SECRET);
    if (!payload || !payload.sub) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid Bearer access token required' });
    }
    if (!allowedRoles.includes(payload.role)) {
      return res.status(403).json({ error: 'FORBIDDEN_ROLE', message: 'Insufficient role permissions' });
    }
    req.user = {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      deviceId: payload.deviceId || null
    };
    next();
  };

  // Ownership / IDOR guard helper
  async function verifyDeviceOwnershipOrReject(req, res, deviceId) {
    const device = await db.getDeviceById(deviceId);
    if (!device) {
      res.status(404).json({ error: 'DEVICE_NOT_FOUND' });
      return null;
    }
    if (device.ownerId !== req.user.id && req.user.role !== 'admin') {
      await db.appendSecurityLog({
        userId: req.user.id,
        deviceId,
        eventType: 'IDOR_ATTEMPT_BLOCKED',
        severity: 'high',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || 'unknown',
        details: { attemptedResource: `device:${deviceId}`, actualOwner: device.ownerId }
      });
      res.status(403).json({
        error: 'IDOR_FORBIDDEN',
        message: 'Access denied: You do not own this device.'
      });
      return null;
    }
    return device;
  }

  // Health & Platform Discovery
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      platform: 'LiveTrack-Pro Unified GPS & Consent Audio Platform',
      codename: 'Veloce / Navox',
      dbMode: db.mode,
      supportedClients: ['android-kotlin', 'termux-cli', 'ios-pwa', 'windows', 'linux', 'macos', 'web-dashboard'],
      timestamp: new Date().toISOString()
    });
  });

  // CSRF Token Issuance
  app.get('/api/auth/csrf-token', (req, res) => {
    const csrfToken = crypto.randomBytes(24).toString('hex');
    csrfTokens.add(csrfToken);
    res.json({ csrfToken });
  });

  // --- AUTHENTICATION ENDPOINTS ---
  app.post('/api/auth/register', async (req, res) => {
    const { email, fullName, password, role } = req.body || {};
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'INVALID_EMAIL', message: 'Provide a valid email address.' });
    }
    if (!fullName || String(fullName).trim().length < 2) {
      return res.status(400).json({ error: 'INVALID_NAME', message: 'Full name must be at least 2 characters.' });
    }
    if (!password || String(password).length < 8) {
      return res.status(400).json({ error: 'WEAK_PASSWORD', message: 'Password must be at least 8 characters.' });
    }
    const safeRole = ['owner', 'viewer', 'auditor'].includes(role) ? role : 'owner';

    try {
      const passwordHash = hashPassword(password);
      const user = await db.createUser({
        email,
        fullName: String(fullName).trim(),
        passwordHash,
        role: safeRole
      });

      const accessToken = signJwt({ sub: user.id, email: user.email, role: user.role }, ACCESS_SECRET, 900);
      const refreshToken = signJwt({ sub: user.id, email: user.email, role: user.role, type: 'refresh' }, REFRESH_SECRET, 604800);

      await db.createSession({
        userId: user.id,
        refreshTokenHash: sha256Hex(refreshToken),
        userAgent: req.headers['user-agent'],
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 7 * 86400 * 1000).toISOString()
      });

      await db.appendSecurityLog({
        userId: user.id,
        eventType: 'USER_REGISTERED',
        severity: 'info',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { email: user.email, role: user.role }
      });

      return res.status(201).json({
        user,
        accessToken,
        refreshToken
      });
    } catch (err) {
      if (err.code === 'DUPLICATE_EMAIL' || String(err.message).includes('duplicate')) {
        return res.status(409).json({ error: 'EMAIL_EXISTS', message: 'Email is already registered.' });
      }
      return res.status(500).json({ error: 'REGISTRATION_FAILED', message: err.message });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body || {};
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: 'INVALID_CREDENTIALS' });
    }
    const user = await db.findUserByEmail(email);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      await db.appendSecurityLog({
        userId: user ? user.id : null,
        eventType: 'LOGIN_FAILED',
        severity: 'warn',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { email }
      });
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
    }

    const accessToken = signJwt({ sub: user.id, email: user.email, role: user.role }, ACCESS_SECRET, 900);
    const refreshToken = signJwt({ sub: user.id, email: user.email, role: user.role, type: 'refresh' }, REFRESH_SECRET, 604800);

    await db.createSession({
      userId: user.id,
      refreshTokenHash: sha256Hex(refreshToken),
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
      expiresAt: new Date(Date.now() + 7 * 86400 * 1000).toISOString()
    });

    await db.appendSecurityLog({
      userId: user.id,
      eventType: 'LOGIN_SUCCESS',
      severity: 'info',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { email: user.email }
    });

    const { passwordHash: _, ...safeUser } = user;
    return res.json({
      user: safeUser,
      accessToken,
      refreshToken
    });
  });

  app.post('/api/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body || {};
    if (!refreshToken) {
      return res.status(400).json({ error: 'MISSING_REFRESH_TOKEN' });
    }
    const payload = verifyJwt(refreshToken, REFRESH_SECRET);
    if (!payload || payload.type !== 'refresh') {
      return res.status(401).json({ error: 'INVALID_REFRESH_TOKEN' });
    }
    const tokenHash = sha256Hex(refreshToken);
    const session = await db.findValidSession(tokenHash);
    if (!session) {
      return res.status(401).json({ error: 'SESSION_EXPIRED_OR_REVOKED' });
    }

    // Rotate refresh token
    await db.revokeSession(tokenHash);
    const newAccessToken = signJwt({ sub: payload.sub, email: payload.email, role: payload.role }, ACCESS_SECRET, 900);
    const newRefreshToken = signJwt({ sub: payload.sub, email: payload.email, role: payload.role, type: 'refresh' }, REFRESH_SECRET, 604800);

    await db.createSession({
      userId: payload.sub,
      refreshTokenHash: sha256Hex(newRefreshToken),
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
      expiresAt: new Date(Date.now() + 7 * 86400 * 1000).toISOString()
    });

    return res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });
  });

  app.post('/api/auth/logout', requireAuth(), async (req, res) => {
    const { refreshToken } = req.body || {};
    if (refreshToken) {
      await db.revokeSession(sha256Hex(refreshToken));
    }
    await db.appendSecurityLog({
      userId: req.user.id,
      eventType: 'USER_LOGOUT',
      severity: 'info',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    res.json({ status: 'logged_out' });
  });

  app.get('/api/auth/me', requireAuth(), async (req, res) => {
    const user = await db.findUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });
    res.json({ user });
  });

  // --- DEVICE REGISTRATION, PAIRING & OWNERSHIP ---
  app.post('/api/devices/register', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceName, platform = 'android', hardwareFingerprint } = req.body || {};
    const validPlatforms = ['android', 'termux', 'ios', 'windows', 'linux', 'macos', 'web'];
    if (!deviceName || String(deviceName).trim().length < 2) {
      return res.status(400).json({ error: 'INVALID_DEVICE_NAME' });
    }
    if (!validPlatforms.includes(platform)) {
      return res.status(400).json({ error: 'UNSUPPORTED_PLATFORM', validPlatforms });
    }
    const fingerprint = hardwareFingerprint || `${platform}-${crypto.randomUUID().slice(0, 8)}`;
    const pairingCode = crypto.randomBytes(3).toString('hex').toUpperCase();

    const device = await db.registerDevice({
      ownerId: req.user.id,
      deviceName: String(deviceName).trim(),
      platform,
      hardwareFingerprint: fingerprint,
      pairingCode
    });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'DEVICE_REGISTERED',
      severity: 'info',
      ipAddress: req.ip,
      details: { deviceName: device.deviceName, platform: device.platform }
    });

    res.status(201).json({ device, pairingCode });
  });

  app.post('/api/devices/pair', async (req, res) => {
    const { pairingCode } = req.body || {};
    if (!pairingCode || String(pairingCode).trim().length < 4) {
      return res.status(400).json({ error: 'INVALID_PAIRING_CODE' });
    }
    const rawDeviceSecret = crypto.randomBytes(32).toString('hex');
    const paired = await db.pairDeviceByCode({
      pairingCode: String(pairingCode).trim().toUpperCase(),
      deviceTokenHash: sha256Hex(rawDeviceSecret)
    });
    if (!paired) {
      return res.status(404).json({ error: 'PAIRING_CODE_NOT_FOUND_OR_EXPIRED' });
    }

    const deviceAccessToken = signJwt(
      { sub: paired.ownerId, role: 'owner', deviceId: paired.id, scope: 'device_telemetry' },
      ACCESS_SECRET,
      86400 * 30
    );

    await db.appendSecurityLog({
      userId: paired.ownerId,
      deviceId: paired.id,
      eventType: 'DEVICE_PAIRED',
      severity: 'info',
      ipAddress: req.ip,
      details: { deviceName: paired.deviceName, platform: paired.platform }
    });

    res.json({
      status: 'paired',
      device: paired,
      deviceAccessToken
    });
  });

  app.get('/api/devices', requireAuth(), async (req, res) => {
    const devices = await db.listDevicesByOwner(req.user.id);
    res.json({ devices });
  });

  app.get('/api/devices/:id', requireAuth(), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id);
    if (!device) return;
    res.json({ device });
  });

  app.post('/api/devices/:id/tracking', requireAuth(['admin', 'owner']), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id);
    if (!device) return;
    const active = Boolean(req.body?.active);
    const updated = await db.updateDeviceState(device.id, { trackingActive: active });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: active ? 'GPS_TRACKING_STARTED' : 'GPS_TRACKING_STOPPED',
      severity: 'info',
      ipAddress: req.ip,
      details: { deviceName: device.deviceName, trackingActive: active }
    });

    wsServer.broadcastToOwner(req.user.id, {
      type: 'DEVICE_TRACKING_STATE',
      deviceId: device.id,
      trackingActive: active,
      timestamp: new Date().toISOString()
    });

    res.json({ device: updated });
  });

  // --- GPS TELEMETRY, BATCH SYNC, GEOFENCE CHECK & EXPORT ---
  async function processGpsPoint(reqUser, point, ipAddress) {
    const lat = Number(point.latitude);
    const lon = Number(point.longitude);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) {
      const err = new Error('Coordinates out of bounds (-90..90, -180..180)');
      err.statusCode = 400;
      throw err;
    }

    const saved = await db.insertGpsLocation({
      deviceId: point.deviceId,
      ownerId: reqUser.id,
      latitude: lat,
      longitude: lon,
      altitude: point.altitude,
      accuracy: point.accuracy,
      speed: point.speed,
      heading: point.heading,
      batteryLevel: point.batteryLevel,
      provider: point.provider || 'fused',
      recordedAt: point.recordedAt
    });

    // Check active geofences for this owner
    const geofences = await db.listGeofencesByOwner(reqUser.id);
    const triggeredGeofences = [];
    for (const gf of geofences) {
      if (!gf.active) continue;
      if (gf.deviceId && gf.deviceId !== point.deviceId) continue;
      const distanceMeters = haversineMeters(lat, lon, gf.latitude, gf.longitude);
      const inside = distanceMeters <= gf.radiusMeters;
      if (!inside && gf.notifyOnExit) {
        const alertPayload = {
          geofenceId: gf.id,
          geofenceName: gf.name,
          event: 'GEOFENCE_EXIT',
          distanceMeters: Math.round(distanceMeters),
          radiusMeters: gf.radiusMeters,
          latitude: lat,
          longitude: lon
        };
        triggeredGeofences.push(alertPayload);
        await db.appendSecurityLog({
          userId: reqUser.id,
          deviceId: point.deviceId,
          eventType: 'GEOFENCE_EXIT_ALERT',
          severity: 'warn',
          ipAddress,
          details: alertPayload
        });
      }
    }

    wsServer.broadcastToOwner(reqUser.id, {
      type: 'GPS_LOCATION_UPDATE',
      location: saved,
      geofenceAlerts: triggeredGeofences
    });

    return { location: saved, geofenceAlerts: triggeredGeofences };
  }

  app.post('/api/gps/update', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceId, latitude, longitude, altitude, accuracy, speed, heading, batteryLevel, provider } = req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'MISSING_DEVICE_ID' });

    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    try {
      const result = await processGpsPoint(
        req.user,
        { deviceId, latitude, longitude, altitude, accuracy, speed, heading, batteryLevel, provider },
        req.ip
      );
      res.status(201).json(result);
    } catch (err) {
      res.status(err.statusCode || 400).json({ error: 'INVALID_GPS_DATA', message: err.message });
    }
  });

  app.post('/api/gps/batch', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceId, locations } = req.body || {};
    if (!deviceId || !Array.isArray(locations) || locations.length === 0) {
      return res.status(400).json({ error: 'INVALID_BATCH_PAYLOAD' });
    }
    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    const results = [];
    for (const item of locations.slice(0, 500)) {
      const processed = await processGpsPoint(req.user, { ...item, deviceId }, req.ip);
      results.push(processed.location);
    }
    res.status(201).json({ syncedCount: results.length, locations: results });
  });

  app.get('/api/gps/history/:deviceId', requireAuth(), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.deviceId);
    if (!device) return;
    const limit = Math.min(500, Math.max(1, Number(req.query.limit || 100)));
    const history = await db.getDeviceGpsHistory(device.id, limit);
    res.json({ deviceId: device.id, count: history.length, history });
  });

  app.get('/api/gps/export/:deviceId', requireAuth(), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.deviceId);
    if (!device) return;
    const format = (req.query.format || 'geojson').toLowerCase();
    const history = await db.getDeviceGpsHistory(device.id, 1000);

    if (format === 'gpx') {
      const trkpts = history
        .map(
          (pt) =>
            `      <trkpt lat="${pt.latitude}" lon="${pt.longitude}"><ele>${pt.altitude || 0}</ele><time>${pt.recordedAt}</time></trkpt>`
        )
        .join('\n');
      const gpx = `<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="LiveTrack-Pro" xmlns="http://www.topografix.com/GPX/1/1">
  <trk>
    <name>${device.deviceName}</name>
    <trkseg>
${trkpts}
    </trkseg>
  </trk>
</gpx>`;
      res.set('Content-Type', 'application/gpx+xml; charset=utf-8');
      return res.send(gpx);
    }

    const geojson = {
      type: 'FeatureCollection',
      features: history.map((pt) => ({
        type: 'Feature',
        geometry: {
          type: 'Point',
          coordinates: [pt.longitude, pt.latitude, pt.altitude || 0]
        },
        properties: {
          id: pt.id,
          deviceId: pt.deviceId,
          speed: pt.speed,
          accuracy: pt.accuracy,
          batteryLevel: pt.batteryLevel,
          recordedAt: pt.recordedAt
        }
      }))
    };
    res.json(geojson);
  });

  // --- CONSENT-BASED AUDIO MODULE (STRICT ANTI-COVERT ENFORCEMENT) ---
  app.post('/api/audio/sessions/start', requireAuth(['admin', 'owner']), async (req, res) => {
    const {
      deviceId,
      initiatedByDevice,
      userConsentConfirmed,
      consentStatement,
      sampleRate = 48000,
      channels = 1,
      mimeType = 'audio/wav'
    } = req.body || {};

    if (!deviceId) return res.status(400).json({ error: 'MISSING_DEVICE_ID' });
    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    // HARD SECURITY GUARD: Reject any remote/dashboard-triggered or unconsented microphone activation
    if (initiatedByDevice !== true || userConsentConfirmed !== true || !consentStatement) {
      await db.appendSecurityLog({
        userId: req.user.id,
        deviceId,
        eventType: 'COVERT_OR_REMOTE_MIC_ATTEMPT_BLOCKED',
        severity: 'critical',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { initiatedByDevice, userConsentConfirmed }
      });
      return res.status(403).json({
        error: 'COVERT_RECORDING_PROHIBITED',
        message: 'LiveTrack-Pro strictly prohibits remote or covert microphone activation. Audio sessions must be explicitly initiated by the physical device user with active consent.'
      });
    }

    const rawConsentToken = crypto.randomBytes(24).toString('hex');
    const session = await db.createAudioSession({
      deviceId: device.id,
      ownerId: req.user.id,
      consentTokenHash: sha256Hex(rawConsentToken),
      consentStatement: String(consentStatement).trim(),
      sampleRate: Number(sampleRate),
      channels: Number(channels),
      mimeType
    });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'AUDIO_CONSENT_SESSION_STARTED',
      severity: 'info',
      ipAddress: req.ip,
      details: { sessionId: session.id, consentStatement: session.consentStatement }
    });

    wsServer.broadcastToOwner(req.user.id, {
      type: 'AUDIO_SESSION_STARTED',
      session
    });

    res.status(201).json({
      session,
      consentToken: rawConsentToken
    });
  });

  app.post('/api/audio/sessions/:sessionId/stop', requireAuth(['admin', 'owner']), async (req, res) => {
    const session = await db.getAudioSessionById(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'AUDIO_SESSION_NOT_FOUND' });
    if (session.ownerId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'IDOR_FORBIDDEN' });
    }

    const stopped = await db.stopAudioSession(session.id);
    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: session.deviceId,
      eventType: 'AUDIO_CONSENT_SESSION_STOPPED',
      severity: 'info',
      ipAddress: req.ip,
      details: { sessionId: session.id }
    });

    wsServer.broadcastToOwner(req.user.id, {
      type: 'AUDIO_SESSION_STOPPED',
      session: stopped
    });

    res.json({ session: stopped });
  });

  app.get('/api/audio/sessions', requireAuth(), async (req, res) => {
    const sessions = await db.listAudioSessionsByOwner(req.user.id);
    res.json({ sessions });
  });

  // Upload Encrypted Audio Recording (Requires Active Consent Session + Consent Token)
  app.post('/api/audio/recordings/upload', requireAuth(['admin', 'owner']), async (req, res) => {
    const {
      sessionId,
      deviceId,
      consentToken,
      title = 'Authorized Consent Recording',
      mimeType = 'audio/wav',
      durationSeconds = 5,
      audioBase64
    } = req.body || {};

    if (!sessionId || !deviceId || !consentToken || !audioBase64) {
      return res.status(400).json({ error: 'MISSING_AUDIO_UPLOAD_FIELDS' });
    }

    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    const session = await db.getAudioSessionById(sessionId);
    if (!session || session.deviceId !== deviceId || session.status !== 'active') {
      return res.status(403).json({
        error: 'ACTIVE_CONSENT_SESSION_REQUIRED',
        message: 'Cannot store audio without an active device-initiated consent session.'
      });
    }

    if (sha256Hex(consentToken) !== session.consentTokenHash) {
      return res.status(403).json({ error: 'INVALID_CONSENT_TOKEN' });
    }

    const audioBuffer = Buffer.from(audioBase64, 'base64');
    if (!validateAudioMagicBytes(audioBuffer)) {
      return res.status(400).json({
        error: 'INVALID_AUDIO_FILE_HEADER',
        message: 'Uploaded audio must be a valid WAV, WebM/Opus, or OGG container.'
      });
    }

    const waveformPeaks = computeWaveformPeaks(audioBuffer, 64);
    const { encrypted, iv, authTag, sha256 } = encryptBuffer(audioBuffer);
    const fileName = `${crypto.randomUUID()}.enc`;
    const filePath = path.join(storageDir, fileName);
    fs.writeFileSync(filePath, encrypted);

    const recording = await db.createAudioRecording({
      sessionId: session.id,
      deviceId: device.id,
      ownerId: req.user.id,
      title: String(title).trim(),
      filePath,
      mimeType,
      durationSeconds,
      sizeBytes: audioBuffer.length,
      encryptionIv: iv,
      encryptionAuthTag: authTag,
      sha256Checksum: sha256,
      waveformPeaks
    });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'AUDIO_RECORDING_STORED_ENCRYPTED',
      severity: 'info',
      ipAddress: req.ip,
      details: { recordingId: recording.id, sizeBytes: recording.sizeBytes, sha256 }
    });

    wsServer.broadcastToOwner(req.user.id, {
      type: 'AUDIO_RECORDING_CREATED',
      recording: { ...recording, filePath: undefined }
    });

    const { filePath: _, ...safeRecording } = recording;
    res.status(201).json({ recording: safeRecording });
  });

  app.get('/api/audio/recordings', requireAuth(), async (req, res) => {
    const list = await db.listAudioRecordingsByOwner(req.user.id);
    const sanitized = list.map(({ filePath, encryptionIv, encryptionAuthTag, ...rest }) => rest);
    res.json({ recordings: sanitized });
  });

  app.get('/api/audio/recordings/:id/stream', requireAuth(), async (req, res) => {
    const rec = await db.getAudioRecordingById(req.params.id);
    if (!rec) return res.status(404).json({ error: 'RECORDING_NOT_FOUND' });
    if (rec.ownerId !== req.user.id && req.user.role !== 'admin') {
      await db.appendSecurityLog({
        userId: req.user.id,
        deviceId: rec.deviceId,
        eventType: 'IDOR_AUDIO_STREAM_BLOCKED',
        severity: 'high',
        ipAddress: req.ip,
        details: { recordingId: rec.id }
      });
      return res.status(403).json({ error: 'IDOR_FORBIDDEN' });
    }

    if (!fs.existsSync(rec.filePath)) {
      return res.status(404).json({ error: 'ENCRYPTED_BLOB_MISSING' });
    }

    const encryptedBuf = fs.readFileSync(rec.filePath);
    const decryptedBuf = decryptBuffer(encryptedBuf, rec.encryptionIv, rec.encryptionAuthTag);

    res.set('Content-Type', rec.mimeType || 'audio/wav');
    res.set('Content-Length', String(decryptedBuf.length));
    res.set('X-Content-SHA256', rec.sha256Checksum);
    res.send(decryptedBuf);
  });

  app.delete('/api/audio/recordings/:id', requireAuth(['admin', 'owner']), async (req, res) => {
    const rec = await db.getAudioRecordingById(req.params.id);
    if (!rec) return res.status(404).json({ error: 'RECORDING_NOT_FOUND' });
    if (rec.ownerId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'IDOR_FORBIDDEN' });
    }

    if (rec.filePath && fs.existsSync(rec.filePath)) {
      try {
        fs.unlinkSync(rec.filePath);
      } catch {}
    }
    await db.deleteAudioRecording(rec.id);

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: rec.deviceId,
      eventType: 'AUDIO_RECORDING_DELETED',
      severity: 'info',
      ipAddress: req.ip,
      details: { recordingId: rec.id, title: rec.title }
    });

    res.json({ status: 'deleted', id: rec.id });
  });

  // --- NEW FEATURE: SMART GEOFENCING ---
  app.post('/api/geofences', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceId, name, latitude, longitude, radiusMeters = 250, notifyOnEnter = true, notifyOnExit = true } = req.body || {};
    if (!name || !Number.isFinite(Number(latitude)) || !Number.isFinite(Number(longitude))) {
      return res.status(400).json({ error: 'INVALID_GEOFENCE_PARAMS' });
    }
    const radius = Number(radiusMeters);
    if (!Number.isFinite(radius) || radius < 25 || radius > 100000) {
      return res.status(400).json({ error: 'INVALID_GEOFENCE_RADIUS', message: 'Radius must be between 25m and 100,000m' });
    }
    const geofence = await db.createGeofence({
      ownerId: req.user.id,
      deviceId: deviceId || null,
      name: String(name).trim(),
      latitude: Number(latitude),
      longitude: Number(longitude),
      radiusMeters: radius,
      notifyOnEnter,
      notifyOnExit
    });
    res.status(201).json({ geofence });
  });

  app.get('/api/geofences', requireAuth(), async (req, res) => {
    const geofences = await db.listGeofencesByOwner(req.user.id);
    res.json({ geofences });
  });

  app.delete('/api/geofences/:id', requireAuth(['admin', 'owner']), async (req, res) => {
    const deleted = await db.deleteGeofence(req.params.id, req.user.id);
    if (!deleted) return res.status(404).json({ error: 'GEOFENCE_NOT_FOUND' });
    res.json({ status: 'deleted', id: req.params.id });
  });

  // --- NEW FEATURE: CONSENT-VERIFIED EMERGENCY SOS BEACON ---
  app.post('/api/sos/trigger', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceId, latitude, longitude, batteryLevel, message } = req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'MISSING_DEVICE_ID' });
    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    const alert = await db.createSosAlert({
      deviceId: device.id,
      ownerId: req.user.id,
      latitude: latitude ?? device.lastLatitude ?? 0,
      longitude: longitude ?? device.lastLongitude ?? 0,
      batteryLevel: batteryLevel ?? device.batteryLevel ?? 100,
      message
    });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'EMERGENCY_SOS_TRIGGERED',
      severity: 'critical',
      ipAddress: req.ip,
      details: { alertId: alert.id, latitude: alert.latitude, longitude: alert.longitude }
    });

    wsServer.broadcastToOwner(req.user.id, {
      type: 'EMERGENCY_SOS_ALERT',
      alert
    });

    res.status(201).json({ alert });
  });

  app.post('/api/sos/:id/resolve', requireAuth(['admin', 'owner']), async (req, res) => {
    const resolved = await db.resolveSosAlert(req.params.id, req.user.id);
    if (!resolved) return res.status(404).json({ error: 'SOS_ALERT_NOT_FOUND' });
    wsServer.broadcastToOwner(req.user.id, {
      type: 'EMERGENCY_SOS_RESOLVED',
      alert: resolved
    });
    res.json({ alert: resolved });
  });

  app.get('/api/sos', requireAuth(), async (req, res) => {
    const alerts = await db.listSosAlertsByOwner(req.user.id);
    res.json({ alerts });
  });

  // --- UNIFIED DASHBOARD OVERVIEW & SECURITY LOGS ---
  app.get('/api/overview', requireAuth(), async (req, res) => {
    const [devices, sessions, recordings, geofences, sosAlerts, securityLogs] = await Promise.all([
      db.listDevicesByOwner(req.user.id),
      db.listAudioSessionsByOwner(req.user.id),
      db.listAudioRecordingsByOwner(req.user.id),
      db.listGeofencesByOwner(req.user.id),
      db.listSosAlertsByOwner(req.user.id),
      db.listSecurityLogsByUser(req.user.id, 25)
    ]);

    res.json({
      summary: {
        totalDevices: devices.length,
        activeTrackingDevices: devices.filter((d) => d.trackingActive).length,
        activeConsentAudioSessions: sessions.filter((s) => s.status === 'active').length,
        totalAuthorizedRecordings: recordings.length,
        activeGeofences: geofences.filter((g) => g.active).length,
        activeSosAlerts: sosAlerts.filter((a) => a.status === 'active').length
      },
      devices,
      recentAudioSessions: sessions.slice(0, 5),
      recentSecurityLogs: securityLogs.slice(0, 10)
    });
  });

  app.get('/api/security-logs', requireAuth(), async (req, res) => {
    const logs = await db.listSecurityLogsByUser(req.user.id, 100);
    res.json({ logs });
  });

  // --- HTTP & WEBSOCKET SERVER INITIALIZATION ---
  const server = http.createServer(app);
  const wsServer = new UnifiedWebSocketServer(server, '/ws');

  wsServer.on('connection', (client, req) => {
    const parsedUrl = new URL(req.url || '/ws', 'http://localhost');
    const token = parsedUrl.searchParams.get('token');
    if (token) {
      const payload = verifyJwt(token, ACCESS_SECRET);
      if (payload && payload.sub) {
        client.meta.userId = payload.sub;
        client.meta.role = payload.role;
        client.meta.deviceId = payload.deviceId || null;
        client.send({ type: 'WS_AUTHENTICATED', userId: payload.sub });
      }
    }

    client.on('message', async (rawMessage) => {
      try {
        const msg = JSON.parse(rawMessage);
        if (msg.type === 'AUTH' && msg.token) {
          const payload = verifyJwt(msg.token, ACCESS_SECRET);
          if (!payload || !payload.sub) {
            return client.send({ type: 'ERROR', error: 'WS_AUTH_FAILED' });
          }
          client.meta.userId = payload.sub;
          client.meta.role = payload.role;
          client.meta.deviceId = payload.deviceId || null;
          return client.send({ type: 'WS_AUTHENTICATED', userId: payload.sub });
        }

        if (!client.meta.userId) {
          return client.send({ type: 'ERROR', error: 'WS_UNAUTHORIZED' });
        }

        if (msg.type === 'GPS_PING' && msg.deviceId) {
          const device = await db.getDeviceById(msg.deviceId);
          if (!device || device.ownerId !== client.meta.userId) {
            return client.send({ type: 'ERROR', error: 'WS_IDOR_FORBIDDEN' });
          }
          await processGpsPoint(
            { id: client.meta.userId, role: client.meta.role },
            {
              deviceId: msg.deviceId,
              latitude: msg.latitude,
              longitude: msg.longitude,
              accuracy: msg.accuracy,
              speed: msg.speed,
              heading: msg.heading,
              batteryLevel: msg.batteryLevel,
              provider: msg.provider || 'ws-live'
            },
            'ws'
          );
        } else if (msg.type === 'AUDIO_STREAM_CHUNK' && msg.sessionId) {
          const session = await db.getAudioSessionById(msg.sessionId);
          if (!session || session.ownerId !== client.meta.userId || session.status !== 'active') {
            return client.send({
              type: 'ERROR',
              error: 'WS_AUDIO_CONSENT_REQUIRED',
              message: 'Live audio streaming requires an active device-initiated consent session.'
            });
          }
          const rawBuf = msg.chunkBase64 ? Buffer.from(msg.chunkBase64, 'base64') : Buffer.from([128, 160, 90, 200]);
          const peaks = computeWaveformPeaks(rawBuf, 32);
          wsServer.broadcastToOwner(client.meta.userId, {
            type: 'LIVE_AUDIO_CHUNK',
            sessionId: session.id,
            deviceId: session.deviceId,
            chunkBase64: msg.chunkBase64,
            waveformPeaks: peaks,
            timestamp: new Date().toISOString()
          });
        }
      } catch (err) {
        client.send({ type: 'ERROR', error: 'INVALID_WS_MESSAGE', message: err.message });
      }
    });
  });

  return { app, server, db, wsServer };
}

module.exports = { createPlatformServer };
