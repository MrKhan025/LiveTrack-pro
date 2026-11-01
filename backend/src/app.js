'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { createApp } = require('./lib/microExpress');
const { DatabaseAdapter, DEFAULT_DEVICE_SCOPES } = require('./db');
const { UnifiedWebSocketServer } = require('./lib/wsServer');
const { ProductionRateLimiter } = require('./lib/rateLimiter');
const { NotificationService } = require('./lib/notificationService');
const { getStandaloneConsoleHtml } = require('./lib/standaloneConsoleHtml');
const {
  validateRequiredSecrets,
  getSecrets,
  validateStrongPassword,
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  sha256Hex,
  encryptBuffer,
  decryptBuffer,
  encryptText,
  decryptText,
  generateSecurePairingCode,
  generateTotpSecret,
  verifyTotpCode,
  buildOtpAuthUri,
  computeWaveformPeaks,
  haversineMeters,
  generatePairingSvgMatrix,
  calculateAdaptiveGpsInterval
} = require('./lib/cryptoAuth');

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function validateAudioMagicBytes(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return false;
  const isWav = buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WAVE';
  const isWebm = buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3;
  const isOgg = buf.subarray(0, 4).toString('ascii') === 'OggS';
  return isWav || isWebm || isOgg;
}

function parseAllowedOrigins() {
  const raw = process.env.CORS_ORIGIN;
  if (!raw || raw.trim() === '') {
    if (process.env.NODE_ENV === 'production') {
      return [];
    }
    return [
      'http://localhost:3000',
      'http://localhost:4000',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:4000'
    ];
  }
  return raw
    .split(',')
    .map((o) => o.trim())
    .filter((o) => o && o !== '*');
}

function createPlatformServer(options = {}) {
  // 1. Fail-Fast Startup Secret Validation (refuses to start if secrets are missing or use dev placeholders)
  const { ACCESS_SECRET, REFRESH_SECRET } = validateRequiredSecrets(options.env || process.env);

  const db = options.db || new DatabaseAdapter(options.dbOptions || {});
  const storageDir = options.storageDir || process.env.STORAGE_DIR || path.join(__dirname, '../storage/audio');
  fs.mkdirSync(storageDir, { recursive: true, mode: 0o700 });

  const rateLimiter =
    options.rateLimiter ||
    new ProductionRateLimiter({
      windowMs: options.rateLimitWindowMs || process.env.RATE_LIMIT_WINDOW_MS || 60000,
      maxRequests: options.rateLimitMax || process.env.RATE_LIMIT_MAX_REQUESTS || 180
    });
  const notifications = options.notifications || new NotificationService(db);

  const app = createApp();
  const csrfTokens = new Map(); // token -> expiresAtMs

  function issueCsrfToken() {
    const now = Date.now();
    if (csrfTokens.size > 5000) {
      for (const [k, exp] of csrfTokens.entries()) {
        if (now > exp) csrfTokens.delete(k);
      }
    }
    const token = crypto.randomBytes(24).toString('hex');
    csrfTokens.set(token, now + 3600 * 1000);
    return token;
  }

  function isValidCsrfToken(token) {
    if (!token || !csrfTokens.has(token)) return false;
    const exp = csrfTokens.get(token);
    if (Date.now() > exp) {
      csrfTokens.delete(token);
      return false;
    }
    return true;
  }

  // 2. Hardened Security Headers, HTTPS Enforcement, Strict CORS & Rate Limiting Middleware
  app.use(async (req, res, next) => {
    // Enforce HTTPS in production (except local health checks)
    if (
      process.env.NODE_ENV === 'production' &&
      req.path !== '/api/health' &&
      req.headers['x-forwarded-proto'] !== 'https' &&
      !req.socket?.encrypted
    ) {
      return res.status(403).json({
        error: 'HTTPS_REQUIRED_IN_PRODUCTION',
        message: 'All production requests must use HTTPS.'
      });
    }

    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Permissions-Policy', 'geolocation=(self), microphone=(self), camera=()');
    res.set('Cross-Origin-Opener-Policy', 'same-origin');
    res.set('Cross-Origin-Resource-Policy', 'same-origin');
    res.set('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
    res.set('Vary', 'Origin');

    // Strict CORS Validation: Never allow '*' when authentication is involved
    const requestOrigin = req.headers.origin;
    const allowedOrigins = parseAllowedOrigins();
    if (requestOrigin) {
      if (!allowedOrigins.includes(requestOrigin)) {
        return res.status(403).json({
          error: 'CORS_ORIGIN_FORBIDDEN',
          message: `Origin '${requestOrigin}' is not permitted by CORS policy.`
        });
      }
      res.set('Access-Control-Allow-Origin', requestOrigin);
      res.set('Access-Control-Allow-Credentials', 'true');
      res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Device-Token');
      res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    }

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    // Production Rate Limiter (Redis / Bounded Sliding Window)
    const routeGroup = req.path.startsWith('/api/auth/login') || req.path.startsWith('/api/auth/mfa') ? 'auth' : 'general';
    const rl = await rateLimiter.consume(req.ip, routeGroup);
    res.set('X-RateLimit-Limit', String(rl.limit));
    res.set('X-RateLimit-Remaining', String(rl.remaining));

    if (!rl.allowed) {
      await db.appendSecurityLog({
        eventType: 'RATE_LIMIT_EXCEEDED',
        severity: 'warn',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { path: req.path, routeGroup }
      });
      return res.status(429).json({
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests, please retry later.'
      });
    }

    // Mandatory CSRF Protection for Browser Clients on State-Changing Requests
    // Pure API clients using Bearer tokens without cookies/browser-origin are exempted unless X-Enforce-CSRF is set.
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      const hasBearer = (req.headers.authorization || '').startsWith('Bearer ');
      const hasCookie = Boolean(req.headers.cookie);
      const isBrowserStateChange =
        req.headers['x-enforce-csrf'] === 'true' ||
        hasCookie ||
        (Boolean(requestOrigin) && !hasBearer && !req.path.startsWith('/api/auth/') && !req.path.startsWith('/api/devices/pair'));

      if (isBrowserStateChange) {
        const csrfToken = req.headers['x-csrf-token'];
        if (!isValidCsrfToken(csrfToken)) {
          await db.appendSecurityLog({
            eventType: 'CSRF_VALIDATION_FAILED',
            severity: 'high',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            details: { path: req.path, method: req.method }
          });
          return res.status(403).json({
            error: 'CSRF_TOKEN_INVALID',
            message: 'A valid X-CSRF-Token header is required for browser state-changing requests.'
          });
        }
      }
    }

    next();
  });

  // Authentication & Device-Scoped Permission Middleware
  const requireAuth = (allowedRoles = ['admin', 'owner', 'viewer', 'auditor'], requiredDeviceScope = null) => async (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    const payload = verifyJwt(token, ACCESS_SECRET);
    if (!payload || !payload.sub || payload.scope === 'mfa_challenge') {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid Bearer access token required' });
    }
    if (!allowedRoles.includes(payload.role)) {
      return res.status(403).json({ error: 'FORBIDDEN_ROLE', message: 'Insufficient role permissions' });
    }

    // If this token is a Device-Scoped API Token, verify token rotation hash & fine-grained permission scopes
    if (payload.deviceId) {
      const dev = await db.getDeviceById(payload.deviceId);
      if (!dev || !dev.isPaired) {
        return res.status(401).json({ error: 'DEVICE_TOKEN_REVOKED' });
      }
      if (payload.tokenHash && dev.deviceTokenHash && payload.tokenHash !== dev.deviceTokenHash) {
        return res.status(401).json({
          error: 'DEVICE_TOKEN_ROTATED',
          message: 'This device API token has been rotated and is no longer valid.'
        });
      }
      const activeScopes = Array.isArray(dev.tokenScopes) ? dev.tokenScopes : DEFAULT_DEVICE_SCOPES;
      if (requiredDeviceScope && !activeScopes.includes(requiredDeviceScope)) {
        await db.appendSecurityLog({
          userId: payload.sub,
          deviceId: dev.id,
          eventType: 'DEVICE_SCOPE_VIOLATION',
          severity: 'high',
          ipAddress: req.ip,
          details: { requiredScope: requiredDeviceScope, activeScopes }
        });
        return res.status(403).json({
          error: 'INSUFFICIENT_DEVICE_SCOPE',
          message: `Device token lacks required permission scope '${requiredDeviceScope}'.`
        });
      }
    }

    req.user = {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      deviceId: payload.deviceId || null
    };
    next();
  };

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

  // Built-in Single-Port Interactive Console
  app.get('/', (req, res) => {
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Content-Security-Policy', "default-src 'self' https://unpkg.com https://*.tile.openstreetmap.org 'unsafe-inline';");
    res.send(getStandaloneConsoleHtml());
  });

  // Health & Platform Discovery
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      platform: 'LiveTrack-Pro Unified GPS & Consent Audio Platform',
      version: '3.0.0',
      dbMode: db.mode,
      security: {
        mfaSupported: true,
        csrfEnforced: true,
        corsWildcardDisabled: true,
        encryptedAtRest: true
      },
      supportedClients: ['android-kotlin', 'termux-cli', 'ios-pwa', 'windows', 'linux', 'macos', 'web-dashboard'],
      timestamp: new Date().toISOString()
    });
  });

  // CSRF Token Issuance
  app.get('/api/auth/csrf-token', (req, res) => {
    const csrfToken = issueCsrfToken();
    res.json({ csrfToken });
  });

  // --- AUTHENTICATION, STRONG PASSWORD, PROGRESSIVE LOCKOUT, TOTP MFA & GDPR ERASURE ---
  app.post('/api/auth/register', async (req, res) => {
    const { email, fullName, password, role } = req.body || {};
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'INVALID_EMAIL', message: 'Provide a valid email address.' });
    }
    if (!fullName || String(fullName).trim().length < 2) {
      return res.status(400).json({ error: 'INVALID_NAME', message: 'Full name must be at least 2 characters.' });
    }

    const pwCheck = validateStrongPassword(password, email);
    if (!pwCheck.valid) {
      return res.status(400).json({ error: 'WEAK_PASSWORD', message: pwCheck.reason });
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
        refreshToken,
        csrfToken: issueCsrfToken()
      });
    } catch (err) {
      if (err.code === 'DUPLICATE_EMAIL' || String(err.message).includes('duplicate')) {
        return res.status(409).json({ error: 'EMAIL_EXISTS', message: 'Email is already registered.' });
      }
      return res.status(500).json({ error: 'REGISTRATION_FAILED', message: err.message });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password, totpCode, recoveryCode } = req.body || {};
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: 'INVALID_CREDENTIALS' });
    }
    const user = await db.findUserByEmail(email);
    if (!user) {
      await db.appendSecurityLog({
        eventType: 'LOGIN_FAILED',
        severity: 'warn',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { email }
      });
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
    }

    // Check Progressive Account Lockout
    if (user.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now()) {
      const retryAfterSeconds = Math.ceil((new Date(user.lockedUntil).getTime() - Date.now()) / 1000);
      res.set('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        error: 'ACCOUNT_TEMPORARILY_LOCKED',
        message: `Account locked due to repeated failed login attempts. Try again in ${retryAfterSeconds} seconds.`,
        retryAfterSeconds
      });
    }

    if (!verifyPassword(password, user.passwordHash)) {
      const lockoutInfo = await db.recordFailedLogin(user.id);
      await db.appendSecurityLog({
        userId: user.id,
        eventType: lockoutInfo.lockSeconds > 0 ? 'ACCOUNT_LOCKOUT_TRIGGERED' : 'LOGIN_FAILED',
        severity: lockoutInfo.lockSeconds > 0 ? 'high' : 'warn',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: {
          email,
          failedLoginAttempts: lockoutInfo.failedLoginAttempts,
          lockedUntil: lockoutInfo.lockedUntil
        }
      });
      if (lockoutInfo.lockSeconds > 0) {
        return res.status(429).json({
          error: 'ACCOUNT_TEMPORARILY_LOCKED',
          message: `Too many failed login attempts. Account locked for ${lockoutInfo.lockSeconds} seconds.`,
          retryAfterSeconds: lockoutInfo.lockSeconds
        });
      }
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
    }

    // Check TOTP Multi-Factor Authentication if enabled on account
    if (user.mfaEnabled) {
      const decryptedSecret = decryptText(user.mfaSecretEncrypted);
      if (!totpCode && !recoveryCode) {
        const mfaChallengeToken = signJwt(
          { sub: user.id, email: user.email, role: user.role, scope: 'mfa_challenge' },
          ACCESS_SECRET,
          300
        );
        return res.status(202).json({
          mfaRequired: true,
          mfaChallengeToken,
          message: 'Multi-Factor Authentication (TOTP) code required to complete sign-in.'
        });
      }

      let mfaValid = false;
      if (totpCode && verifyTotpCode(decryptedSecret, totpCode)) {
        mfaValid = true;
      } else if (recoveryCode) {
        mfaValid = await db.consumeMfaRecoveryCode(user.id, sha256Hex(String(recoveryCode).trim().toUpperCase()));
      }

      if (!mfaValid) {
        await db.recordFailedLogin(user.id);
        await db.appendSecurityLog({
          userId: user.id,
          eventType: 'MFA_VERIFICATION_FAILED',
          severity: 'high',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });
        return res.status(401).json({ error: 'INVALID_MFA_CODE', message: 'Invalid TOTP or recovery code.' });
      }
    }

    await db.resetFailedLogins(user.id);

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
      details: { email: user.email, mfaVerified: Boolean(user.mfaEnabled) }
    });

    const safeUser = await db.findUserById(user.id);
    return res.json({
      user: safeUser,
      accessToken,
      refreshToken,
      csrfToken: issueCsrfToken()
    });
  });

  // TOTP MFA Setup, Enable, Verify Challenge & Disable
  app.post('/api/auth/mfa/setup', requireAuth(), async (req, res) => {
    const user = await db.findRawUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });

    const { secretBase32, recoveryCodes } = generateTotpSecret();
    const encryptedSecret = encryptText(secretBase32);
    const recoveryHashes = recoveryCodes.map((c) => sha256Hex(c));

    await db.saveMfaSetup(user.id, encryptedSecret, recoveryHashes);
    const otpauthUri = buildOtpAuthUri(user.email, secretBase32);
    const svgQr = generatePairingSvgMatrix(otpauthUri, 'TOTP-MFA');

    res.json({
      secret: secretBase32,
      otpauthUri,
      svgQr,
      recoveryCodes
    });
  });

  app.post('/api/auth/mfa/enable', requireAuth(), async (req, res) => {
    const { totpCode } = req.body || {};
    const user = await db.findRawUserById(req.user.id);
    if (!user || !user.mfaSecretEncrypted) {
      return res.status(400).json({ error: 'MFA_SETUP_NOT_INITIALIZED' });
    }
    const secretBase32 = decryptText(user.mfaSecretEncrypted);
    if (!verifyTotpCode(secretBase32, totpCode)) {
      return res.status(400).json({ error: 'INVALID_TOTP_CODE', message: 'Provided 6-digit TOTP code is invalid.' });
    }

    const updatedUser = await db.setMfaEnabled(user.id, true);
    await db.appendSecurityLog({
      userId: user.id,
      eventType: 'MFA_ENABLED',
      severity: 'info',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    res.json({ status: 'mfa_enabled', user: updatedUser });
  });

  app.post('/api/auth/mfa/verify', async (req, res) => {
    const { mfaChallengeToken, totpCode, recoveryCode } = req.body || {};
    const payload = verifyJwt(mfaChallengeToken, ACCESS_SECRET);
    if (!payload || payload.scope !== 'mfa_challenge') {
      return res.status(401).json({ error: 'INVALID_MFA_CHALLENGE_TOKEN' });
    }
    const user = await db.findRawUserById(payload.sub);
    if (!user || !user.mfaEnabled) {
      return res.status(400).json({ error: 'MFA_NOT_ACTIVE' });
    }

    const secretBase32 = decryptText(user.mfaSecretEncrypted);
    let valid = false;
    if (totpCode && verifyTotpCode(secretBase32, totpCode)) {
      valid = true;
    } else if (recoveryCode) {
      valid = await db.consumeMfaRecoveryCode(user.id, sha256Hex(String(recoveryCode).trim().toUpperCase()));
    }

    if (!valid) {
      return res.status(401).json({ error: 'INVALID_MFA_CODE' });
    }

    await db.resetFailedLogins(user.id);
    const accessToken = signJwt({ sub: user.id, email: user.email, role: user.role }, ACCESS_SECRET, 900);
    const refreshToken = signJwt({ sub: user.id, email: user.email, role: user.role, type: 'refresh' }, REFRESH_SECRET, 604800);

    await db.createSession({
      userId: user.id,
      refreshTokenHash: sha256Hex(refreshToken),
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
      expiresAt: new Date(Date.now() + 7 * 86400 * 1000).toISOString()
    });

    const safeUser = await db.findUserById(user.id);
    res.json({ user: safeUser, accessToken, refreshToken, csrfToken: issueCsrfToken() });
  });

  app.post('/api/auth/mfa/disable', requireAuth(), async (req, res) => {
    const { password, totpCode } = req.body || {};
    const user = await db.findRawUserById(req.user.id);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({ error: 'INVALID_PASSWORD' });
    }
    const secretBase32 = decryptText(user.mfaSecretEncrypted);
    if (user.mfaEnabled && !verifyTotpCode(secretBase32, totpCode)) {
      return res.status(401).json({ error: 'INVALID_TOTP_CODE' });
    }

    const updatedUser = await db.setMfaEnabled(user.id, false);
    await db.appendSecurityLog({
      userId: user.id,
      eventType: 'MFA_DISABLED',
      severity: 'warn',
      ipAddress: req.ip
    });
    res.json({ status: 'mfa_disabled', user: updatedUser });
  });

  // GDPR Account & Full Data Erasure Endpoint
  app.delete('/api/auth/account', requireAuth(), async (req, res) => {
    const { password, totpCode } = req.body || {};
    const user = await db.findRawUserById(req.user.id);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({
        error: 'INVALID_PASSWORD',
        message: 'Current account password is required to permanently delete your account and data.'
      });
    }
    if (user.mfaEnabled) {
      const secretBase32 = decryptText(user.mfaSecretEncrypted);
      if (!verifyTotpCode(secretBase32, totpCode)) {
        return res.status(401).json({ error: 'INVALID_TOTP_CODE', message: 'Valid TOTP code required for account deletion.' });
      }
    }

    const { deletedAudioFiles } = await db.deleteUserAccountAndAllData(user.id);
    for (const filePath of deletedAudioFiles) {
      if (filePath && fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch {}
      }
    }

    await db.appendSecurityLog({
      userId: null,
      eventType: 'GDPR_ACCOUNT_AND_DATA_DELETED',
      severity: 'info',
      ipAddress: req.ip,
      details: { anonymizedAccountHash: sha256Hex(user.email).slice(0, 16), wipedAudioBlobs: deletedAudioFiles.length }
    });

    res.json({
      status: 'account_and_data_deleted',
      wipedAudioBlobs: deletedAudioFiles.length
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

  // --- DEVICE REGISTRATION, SINGLE-USE EXPIRING PAIRING CODES & SCOPED TOKENS ---
  app.post('/api/devices/register', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceName, platform = 'android', hardwareFingerprint, tokenScopes, pairingTtlMinutes = 10 } = req.body || {};
    const validPlatforms = ['android', 'termux', 'ios', 'windows', 'linux', 'macos', 'web'];
    if (!deviceName || String(deviceName).trim().length < 2) {
      return res.status(400).json({ error: 'INVALID_DEVICE_NAME' });
    }
    if (!validPlatforms.includes(platform)) {
      return res.status(400).json({ error: 'UNSUPPORTED_PLATFORM', validPlatforms });
    }
    const fingerprint = hardwareFingerprint || `${platform}-${crypto.randomUUID().slice(0, 8)}`;
    const { code: pairingCode, expiresAt: pairingCodeExpiresAt } = generateSecurePairingCode(
      Number(pairingTtlMinutes)
    );

    const device = await db.registerDevice({
      ownerId: req.user.id,
      deviceName: String(deviceName).trim(),
      platform,
      hardwareFingerprint: fingerprint,
      pairingCode,
      pairingCodeExpiresAt,
      tokenScopes
    });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'DEVICE_REGISTERED',
      severity: 'info',
      ipAddress: req.ip,
      details: { deviceName: device.deviceName, platform: device.platform, pairingCodeExpiresAt }
    });

    res.status(201).json({ device, pairingCode, pairingCodeExpiresAt });
  });

  app.post('/api/devices/pair', async (req, res) => {
    const { pairingCode } = req.body || {};
    if (!pairingCode || String(pairingCode).trim().length < 4) {
      return res.status(400).json({ error: 'INVALID_PAIRING_CODE' });
    }
    const rawDeviceSecret = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256Hex(rawDeviceSecret);
    const result = await db.pairDeviceByCode({
      pairingCode: String(pairingCode).trim().toUpperCase(),
      deviceTokenHash: tokenHash
    });

    if (result.status === 'expired') {
      await db.appendSecurityLog({
        userId: result.device.ownerId,
        deviceId: result.device.id,
        eventType: 'PAIRING_CODE_EXPIRED_ATTEMPT',
        severity: 'warn',
        ipAddress: req.ip
      });
      return res.status(410).json({
        error: 'PAIRING_CODE_EXPIRED',
        message: 'This single-use pairing code has expired. Generate a new code from the dashboard.'
      });
    }

    if (result.status !== 'paired' || !result.device) {
      return res.status(404).json({ error: 'PAIRING_CODE_NOT_FOUND_OR_ALREADY_USED' });
    }

    const paired = result.device;
    const deviceAccessToken = signJwt(
      {
        sub: paired.ownerId,
        role: 'owner',
        deviceId: paired.id,
        scope: 'device_telemetry',
        scopes: paired.tokenScopes,
        tokenHash
      },
      ACCESS_SECRET,
      86400 * 30
    );

    await db.appendSecurityLog({
      userId: paired.ownerId,
      deviceId: paired.id,
      eventType: 'DEVICE_PAIRED',
      severity: 'info',
      ipAddress: req.ip,
      details: { deviceName: paired.deviceName, platform: paired.platform, scopes: paired.tokenScopes }
    });

    res.json({
      status: 'paired',
      device: paired,
      deviceAccessToken
    });
  });

  // Rotate Device-Scoped API Token
  app.post('/api/devices/:id/rotate-token', requireAuth(['admin', 'owner']), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id);
    if (!device) return;

    const rawDeviceSecret = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256Hex(rawDeviceSecret);
    const updated = await db.rotateDeviceToken(device.id, tokenHash, req.body?.tokenScopes || null);

    const newDeviceAccessToken = signJwt(
      {
        sub: updated.ownerId,
        role: 'owner',
        deviceId: updated.id,
        scope: 'device_telemetry',
        scopes: updated.tokenScopes,
        tokenHash
      },
      ACCESS_SECRET,
      86400 * 30
    );

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'DEVICE_TOKEN_ROTATED',
      severity: 'info',
      ipAddress: req.ip,
      details: { scopes: updated.tokenScopes }
    });

    res.json({
      status: 'rotated',
      device: updated,
      deviceAccessToken: newDeviceAccessToken
    });
  });

  // Update Fine-Grained Device Token Permissions
  app.put('/api/devices/:id/permissions', requireAuth(['admin', 'owner']), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id);
    if (!device) return;
    const { tokenScopes } = req.body || {};
    if (!Array.isArray(tokenScopes)) {
      return res.status(400).json({ error: 'INVALID_SCOPES_ARRAY' });
    }
    const updated = await db.updateDevicePermissions(device.id, tokenScopes);
    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'DEVICE_PERMISSIONS_UPDATED',
      severity: 'info',
      ipAddress: req.ip,
      details: { tokenScopes: updated.tokenScopes }
    });
    res.json({ device: updated });
  });

  // Adaptive GPS Reporting Interval Endpoint
  app.get('/api/devices/:id/adaptive-config', requireAuth(), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id);
    if (!device) return;
    const batteryLevel = Number(req.query.batteryLevel ?? device.batteryLevel ?? 100);
    const isCharging = req.query.isCharging === 'true' || Boolean(device.isCharging);
    const speed = Number(req.query.speed ?? device.lastSpeed ?? 0);
    const networkType = String(req.query.networkType || 'wifi');

    const recommendedIntervalSeconds = calculateAdaptiveGpsInterval({
      batteryLevel,
      isCharging,
      speed,
      networkType
    });

    await db.updateDeviceState(device.id, { adaptiveIntervalSeconds: recommendedIntervalSeconds });
    res.json({
      deviceId: device.id,
      recommendedIntervalSeconds,
      factors: { batteryLevel, isCharging, speed, networkType }
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

  app.get('/api/devices/:id/pairing-qr', requireAuth(), async (req, res) => {
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id);
    if (!device) return;
    const serverOrigin = `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host || 'localhost:4000'}`;
    const code = device.pairingCode || 'PAIRED';
    const deepLink = `livetrack://pair?server=${encodeURIComponent(serverOrigin)}&code=${encodeURIComponent(code)}&deviceId=${device.id}`;
    const svgQr = generatePairingSvgMatrix(deepLink, code);
    res.json({
      deviceId: device.id,
      deviceName: device.deviceName,
      pairingCode: device.pairingCode,
      pairingCodeExpiresAt: device.pairingCodeExpiresAt,
      deepLink,
      cliCommand: `node cli-agent/livetrack-agent.js --server ${serverOrigin} --pair ${code}`,
      svgQr
    });
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

  // --- GPS TELEMETRY, COMPLETE GEOFENCE ENTER/EXIT ENGINE, ADAPTIVE INTERVAL & EXPORTS ---
  async function processGpsPoint(reqUser, point, ipAddress) {
    const lat = Number(point.latitude);
    const lon = Number(point.longitude);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) {
      const err = new Error('Coordinates out of bounds (-90..90, -180..180)');
      err.statusCode = 400;
      throw err;
    }

    const batteryLevel = Number(point.batteryLevel ?? 100);
    const isCharging = Boolean(point.isCharging);
    const speed = Number(point.speed || 0);
    const adaptiveIntervalSeconds = calculateAdaptiveGpsInterval({
      batteryLevel,
      isCharging,
      speed,
      networkType: point.networkType || 'wifi'
    });

    const saved = await db.insertGpsLocation({
      deviceId: point.deviceId,
      ownerId: reqUser.id,
      latitude: lat,
      longitude: lon,
      altitude: point.altitude,
      accuracy: point.accuracy,
      speed,
      heading: point.heading,
      batteryLevel,
      isCharging,
      adaptiveIntervalSeconds,
      provider: point.provider || 'fused',
      recordedAt: point.recordedAt
    });

    // Low-Battery Alert Check (< 20%)
    if (batteryLevel < 20 && !isCharging) {
      await notifications.dispatchCriticalEvent({
        userId: reqUser.id,
        deviceId: point.deviceId,
        eventType: 'LOW_BATTERY',
        title: `Low Battery Alert (${batteryLevel}%)`,
        body: `Device ${point.deviceId} battery dropped to ${batteryLevel}% at (${lat.toFixed(4)}, ${lon.toFixed(4)}).`,
        metadata: { batteryLevel, latitude: lat, longitude: lon }
      });
    }

    // Complete Geofence Enter & Exit Transition Detection
    const geofences = await db.listGeofencesByOwner(reqUser.id);
    const triggeredGeofences = [];
    for (const gf of geofences) {
      if (!gf.active) continue;
      if (gf.deviceId && gf.deviceId !== point.deviceId) continue;

      const distanceMeters = haversineMeters(lat, lon, gf.latitude, gf.longitude);
      const isInside = distanceMeters <= gf.radiusMeters;
      const { transition } = await db.evaluateGeofenceTransition(gf.id, point.deviceId, isInside);

      if (transition === 'ENTER' && gf.notifyOnEnter) {
        const alertPayload = {
          geofenceId: gf.id,
          geofenceName: gf.name,
          event: 'GEOFENCE_ENTER',
          distanceMeters: Math.round(distanceMeters),
          radiusMeters: gf.radiusMeters,
          latitude: lat,
          longitude: lon
        };
        triggeredGeofences.push(alertPayload);
        await db.appendSecurityLog({
          userId: reqUser.id,
          deviceId: point.deviceId,
          eventType: 'GEOFENCE_ENTER_ALERT',
          severity: 'info',
          ipAddress,
          details: alertPayload
        });
        wsServer.broadcastToOwner(reqUser.id, {
          type: 'GEOFENCE_ENTER',
          deviceId: point.deviceId,
          alert: alertPayload,
          timestamp: new Date().toISOString()
        });
        await notifications.dispatchCriticalEvent({
          userId: reqUser.id,
          deviceId: point.deviceId,
          eventType: 'GEOFENCE_ENTER',
          title: `Geofence Entered: ${gf.name}`,
          body: `Device entered geofence '${gf.name}' (${Math.round(distanceMeters)}m from center).`,
          metadata: alertPayload
        });
      } else if (transition === 'EXIT' && gf.notifyOnExit) {
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
        wsServer.broadcastToOwner(reqUser.id, {
          type: 'GEOFENCE_EXIT',
          deviceId: point.deviceId,
          alert: alertPayload,
          timestamp: new Date().toISOString()
        });
        await notifications.dispatchCriticalEvent({
          userId: reqUser.id,
          deviceId: point.deviceId,
          eventType: 'GEOFENCE_EXIT',
          title: `Geofence Exited: ${gf.name}`,
          body: `Device exited geofence '${gf.name}' (${Math.round(distanceMeters)}m from center).`,
          metadata: alertPayload
        });
      }
    }

    wsServer.broadcastToOwner(reqUser.id, {
      type: 'GPS_LOCATION_UPDATE',
      location: saved,
      adaptiveIntervalSeconds,
      geofenceAlerts: triggeredGeofences
    });

    return { location: saved, adaptiveIntervalSeconds, geofenceAlerts: triggeredGeofences };
  }

  app.post('/api/gps/update', requireAuth(['admin', 'owner'], 'gps:write'), async (req, res) => {
    const { deviceId, latitude, longitude, altitude, accuracy, speed, heading, batteryLevel, isCharging, provider, networkType } =
      req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'MISSING_DEVICE_ID' });

    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    try {
      const result = await processGpsPoint(
        req.user,
        { deviceId, latitude, longitude, altitude, accuracy, speed, heading, batteryLevel, isCharging, provider, networkType },
        req.ip
      );
      res.status(201).json(result);
    } catch (err) {
      res.status(err.statusCode || 400).json({ error: 'INVALID_GPS_DATA', message: err.message });
    }
  });

  app.post('/api/gps/batch', requireAuth(['admin', 'owner'], 'gps:write'), async (req, res) => {
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
    const device = await verifyDeviceOwnershipOrReject(req, res, req.params.id || req.params.deviceId);
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

    if (format === 'csv') {
      const rows = ['id,deviceId,latitude,longitude,altitude,accuracy,speed,heading,batteryLevel,recordedAt'];
      for (const pt of history) {
        rows.push(
          `${pt.id},${pt.deviceId},${pt.latitude},${pt.longitude},${pt.altitude || 0},${pt.accuracy || 5},${pt.speed || 0},${pt.heading || 0},${pt.batteryLevel ?? 100},${pt.recordedAt}`
        );
      }
      res.set('Content-Type', 'text/csv; charset=utf-8');
      return res.send(rows.join('\n'));
    }

    if (format === 'kml') {
      const coords = history.map((pt) => `${pt.longitude},${pt.latitude},${pt.altitude || 0}`).join(' ');
      const kml = `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>${device.deviceName} Route Track</name>
    <Placemark>
      <name>${device.deviceName}</name>
      <LineString>
        <tessellate>1</tessellate>
        <coordinates>${coords}</coordinates>
      </LineString>
    </Placemark>
  </Document>
</kml>`;
      res.set('Content-Type', 'application/vnd.google-earth.kml+xml; charset=utf-8');
      return res.send(kml);
    }

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

  // --- CONSENT-BASED AUDIO MODULE (STRICT ANTI-COVERT ENFORCEMENT & 0600 FILE PERMISSIONS) ---
  app.post('/api/audio/sessions/start', requireAuth(['admin', 'owner'], 'audio:consent'), async (req, res) => {
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
        message:
          'LiveTrack-Pro strictly prohibits remote or covert microphone activation. Audio sessions must be explicitly initiated by the physical device user with active consent.'
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

  app.post('/api/audio/sessions/:sessionId/stop', requireAuth(['admin', 'owner'], 'audio:consent'), async (req, res) => {
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

  app.post('/api/audio/recordings/upload', requireAuth(['admin', 'owner'], 'audio:consent'), async (req, res) => {
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
    // Strict 0600 file permissions for encrypted audio blobs at rest
    fs.writeFileSync(filePath, encrypted, { mode: 0o600 });

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
      details: { recordingId: recording.id, sizeBytes: recording.sizeBytes, sha256, fileMode: '0600' }
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

  // --- SMART GEOFENCING ---
  app.post('/api/geofences', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceId, name, latitude, longitude, radiusMeters = 250, notifyOnEnter = true, notifyOnExit = true } =
      req.body || {};
    if (!name || !Number.isFinite(Number(latitude)) || !Number.isFinite(Number(longitude))) {
      return res.status(400).json({ error: 'INVALID_GEOFENCE_PARAMS' });
    }
    const radius = Number(radiusMeters);
    if (!Number.isFinite(radius) || radius < 25 || radius > 100000) {
      return res.status(400).json({
        error: 'INVALID_GEOFENCE_RADIUS',
        message: 'Radius must be between 25m and 100,000m'
      });
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

  // --- EMERGENCY SOS BEACON (WITH FCM/APNS PUSH & WEBHOOK/TELEGRAM/EMAIL ALERTING) ---
  app.post('/api/sos/trigger', requireAuth(['admin', 'owner'], 'sos:trigger'), async (req, res) => {
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

    const dispatchedAlerts = await notifications.dispatchCriticalEvent({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'EMERGENCY_SOS',
      title: `🚨 Emergency SOS: ${device.deviceName}`,
      body: `${alert.message} at (${alert.latitude.toFixed(4)}, ${alert.longitude.toFixed(4)}) — Battery: ${alert.batteryLevel}%`,
      metadata: { alertId: alert.id, latitude: alert.latitude, longitude: alert.longitude, batteryLevel: alert.batteryLevel }
    });

    res.status(201).json({ alert, dispatchedNotifications: dispatchedAlerts.length });
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

  // --- EPHEMERAL READ-ONLY LIVE SHARE LINKS ---
  app.post('/api/shares', requireAuth(['admin', 'owner']), async (req, res) => {
    const { deviceId, label = 'Live Family Safety Link', expiresInMinutes = 60 } = req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'MISSING_DEVICE_ID' });
    const device = await verifyDeviceOwnershipOrReject(req, res, deviceId);
    if (!device) return;

    const mins = Math.min(10080, Math.max(5, Number(expiresInMinutes || 60)));
    const share = await db.createLiveShare({
      ownerId: req.user.id,
      deviceId: device.id,
      label,
      expiresInMinutes: mins
    });

    await db.appendSecurityLog({
      userId: req.user.id,
      deviceId: device.id,
      eventType: 'LIVE_SHARE_LINK_CREATED',
      severity: 'info',
      ipAddress: req.ip,
      details: { shareId: share.id, expiresAt: share.expiresAt }
    });

    res.status(201).json({
      share,
      publicUrl: `/api/shares/public/${share.shareToken}`
    });
  });

  app.get('/api/shares', requireAuth(), async (req, res) => {
    const shares = await db.listLiveSharesByOwner(req.user.id);
    res.json({ shares });
  });

  app.get('/api/shares/public/:token', async (req, res) => {
    const share = await db.getLiveShareByToken(req.params.token);
    if (!share) {
      return res.status(404).json({ error: 'SHARE_LINK_EXPIRED_OR_INVALID' });
    }
    const device = await db.getDeviceById(share.deviceId);
    const recentTrack = await db.getDeviceGpsHistory(share.deviceId, 20);
    res.json({
      share: {
        label: share.label,
        expiresAt: share.expiresAt
      },
      device: device
        ? {
            deviceName: device.deviceName,
            platform: device.platform,
            batteryLevel: device.batteryLevel,
            lastLatitude: device.lastLatitude,
            lastLongitude: device.lastLongitude,
            lastSpeed: device.lastSpeed,
            lastSeenAt: device.lastSeenAt
          }
        : null,
      recentTrack
    });
  });

  app.delete('/api/shares/:id', requireAuth(['admin', 'owner']), async (req, res) => {
    const revoked = await db.revokeLiveShare(req.params.id, req.user.id);
    if (!revoked) return res.status(404).json({ error: 'SHARE_NOT_FOUND' });
    res.json({ status: 'revoked', share: revoked });
  });

  // --- PUSH NOTIFICATIONS (FCM / APNS) & WEBHOOK / TELEGRAM / EMAIL ALERT CHANNELS ---
  app.post('/api/notifications/register-token', requireAuth(), async (req, res) => {
    const { deviceId = null, provider = 'fcm', token } = req.body || {};
    if (!token || !['fcm', 'apns', 'webpush'].includes(provider)) {
      return res.status(400).json({ error: 'INVALID_PUSH_TOKEN_PARAMS' });
    }
    const registered = await db.registerPushToken({
      userId: req.user.id,
      deviceId,
      provider,
      token: String(token).trim()
    });
    res.status(201).json({ pushToken: registered });
  });

  app.get('/api/notifications/history', requireAuth(), async (req, res) => {
    res.json({ notifications: notifications.getHistoryByUser(req.user.id) });
  });

  app.post('/api/alerts/channels', requireAuth(['admin', 'owner']), async (req, res) => {
    const { channelType, name, target, secretHeader = null, events } = req.body || {};
    if (!['webhook', 'telegram', 'email'].includes(channelType) || !name || !target) {
      return res.status(400).json({ error: 'INVALID_ALERT_CHANNEL_PARAMS' });
    }
    const channel = await db.createAlertChannel({
      userId: req.user.id,
      channelType,
      name,
      target,
      secretHeader,
      events
    });
    res.status(201).json({ channel });
  });

  app.get('/api/alerts/channels', requireAuth(), async (req, res) => {
    const channels = await db.listAlertChannelsByUser(req.user.id);
    res.json({ channels });
  });

  app.delete('/api/alerts/channels/:id', requireAuth(['admin', 'owner']), async (req, res) => {
    const deleted = await db.deleteAlertChannel(req.params.id, req.user.id);
    if (!deleted) return res.status(404).json({ error: 'ALERT_CHANNEL_NOT_FOUND' });
    res.json({ status: 'deleted', id: req.params.id });
  });

  // --- CONFIGURABLE DATA RETENTION POLICIES & AUTOMATED PURGE ---
  app.get('/api/settings/retention', requireAuth(), async (req, res) => {
    const user = await db.findUserById(req.user.id);
    res.json({
      retention: {
        gpsRetentionDays: user?.gpsRetentionDays ?? 30,
        audioRetentionDays: user?.audioRetentionDays ?? 14,
        autoPurgeEnabled: user?.autoPurgeEnabled ?? true
      }
    });
  });

  app.put('/api/settings/retention', requireAuth(['admin', 'owner']), async (req, res) => {
    const { gpsRetentionDays, audioRetentionDays, autoPurgeEnabled } = req.body || {};
    if (
      (gpsRetentionDays !== undefined && (Number(gpsRetentionDays) < 1 || Number(gpsRetentionDays) > 3650)) ||
      (audioRetentionDays !== undefined && (Number(audioRetentionDays) < 1 || Number(audioRetentionDays) > 3650))
    ) {
      return res.status(400).json({ error: 'INVALID_RETENTION_DAYS', message: 'Retention days must be between 1 and 3650.' });
    }
    const updated = await db.updateUserRetentionPolicy(req.user.id, {
      gpsRetentionDays,
      audioRetentionDays,
      autoPurgeEnabled
    });
    await db.appendSecurityLog({
      userId: req.user.id,
      eventType: 'RETENTION_POLICY_UPDATED',
      severity: 'info',
      ipAddress: req.ip,
      details: updated
    });
    res.json({ retention: updated });
  });

  app.post('/api/settings/retention/purge', requireAuth(['admin', 'owner']), async (req, res) => {
    const { purgedGpsCount, purgedAudioRecordings } = await db.purgeExpiredDataForUser(req.user.id);
    for (const rec of purgedAudioRecordings) {
      if (rec.filePath && fs.existsSync(rec.filePath)) {
        try {
          fs.unlinkSync(rec.filePath);
        } catch {}
      }
    }
    await db.appendSecurityLog({
      userId: req.user.id,
      eventType: 'DATA_RETENTION_PURGE_EXECUTED',
      severity: 'info',
      ipAddress: req.ip,
      details: { purgedGpsCount, purgedAudioCount: purgedAudioRecordings.length }
    });
    res.json({
      status: 'purged',
      purgedGpsCount,
      purgedAudioCount: purgedAudioRecordings.length
    });
  });

  // --- FLEET TELEMETRY & DISTANCE ANALYTICS ---
  app.get('/api/analytics/fleet', requireAuth(), async (req, res) => {
    const [devices, recordings] = await Promise.all([
      db.listDevicesByOwner(req.user.id),
      db.listAudioRecordingsByOwner(req.user.id)
    ]);

    const deviceMetrics = [];
    let fleetTotalMeters = 0;

    for (const dev of devices) {
      const history = await db.getDeviceGpsHistory(dev.id, 500);
      let distanceMeters = 0;
      let maxSpeed = 0;
      let maxAltitude = 0;
      for (let i = 0; i < history.length; i++) {
        if (history[i].speed > maxSpeed) maxSpeed = history[i].speed;
        if ((history[i].altitude || 0) > maxAltitude) maxAltitude = history[i].altitude || 0;
        if (i > 0) {
          distanceMeters += haversineMeters(
            history[i - 1].latitude,
            history[i - 1].longitude,
            history[i].latitude,
            history[i].longitude
          );
        }
      }
      fleetTotalMeters += distanceMeters;
      deviceMetrics.push({
        deviceId: dev.id,
        deviceName: dev.deviceName,
        platform: dev.platform,
        totalPoints: history.length,
        distanceKm: Number((distanceMeters / 1000).toFixed(3)),
        maxSpeedMps: Number(maxSpeed.toFixed(2)),
        maxAltitudeMeters: Number(maxAltitude.toFixed(1)),
        adaptiveIntervalSeconds: dev.adaptiveIntervalSeconds || 10,
        batteryLevel: dev.batteryLevel,
        lowBatteryWarning: (dev.batteryLevel ?? 100) < 20
      });
    }

    const totalAudioDurationSeconds = recordings.reduce((acc, r) => acc + Number(r.durationSeconds || 0), 0);

    res.json({
      fleetSummary: {
        totalDevices: devices.length,
        fleetDistanceKm: Number((fleetTotalMeters / 1000).toFixed(3)),
        totalAuthorizedAudioSeconds: Number(totalAudioDurationSeconds.toFixed(1)),
        lowBatteryDevices: deviceMetrics.filter((m) => m.lowBatteryWarning).length
      },
      deviceMetrics
    });
  });

  // --- UNIFIED DASHBOARD OVERVIEW, SECURITY LOGS & ADMIN SECURITY / RATE-LIMIT VIEW ---
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

  app.get('/api/admin/security-summary', requireAuth(['admin', 'owner', 'auditor']), async (req, res) => {
    const logs =
      req.user.role === 'admin'
        ? await db.listAllSecurityLogs(200)
        : await db.listSecurityLogsByUser(req.user.id, 200);

    const severityCounts = { critical: 0, high: 0, warn: 0, info: 0 };
    for (const l of logs) {
      severityCounts[l.severity] = (severityCounts[l.severity] || 0) + 1;
    }

    res.json({
      rateLimitStatistics: rateLimiter.getStatistics(),
      severityBreakdown: severityCounts,
      recentCriticalEvents: logs.filter((l) => l.severity === 'critical' || l.severity === 'high').slice(0, 20),
      totalAuditLogsReturned: logs.length
    });
  });

  // --- HTTP & WEBSOCKET SERVER INITIALIZATION ---
  const server = http.createServer(app);
  const wsServer = new UnifiedWebSocketServer(server, '/ws');

  wsServer.on('connection', (client, req) => {
    client.on('error', () => {});
    const parsedUrl = new URL(req.url || '/ws', 'http://localhost');
    const token = parsedUrl.searchParams.get('token');
    if (token) {
      const payload = verifyJwt(token, ACCESS_SECRET);
      if (payload && payload.sub && payload.scope !== 'mfa_challenge') {
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
          if (!payload || !payload.sub || payload.scope === 'mfa_challenge') {
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
              altitude: msg.altitude,
              accuracy: msg.accuracy,
              speed: msg.speed,
              heading: msg.heading,
              batteryLevel: msg.batteryLevel,
              isCharging: msg.isCharging,
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

  return { app, server, db, wsServer, rateLimiter, notifications };
}

module.exports = { createPlatformServer };
