'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');

// Provision ephemeral cryptographic secrets for the test runner if not already set in env
if (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET.length < 32) {
  process.env.JWT_ACCESS_SECRET = crypto.randomBytes(32).toString('hex');
}
if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
  process.env.JWT_REFRESH_SECRET = crypto.randomBytes(32).toString('hex');
}
if (!process.env.AUDIO_ENCRYPTION_KEY || !/^[0-9a-fA-F]{64}$/.test(process.env.AUDIO_ENCRYPTION_KEY)) {
  process.env.AUDIO_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
}

const appModulePath = fs.existsSync(path.join(__dirname, 'app.js')) ? './app' : '../src/app';
const dbModulePath = fs.existsSync(path.join(__dirname, 'db/index.js')) ? './db' : '../src/db';
const cryptoModulePath = fs.existsSync(path.join(__dirname, 'lib/cryptoAuth.js'))
  ? './lib/cryptoAuth'
  : '../src/lib/cryptoAuth';

const { createPlatformServer } = require(appModulePath);
const { DatabaseAdapter } = require(dbModulePath);
const { validateRequiredSecrets, generateTotpCode } = require(cryptoModulePath);

function createValidWavBuffer(durationSamples = 512) {
  const header = Buffer.alloc(44);
  const dataSize = durationSamples * 2;
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + dataSize, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(48000, 24);
  header.writeUInt32LE(96000, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36);
  header.writeUInt32LE(dataSize, 40);

  const samples = Buffer.alloc(dataSize);
  for (let i = 0; i < durationSamples; i++) {
    const val = Math.floor(Math.sin(i / 8) * 12000);
    samples.writeInt16LE(val, i * 2);
  }
  return Buffer.concat([header, samples]);
}

function requestJson(baseUrl, method, urlPath, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      url,
      {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          const contentType = res.headers['content-type'] || '';
          let parsed = raw;
          if (contentType.includes('application/json')) {
            try {
              parsed = JSON.parse(raw.toString('utf8'));
            } catch {}
          } else if (contentType.includes('text') || contentType.includes('xml') || contentType.includes('kml')) {
            parsed = raw.toString('utf8');
          }
          resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('LiveTrack-Pro v3.0 Comprehensive Security Hardening & Feature Verification Suite', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'livetrack-pro-v3-test-'));
  const encryptedDbFile = path.join(tmpDir, 'db.json.enc');
  const db = new DatabaseAdapter({
    mode: 'embedded',
    filePath: encryptedDbFile,
    persist: true,
    silentWarning: true
  });
  const { server, wsServer } = createPlatformServer({
    db,
    storageDir: path.join(tmpDir, 'audio'),
    rateLimitMax: 300
  });

  if (wsServer && typeof wsServer.on === 'function') {
    wsServer.on('connection', (client) => {
      client.on('error', () => {});
    });
  }

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(() => {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  let aliceAccess = '';
  let aliceRefresh = '';
  let bobAccess = '';
  let androidDeviceId = '';
  let pairingCode = '';
  let deviceScopedToken = '';
  let consentSessionId = '';
  let consentToken = '';
  let recordingId = '';

  await t.test('1. Fail-Fast Secret Check, Strict CORS Origin Policy & Mandatory Browser CSRF Enforcement', async () => {
    // 1a. Verify server refuses missing or placeholder development secrets
    assert.throws(() => validateRequiredSecrets({}), /FATAL_SECURITY_CONFIG/);
    assert.throws(
      () =>
        validateRequiredSecrets({
          JWT_ACCESS_SECRET: 'livetrack-dev-access-secret-override-in-prod',
          JWT_REFRESH_SECRET: crypto.randomBytes(32).toString('hex'),
          AUDIO_ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
        }),
      /FATAL_SECURITY_CONFIG/
    );

    // 1b. Health check & strict security headers (Never Access-Control-Allow-Origin: *)
    const res = await requestJson(baseUrl, 'GET', '/api/health', null, {
      Origin: 'http://localhost:3000'
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers['access-control-allow-origin'], 'http://localhost:3000');
    assert.notEqual(res.headers['access-control-allow-origin'], '*');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'DENY');

    // 1c. Unauthorized CORS Origin must be rejected with 403
    const badCors = await requestJson(baseUrl, 'GET', '/api/health', null, {
      Origin: 'https://evil-attacker.example.com'
    });
    assert.equal(badCors.status, 403);
    assert.equal(badCors.body.error, 'CORS_ORIGIN_FORBIDDEN');

    // 1d. Browser state-changing request without CSRF token must be rejected with 403
    const noCsrf = await requestJson(
      baseUrl,
      'POST',
      '/api/auth/logout',
      {},
      { Cookie: 'session_mode=browser' }
    );
    assert.equal(noCsrf.status, 403);
    assert.equal(noCsrf.body.error, 'CSRF_TOKEN_INVALID');
  });

  await t.test('2. Strong Password Policy (12+ Chars + Complexity) & Progressive Login Lockout', async () => {
    // Reject weak 8-char password
    const weakPw = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'alice@livetrack.pro',
      fullName: 'Alice Operator',
      password: 'Short1!'
    });
    assert.equal(weakPw.status, 400);
    assert.equal(weakPw.body.error, 'WEAK_PASSWORD');

    // Reject common breached password
    const breachedPw = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'alice@livetrack.pro',
      fullName: 'Alice Operator',
      password: 'Password1234!'
    });
    assert.equal(breachedPw.status, 400);

    // Register Alice with strong 12+ character password
    const regAlice = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'alice@livetrack.pro',
      fullName: 'Alice Operator',
      password: 'V3ryStr0ng#Pass2026'
    });
    assert.equal(regAlice.status, 201);
    aliceAccess = regAlice.body.accessToken;
    aliceRefresh = regAlice.body.refreshToken;

    // Register Bob for IDOR & Lockout testing
    const regBob = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'bob@livetrack.pro',
      fullName: 'Bob Intruder',
      password: 'B0bStr0ng#Pass2026'
    });
    assert.equal(regBob.status, 201);
    bobAccess = regBob.body.accessToken;

    // Trigger Progressive Account Lockout on Bob after 5 failed login attempts
    for (let i = 0; i < 4; i++) {
      const fail = await requestJson(baseUrl, 'POST', '/api/auth/login', {
        email: 'bob@livetrack.pro',
        password: 'WrongPassword#999'
      });
      assert.equal(fail.status, 401);
    }
    const fifthFail = await requestJson(baseUrl, 'POST', '/api/auth/login', {
      email: 'bob@livetrack.pro',
      password: 'WrongPassword#999'
    });
    assert.equal(fifthFail.status, 429);
    assert.equal(fifthFail.body.error, 'ACCOUNT_TEMPORARILY_LOCKED');
    assert.ok(fifthFail.body.retryAfterSeconds >= 30);
  });

  await t.test('3. Real RFC-6238 TOTP Multi-Factor Authentication (Setup, Enable, Challenge & Disable)', async () => {
    const setupRes = await requestJson(
      baseUrl,
      'POST',
      '/api/auth/mfa/setup',
      {},
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(setupRes.status, 200);
    assert.ok(setupRes.body.secret);
    assert.equal(setupRes.body.recoveryCodes.length, 8);

    const validTotp = generateTotpCode(setupRes.body.secret);
    const enableRes = await requestJson(
      baseUrl,
      'POST',
      '/api/auth/mfa/enable',
      { totpCode: validTotp },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(enableRes.status, 200);
    assert.equal(enableRes.body.user.mfaEnabled, true);

    // Login without TOTP code must return 202 MFA_REQUIRED
    const loginNoMfa = await requestJson(baseUrl, 'POST', '/api/auth/login', {
      email: 'alice@livetrack.pro',
      password: 'V3ryStr0ng#Pass2026'
    });
    assert.equal(loginNoMfa.status, 202);
    assert.equal(loginNoMfa.body.mfaRequired, true);

    // Complete MFA challenge via /api/auth/mfa/verify
    const verifyMfa = await requestJson(baseUrl, 'POST', '/api/auth/mfa/verify', {
      mfaChallengeToken: loginNoMfa.body.mfaChallengeToken,
      totpCode: generateTotpCode(setupRes.body.secret)
    });
    assert.equal(verifyMfa.status, 200);
    assert.ok(verifyMfa.body.accessToken);
    aliceAccess = verifyMfa.body.accessToken;

    // Disable MFA cleanly
    const disableRes = await requestJson(
      baseUrl,
      'POST',
      '/api/auth/mfa/disable',
      {
        password: 'V3ryStr0ng#Pass2026',
        totpCode: generateTotpCode(setupRes.body.secret)
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(disableRes.status, 200);
    assert.equal(disableRes.body.user.mfaEnabled, false);
  });

  await t.test('4. Expiring Single-Use Pairing Codes, Scoped Device Tokens, Rotation & Fine-Grained Permissions', async () => {
    // Register a device with already-expired TTL (-1 min) to verify 410 PAIRING_CODE_EXPIRED
    const expDev = await requestJson(
      baseUrl,
      'POST',
      '/api/devices/register',
      {
        deviceName: 'Expired Code Test Unit',
        platform: 'android',
        hardwareFingerprint: 'exp-hw-001',
        pairingTtlMinutes: -1
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(expDev.status, 201);
    const expPairAttempt = await requestJson(baseUrl, 'POST', '/api/devices/pair', {
      pairingCode: expDev.body.pairingCode
    });
    assert.equal(expPairAttempt.status, 410);
    assert.equal(expPairAttempt.body.error, 'PAIRING_CODE_EXPIRED');

    // Register Pixel 9 Pro with valid 10-minXXXX-XXXX pairing code
    const regDev = await requestJson(
      baseUrl,
      'POST',
      '/api/devices/register',
      {
        deviceName: 'Pixel 9 Pro - Android',
        platform: 'android',
        hardwareFingerprint: 'pixel9-hw-001'
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(regDev.status, 201);
    androidDeviceId = regDev.body.device.id;
    pairingCode = regDev.body.pairingCode;
    assert.match(pairingCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);

    const pairRes = await requestJson(baseUrl, 'POST', '/api/devices/pair', { pairingCode });
    assert.equal(pairRes.status, 200);
    deviceScopedToken = pairRes.body.deviceAccessToken;

    // Reusing the same pairing code must fail (Single-Use enforcement)
    const reusePair = await requestJson(baseUrl, 'POST', '/api/devices/pair', { pairingCode });
    assert.equal(reusePair.status, 404);

    // Restrict device scopes to GPS-only (remove 'audio:consent')
    const permRes = await requestJson(
      baseUrl,
      'PUT',
      `/api/devices/${androidDeviceId}/permissions`,
      { tokenScopes: ['gps:write', 'device:status'] },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(permRes.status, 200);

    // Device token attempting to start audio session without 'audio:consent' scope must fail 403
    const scopeBlocked = await requestJson(
      baseUrl,
      'POST',
      '/api/audio/sessions/start',
      {
        deviceId: androidDeviceId,
        initiatedByDevice: true,
        userConsentConfirmed: true,
        consentStatement: 'Attempt with GPS-only token'
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(scopeBlocked.status, 403);
    assert.equal(scopeBlocked.body.error, 'INSUFFICIENT_DEVICE_SCOPE');

    // Rotate device token & restore full scopes -> old deviceScopedToken must be rejected with 401
    const oldToken = deviceScopedToken;
    const rotateRes = await requestJson(
      baseUrl,
      'POST',
      `/api/devices/${androidDeviceId}/rotate-token`,
      { tokenScopes: ['gps:write', 'audio:consent', 'sos:trigger', 'device:status'] },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(rotateRes.status, 200);
    deviceScopedToken = rotateRes.body.deviceAccessToken;

    const oldTokenAttempt = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/update',
      { deviceId: androidDeviceId, latitude: 17.385, longitude: 78.4867 },
      { Authorization: `Bearer ${oldToken}` }
    );
    assert.equal(oldTokenAttempt.status, 401);
    assert.equal(oldTokenAttempt.body.error, 'DEVICE_TOKEN_ROTATED');
  });

  await t.test('5. Complete Geofence Enter & Exit Transitions, Adaptive GPS Interval & Exports', async () => {
    const gfRes = await requestJson(
      baseUrl,
      'POST',
      '/api/geofences',
      {
        deviceId: androidDeviceId,
        name: 'Hyderabad Safe Zone',
        latitude: 17.3850,
        longitude: 78.4867,
        radiusMeters: 500,
        notifyOnEnter: true,
        notifyOnExit: true
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(gfRes.status, 201);

    // 1st GPS point inside zone -> triggers GEOFENCE_ENTER
    const gpsEnter = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/update',
      {
        deviceId: androidDeviceId,
        latitude: 17.3852,
        longitude: 78.4868,
        altitude: 540,
        accuracy: 3.8,
        speed: 1.4,
        batteryLevel: 91
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(gpsEnter.status, 201);
    assert.equal(gpsEnter.body.geofenceAlerts.length, 1);
    assert.equal(gpsEnter.body.geofenceAlerts[0].event, 'GEOFENCE_ENTER');

    // 2nd GPS point outside zone -> triggers GEOFENCE_EXIT
    const gpsExit = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/update',
      {
        deviceId: androidDeviceId,
        latitude: 17.4150,
        longitude: 78.5100,
        altitude: 555,
        accuracy: 4.2,
        speed: 12.5,
        batteryLevel: 18
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(gpsExit.status, 201);
    assert.equal(gpsExit.body.geofenceAlerts.length, 1);
    assert.equal(gpsExit.body.geofenceAlerts[0].event, 'GEOFENCE_EXIT');

    // 3rd GPS point re-entering zone -> triggers GEOFENCE_ENTER again
    const gpsReEnter = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/update',
      {
        deviceId: androidDeviceId,
        latitude: 17.3851,
        longitude: 78.4866,
        altitude: 542,
        speed: 2.0,
        batteryLevel: 85
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(gpsReEnter.status, 201);
    assert.equal(gpsReEnter.body.geofenceAlerts.length, 1);
    assert.equal(gpsReEnter.body.geofenceAlerts[0].event, 'GEOFENCE_ENTER');

    // Verify Adaptive GPS Interval endpoint
    const adaptiveRes = await requestJson(
      baseUrl,
      'GET',
      `/api/devices/${androidDeviceId}/adaptive-config?batteryLevel=12&isCharging=false&speed=0`,
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(adaptiveRes.status, 200);
    assert.equal(adaptiveRes.body.recommendedIntervalSeconds, 90);
  });

  await t.test('6. Consent Audio Module: Anti-Covert 403 Block, 0600 Encrypted Storage & Decryption', async () => {
    const covertAttempt = await requestJson(
      baseUrl,
      'POST',
      '/api/audio/sessions/start',
      {
        deviceId: androidDeviceId,
        initiatedByDevice: false,
        userConsentConfirmed: false
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(covertAttempt.status, 403);
    assert.equal(covertAttempt.body.error, 'COVERT_RECORDING_PROHIBITED');

    const startAudio = await requestJson(
      baseUrl,
      'POST',
      '/api/audio/sessions/start',
      {
        deviceId: androidDeviceId,
        initiatedByDevice: true,
        userConsentConfirmed: true,
        consentStatement: 'Explicit device user consent confirmed.'
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(startAudio.status, 201);
    consentSessionId = startAudio.body.session.id;
    consentToken = startAudio.body.consentToken;

    const wavBuffer = createValidWavBuffer(1024);
    const uploadRes = await requestJson(
      baseUrl,
      'POST',
      '/api/audio/recordings/upload',
      {
        sessionId: consentSessionId,
        deviceId: androidDeviceId,
        consentToken,
        title: 'Field Safety Check-In #1',
        mimeType: 'audio/wav',
        durationSeconds: 4.5,
        audioBase64: wavBuffer.toString('base64')
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(uploadRes.status, 201);
    recordingId = uploadRes.body.recording.id;

    const aliceStream = await requestJson(
      baseUrl,
      'GET',
      `/api/audio/recordings/${recordingId}/stream`,
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(aliceStream.status, 200);
    assert.equal(Buffer.compare(aliceStream.raw, wavBuffer), 0);

    await requestJson(
      baseUrl,
      'POST',
      `/api/audio/sessions/${consentSessionId}/stop`,
      {},
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
  });

  await t.test('7. Push Notifications (FCM/APNs), Outbound Alert Channels (Webhook/Telegram/Email) & SOS', async () => {
    const pushReg = await requestJson(
      baseUrl,
      'POST',
      '/api/notifications/register-token',
      { deviceId: androidDeviceId, provider: 'fcm', token: 'fcm-token-pixel9-xyz987654321' },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(pushReg.status, 201);

    const chReg = await requestJson(
      baseUrl,
      'POST',
      '/api/alerts/channels',
      {
        channelType: 'webhook',
        name: 'SOC Security Webhook',
        target: 'https://soc.example.com/webhook',
        secretHeader: 'webhook-hmac-secret-2026'
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(chReg.status, 201);

    const sosRes = await requestJson(
      baseUrl,
      'POST',
      '/api/sos/trigger',
      {
        deviceId: androidDeviceId,
        latitude: 17.3850,
        longitude: 78.4867,
        batteryLevel: 42,
        message: 'Need immediate assistance at checkpoint'
      },
      { Authorization: `Bearer ${deviceScopedToken}` }
    );
    assert.equal(sosRes.status, 201);
    assert.ok(sosRes.body.dispatchedNotifications >= 2);

    const notifHist = await requestJson(
      baseUrl,
      'GET',
      '/api/notifications/history',
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(notifHist.status, 200);
    assert.ok(notifHist.body.notifications.some((n) => n.eventType === 'EMERGENCY_SOS'));
  });

  await t.test('8. Data Retention Policy, Encrypted Embedded DB Verification & Admin Security View', async () => {
    // Verify embedded database file on disk is AES-256-GCM encrypted (never plain JSON users/emails)
    assert.ok(fs.existsSync(encryptedDbFile));
    const diskRaw = fs.readFileSync(encryptedDbFile, 'utf8');
    const diskEnvelope = JSON.parse(diskRaw);
    assert.equal(diskEnvelope.encrypted, true);
    assert.equal(diskEnvelope.algorithm, 'aes-256-gcm');
    assert.ok(!diskRaw.includes('alice@livetrack.pro'));

    const retUpdate = await requestJson(
      baseUrl,
      'PUT',
      '/api/settings/retention',
      { gpsRetentionDays: 15, audioRetentionDays: 7, autoPurgeEnabled: true },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(retUpdate.status, 200);
    assert.equal(retUpdate.body.retention.gpsRetentionDays, 15);

    const purgeRes = await requestJson(
      baseUrl,
      'POST',
      '/api/settings/retention/purge',
      {},
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(purgeRes.status, 200);

    const adminRes = await requestJson(
      baseUrl,
      'GET',
      '/api/admin/security-summary',
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(adminRes.status, 200);
    assert.ok(adminRes.body.rateLimitStatistics.totalRequests > 10);
    assert.ok(adminRes.body.severityBreakdown.critical >= 1);
  });

  await t.test('9. Real-Time RFC-6455 WebSockets & Universal CLI Agent Verification', async () => {
    const { execFile } = require('child_process');
    const runAgentAsync = (args, env) =>
      new Promise((resolve, reject) => {
        execFile(process.execPath, args, { env, timeout: 6000 }, (err, stdout, stderr) => {
          if (err) return reject(new Error(stderr || err.message));
          resolve(stdout.toString());
        });
      });

    const regCliDev = await requestJson(
      baseUrl,
      'POST',
      '/api/devices/register',
      { deviceName: 'Universal CLI Agent', platform: 'linux', hardwareFingerprint: 'cli-test-01' },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    const cliCode = regCliDev.body.pairingCode;
    const cliConfigPath = path.join(tmpDir, 'cli-config.json');
    const agentScript = path.resolve(__dirname, '../../cli-agent/livetrack-agent.js');

    if (fs.existsSync(agentScript)) {
      const agentEnv = { ...process.env, LIVETRACK_AGENT_CONFIG: cliConfigPath };
      const pairOut = await runAgentAsync([agentScript, '--server', baseUrl, '--pair', cliCode], agentEnv);
      assert.ok(pairOut.includes('Paired successfully'));

      const pingOut = await runAgentAsync([agentScript, '--server', baseUrl, '--ping-once'], agentEnv);
      assert.ok(pingOut.includes('GPS Ping Sent'));

      const audioOut = await runAgentAsync([agentScript, '--server', baseUrl, '--consent-audio'], agentEnv);
      assert.ok(audioOut.includes('Encrypted Recording Stored'));
    }

    const wsKey = crypto.randomBytes(16).toString('base64');
    const wsUpgradeConfirmed = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port,
        path: `/ws?token=${encodeURIComponent(aliceAccess)}`,
        headers: {
          Connection: 'Upgrade',
          Upgrade: 'websocket',
          'Sec-WebSocket-Key': wsKey,
          'Sec-WebSocket-Version': '13'
        }
      });
      req.on('upgrade', (res, socket, head) => {
        if (res.statusCode === 101 && res.headers['sec-websocket-accept']) {
          const initial = head ? head.toString('utf8') : '';
          if (initial.includes('WS_AUTHENTICATED')) {
            socket.destroy();
            return resolve(true);
          }
          socket.on('data', (chunk) => {
            if (chunk.toString('utf8').includes('WS_AUTHENTICATED')) {
              socket.destroy();
              resolve(true);
            }
          });
        } else {
          socket.destroy();
          reject(new Error('WebSocket upgrade failed'));
        }
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(wsUpgradeConfirmed, true);
  });

  await t.test('10. GDPR Right to Erasure: Delete My Account & All Associated Data', async () => {
    const delRes = await requestJson(
      baseUrl,
      'DELETE',
      '/api/auth/account',
      { password: 'V3ryStr0ng#Pass2026' },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(delRes.status, 200);
    assert.equal(delRes.body.status, 'account_and_data_deleted');
    assert.ok(delRes.body.wipedAudioBlobs >= 1);

    // Subsequent profile lookup must return 404 USER_NOT_FOUND
    const meAfter = await requestJson(
      baseUrl,
      'GET',
      '/api/auth/me',
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(meAfter.status, 404);
  });
});
