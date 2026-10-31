'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');

const appModulePath = fs.existsSync(path.join(__dirname, 'app.js'))
  ? './app'
  : '../src/app';
const dbModulePath = fs.existsSync(path.join(__dirname, 'db/index.js'))
  ? './db'
  : '../src/db';

const { createPlatformServer } = require(appModulePath);
const { DatabaseAdapter } = require(dbModulePath);

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

test('LiveTrack-Pro Unified Platform End-to-End Integration & Security Suite', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'livetrack-pro-test-'));
  const db = new DatabaseAdapter({ mode: 'embedded', persist: false });
  const { server } = createPlatformServer({
    db,
    storageDir: path.join(tmpDir, 'audio'),
    rateLimitMax: 250
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(() => {
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  let aliceAccess = '';
  let aliceRefresh = '';
  let bobAccess = '';
  let androidDeviceId = '';
  let pairingCode = '';
  let consentSessionId = '';
  let consentToken = '';
  let recordingId = '';

  await t.test('1. Health, Standalone Web Console & Security Headers Check', async () => {
    const consoleRes = await requestJson(baseUrl, 'GET', '/');
    assert.equal(consoleRes.status, 200);
    assert.ok(String(consoleRes.body).includes('LiveTrack-Pro'));

    const res = await requestJson(baseUrl, 'GET', '/api/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.ok(res.headers['strict-transport-security'].includes('max-age='));
  });

  await t.test('2. Unified Authentication: Register Alice & Bob, Login, and Rotate Refresh Tokens', async () => {
    const regAlice = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'alice@livetrack.pro',
      fullName: 'Alice Operator',
      password: 'StrongPassword!2026'
    });
    assert.equal(regAlice.status, 201);
    aliceAccess = regAlice.body.accessToken;
    aliceRefresh = regAlice.body.refreshToken;

    const dupAlice = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'alice@livetrack.pro',
      fullName: 'Alice Dup',
      password: 'StrongPassword!2026'
    });
    assert.equal(dupAlice.status, 409);

    const regBob = await requestJson(baseUrl, 'POST', '/api/auth/register', {
      email: 'bob@livetrack.pro',
      fullName: 'Bob Intruder',
      password: 'BobPassword!2026'
    });
    assert.equal(regBob.status, 201);
    bobAccess = regBob.body.accessToken;

    const refreshRes = await requestJson(baseUrl, 'POST', '/api/auth/refresh', {
      refreshToken: aliceRefresh
    });
    assert.equal(refreshRes.status, 200);

    const replayRes = await requestJson(baseUrl, 'POST', '/api/auth/refresh', {
      refreshToken: aliceRefresh
    });
    assert.equal(replayRes.status, 401);
    aliceAccess = refreshRes.body.accessToken;
    aliceRefresh = refreshRes.body.refreshToken;
  });

  await t.test('3. Device Registration, SVG QR Pairing Generator, Pairing Handshake & IDOR Protection', async () => {
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

    // Verify SVG QR Code & Deep-Link Generator
    const qrRes = await requestJson(
      baseUrl,
      'GET',
      `/api/devices/${androidDeviceId}/pairing-qr`,
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(qrRes.status, 200);
    assert.ok(qrRes.body.svgQr.includes('<svg'));
    assert.ok(qrRes.body.deepLink.startsWith('livetrack://pair'));

    const regTermux = await requestJson(
      baseUrl,
      'POST',
      '/api/devices/register',
      {
        deviceName: 'Termux Edge Node',
        platform: 'termux',
        hardwareFingerprint: 'termux-aarch64-01'
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(regTermux.status, 201);

    const pairRes = await requestJson(baseUrl, 'POST', '/api/devices/pair', {
      pairingCode
    });
    assert.equal(pairRes.status, 200);
    assert.equal(pairRes.body.status, 'paired');

    const idorRes = await requestJson(
      baseUrl,
      'GET',
      `/api/devices/${androidDeviceId}`,
      null,
      { Authorization: `Bearer ${bobAccess}` }
    );
    assert.equal(idorRes.status, 403);
    assert.equal(idorRes.body.error, 'IDOR_FORBIDDEN');
  });

  await t.test('4. GPS Module: Tracking, Geofences, Batch Sync, and GPX/GeoJSON/KML/CSV Exports', async () => {
    const startTrack = await requestJson(
      baseUrl,
      'POST',
      `/api/devices/${androidDeviceId}/tracking`,
      { active: true },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(startTrack.status, 200);

    const gfRes = await requestJson(
      baseUrl,
      'POST',
      '/api/geofences',
      {
        deviceId: androidDeviceId,
        name: 'Hyderabad Safe Zone',
        latitude: 17.3850,
        longitude: 78.4867,
        radiusMeters: 500
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(gfRes.status, 201);

    const gpsInside = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/update',
      {
        deviceId: androidDeviceId,
        latitude: 17.3852,
        longitude: 78.4868,
        accuracy: 3.8,
        speed: 1.4,
        batteryLevel: 91
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(gpsInside.status, 201);
    assert.equal(gpsInside.body.geofenceAlerts.length, 0);

    const gpsOutside = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/update',
      {
        deviceId: androidDeviceId,
        latitude: 17.4150,
        longitude: 78.5100,
        accuracy: 4.2,
        speed: 12.5,
        batteryLevel: 88
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(gpsOutside.status, 201);
    assert.equal(gpsOutside.body.geofenceAlerts.length, 1);

    const batchRes = await requestJson(
      baseUrl,
      'POST',
      '/api/gps/batch',
      {
        deviceId: androidDeviceId,
        locations: [
          { latitude: 17.4200, longitude: 78.5150, batteryLevel: 86 },
          { latitude: 17.4250, longitude: 78.5200, batteryLevel: 85 }
        ]
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(batchRes.status, 201);

    const gpxRes = await requestJson(baseUrl, 'GET', `/api/gps/export/${androidDeviceId}?format=gpx`, null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(gpxRes.status, 200);
    assert.ok(String(gpxRes.body).includes('<gpx version="1.1"'));

    const kmlRes = await requestJson(baseUrl, 'GET', `/api/gps/export/${androidDeviceId}?format=kml`, null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(kmlRes.status, 200);
    assert.ok(String(kmlRes.body).includes('<kml'));

    const csvRes = await requestJson(baseUrl, 'GET', `/api/gps/export/${androidDeviceId}?format=csv`, null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(csvRes.status, 200);
    assert.ok(String(csvRes.body).includes('latitude,longitude'));
  });

  await t.test('5. Audio Module: Reject Covert Activation, Verify Consent, Encrypt Upload, Stream & Delete', async () => {
    const covertAttempt = await requestJson(
      baseUrl,
      'POST',
      '/api/audio/sessions/start',
      {
        deviceId: androidDeviceId,
        initiatedByDevice: false,
        userConsentConfirmed: false
      },
      { Authorization: `Bearer ${aliceAccess}` }
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
        consentStatement: 'I explicitly consent to stream and record microphone audio with persistent notification visible.'
      },
      { Authorization: `Bearer ${aliceAccess}` }
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
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(uploadRes.status, 201);
    assert.equal(uploadRes.body.recording.waveformPeaks.length, 64);
    recordingId = uploadRes.body.recording.id;

    const bobStream = await requestJson(
      baseUrl,
      'GET',
      `/api/audio/recordings/${recordingId}/stream`,
      null,
      { Authorization: `Bearer ${bobAccess}` }
    );
    assert.equal(bobStream.status, 403);

    const aliceStream = await requestJson(
      baseUrl,
      'GET',
      `/api/audio/recordings/${recordingId}/stream`,
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(aliceStream.status, 200);
    assert.equal(Buffer.compare(aliceStream.raw, wavBuffer), 0);

    const stopRes = await requestJson(
      baseUrl,
      'POST',
      `/api/audio/sessions/${consentSessionId}/stop`,
      {},
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(stopRes.status, 200);

    const delRes = await requestJson(
      baseUrl,
      'DELETE',
      `/api/audio/recordings/${recordingId}`,
      null,
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(delRes.status, 200);
  });

  await t.test('6. Ephemeral Live Share Links & Fleet Telemetry Distance Analytics', async () => {
    const shareRes = await requestJson(
      baseUrl,
      'POST',
      '/api/shares',
      {
        deviceId: androidDeviceId,
        label: 'Emergency Responder Share',
        expiresInMinutes: 30
      },
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(shareRes.status, 201);
    const token = shareRes.body.share.shareToken;

    const pubRes = await requestJson(baseUrl, 'GET', `/api/shares/public/${token}`);
    assert.equal(pubRes.status, 200);
    assert.equal(pubRes.body.device.deviceName, 'Pixel 9 Pro - Android');

    const analyticsRes = await requestJson(baseUrl, 'GET', '/api/analytics/fleet', null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(analyticsRes.status, 200);
    assert.ok(analyticsRes.body.fleetSummary.fleetDistanceKm > 0);

    const revokeRes = await requestJson(baseUrl, 'DELETE', `/api/shares/${shareRes.body.share.id}`, null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(revokeRes.status, 200);
  });

  await t.test('7. Emergency SOS Beacon, Unified Overview & Immutable Security Audit Logs', async () => {
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
      { Authorization: `Bearer ${aliceAccess}` }
    );
    assert.equal(sosRes.status, 201);
    const sosId = sosRes.body.alert.id;

    const overviewRes = await requestJson(baseUrl, 'GET', '/api/overview', null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(overviewRes.status, 200);
    assert.equal(overviewRes.body.summary.activeSosAlerts, 1);

    const resolveRes = await requestJson(baseUrl, 'POST', `/api/sos/${sosId}/resolve`, {}, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(resolveRes.status, 200);

    const logsRes = await requestJson(baseUrl, 'GET', '/api/security-logs', null, {
      Authorization: `Bearer ${aliceAccess}`
    });
    assert.equal(logsRes.status, 200);
    assert.ok(logsRes.body.logs.some((l) => l.eventType === 'COVERT_OR_REMOTE_MIC_ATTEMPT_BLOCKED'));
  });

  await t.test('8. Real-Time RFC-6455 WebSocket Upgrade & Universal CLI Agent Verification', async () => {
    const { execFile } = require('child_process');
    const runAgentAsync = (args, env) =>
      new Promise((resolve, reject) => {
        execFile(process.execPath, args, { env, timeout: 5000 }, (err, stdout, stderr) => {
          if (err) return reject(new Error(stderr || err.message));
          resolve(stdout.toString());
        });
      });

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
    const agentEnv = { ...process.env, LIVETRACK_AGENT_CONFIG: cliConfigPath };

    const pairOut = await runAgentAsync([agentScript, '--server', baseUrl, '--pair', cliCode], agentEnv);
    assert.ok(pairOut.includes('Paired successfully'));

    const pingOut = await runAgentAsync([agentScript, '--server', baseUrl, '--ping-once'], agentEnv);
    assert.ok(pingOut.includes('GPS Ping Sent'));

    const audioOut = await runAgentAsync([agentScript, '--server', baseUrl, '--consent-audio'], agentEnv);
    assert.ok(audioOut.includes('Encrypted Recording Stored'));
  });
});
