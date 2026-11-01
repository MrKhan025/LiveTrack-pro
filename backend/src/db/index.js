'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { encryptText, decryptText } = require('../lib/cryptoAuth');

const DEFAULT_DEVICE_SCOPES = ['gps:write', 'audio:consent', 'sos:trigger', 'device:status'];

class DatabaseAdapter {
  constructor(options = {}) {
    this.mode = options.mode || process.env.DB_MODE || 'embedded';
    this.filePath =
      options.filePath ||
      process.env.EMBEDDED_DB_FILE ||
      path.join(__dirname, '../../storage/db.json.enc');
    this.persist = options.persist !== false;
    this.pgPool = null;

    if (
      process.env.NODE_ENV === 'production' &&
      this.mode === 'embedded' &&
      process.env.ALLOW_EMBEDDED_IN_PROD !== 'true' &&
      !options.allowEmbeddedInProd
    ) {
      throw new Error(
        'FATAL_DB_CONFIG: Embedded database mode is disabled in production by default. Configure DB_MODE=postgres with DATABASE_URL, or set ALLOW_EMBEDDED_IN_PROD=true if running on an edge/Termux node.'
      );
    }

    this.state = {
      users: [],
      sessions: [],
      devices: [],
      gps_locations: [],
      audio_sessions: [],
      audio_recordings: [],
      geofences: [],
      geofence_states: [],
      sos_alerts: [],
      live_shares: [],
      push_tokens: [],
      alert_channels: [],
      security_logs: []
    };

    if (this.mode === 'postgres') {
      try {
        const { Pool } = require('pg');
        this.pgPool = new Pool({
          connectionString: process.env.DATABASE_URL
        });
      } catch {
        console.warn('[DB] `pg` driver not found in current environment; falling back to encrypted embedded store.');
        this.mode = 'embedded';
      }
    }

    if (this.mode === 'embedded') {
      if (!options.silentWarning) {
        console.warn(
          '[DB SECURITY NOTICE] Running in embedded database mode (AES-256-GCM encrypted at rest). Use PostgreSQL (DB_MODE=postgres) for multi-user production clusters.'
        );
      }
      if (this.persist) {
        this._loadFromDisk();
      }
    }
  }

  _loadFromDisk() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        let jsonStr = raw;
        if (raw.trim().startsWith('{')) {
          const envelope = JSON.parse(raw);
          if (envelope && envelope.encrypted && envelope.payload) {
            jsonStr = decryptText(envelope.payload);
          }
        } else {
          jsonStr = decryptText(raw);
        }
        if (jsonStr) {
          const parsed = JSON.parse(jsonStr);
          this.state = { ...this.state, ...parsed };
        }
      }
    } catch {}
  }

  _saveToDisk() {
    if (this.mode !== 'embedded' || !this.persist || !this.filePath) return;
    try {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const encryptedPayload = encryptText(JSON.stringify(this.state));
      const envelope = JSON.stringify(
        {
          encrypted: true,
          algorithm: 'aes-256-gcm',
          updatedAt: new Date().toISOString(),
          payload: encryptedPayload
        },
        null,
        2
      );
      fs.writeFileSync(this.filePath, envelope, { encoding: 'utf8', mode: 0o600 });
    } catch {}
  }

  _sanitizeUser(u) {
    if (!u) return null;
    const {
      passwordHash: _pw,
      mfaSecretEncrypted: _mfa,
      mfaRecoveryCodes: _rec,
      ...safe
    } = u;
    return safe;
  }

  // --- USERS, LOCKOUT, MFA & RETENTION ---
  async createUser({ email, fullName, passwordHash, role = 'owner' }) {
    const normalizedEmail = String(email).trim().toLowerCase();
    if (this.state.users.some((u) => u.email === normalizedEmail)) {
      const err = new Error('Email already registered');
      err.code = 'DUPLICATE_EMAIL';
      throw err;
    }
    const user = {
      id: crypto.randomUUID(),
      email: normalizedEmail,
      fullName,
      passwordHash,
      role,
      mfaEnabled: false,
      mfaSecretEncrypted: null,
      mfaRecoveryCodes: [],
      failedLoginAttempts: 0,
      lockedUntil: null,
      gpsRetentionDays: 30,
      audioRetentionDays: 14,
      autoPurgeEnabled: true,
      isActive: true,
      createdAt: new Date().toISOString()
    };
    this.state.users.push(user);
    this._saveToDisk();
    return this._sanitizeUser(user);
  }

  async findUserByEmail(email) {
    const normalizedEmail = String(email).trim().toLowerCase();
    return this.state.users.find((u) => u.email === normalizedEmail) || null;
  }

  async findUserById(id) {
    const u = this.state.users.find((item) => item.id === id);
    return this._sanitizeUser(u);
  }

  async findRawUserById(id) {
    return this.state.users.find((item) => item.id === id) || null;
  }

  async recordFailedLogin(userId) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u) return null;
    u.failedLoginAttempts = (u.failedLoginAttempts || 0) + 1;
    let lockSeconds = 0;
    if (u.failedLoginAttempts >= 5) {
      // Progressive exponential backoff: 30s, 60s, 120s, 240s... capped at 900s (15m)
      lockSeconds = Math.min(900, 30 * 2 ** (u.failedLoginAttempts - 5));
      u.lockedUntil = new Date(Date.now() + lockSeconds * 1000).toISOString();
    }
    this._saveToDisk();
    return {
      failedLoginAttempts: u.failedLoginAttempts,
      lockedUntil: u.lockedUntil,
      lockSeconds
    };
  }

  async resetFailedLogins(userId) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u) return;
    u.failedLoginAttempts = 0;
    u.lockedUntil = null;
    this._saveToDisk();
  }

  async saveMfaSetup(userId, mfaSecretEncrypted, recoveryCodesHashes) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u) return null;
    u.mfaSecretEncrypted = mfaSecretEncrypted;
    u.mfaRecoveryCodes = recoveryCodesHashes;
    this._saveToDisk();
    return this._sanitizeUser(u);
  }

  async setMfaEnabled(userId, enabled) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u) return null;
    u.mfaEnabled = Boolean(enabled);
    if (!enabled) {
      u.mfaSecretEncrypted = null;
      u.mfaRecoveryCodes = [];
    }
    this._saveToDisk();
    return this._sanitizeUser(u);
  }

  async consumeMfaRecoveryCode(userId, codeHash) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u || !Array.isArray(u.mfaRecoveryCodes)) return false;
    const idx = u.mfaRecoveryCodes.indexOf(codeHash);
    if (idx === -1) return false;
    u.mfaRecoveryCodes.splice(idx, 1);
    this._saveToDisk();
    return true;
  }

  async updateUserRetentionPolicy(userId, { gpsRetentionDays, audioRetentionDays, autoPurgeEnabled }) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u) return null;
    if (gpsRetentionDays !== undefined) u.gpsRetentionDays = Number(gpsRetentionDays);
    if (audioRetentionDays !== undefined) u.audioRetentionDays = Number(audioRetentionDays);
    if (autoPurgeEnabled !== undefined) u.autoPurgeEnabled = Boolean(autoPurgeEnabled);
    this._saveToDisk();
    return {
      gpsRetentionDays: u.gpsRetentionDays,
      audioRetentionDays: u.audioRetentionDays,
      autoPurgeEnabled: u.autoPurgeEnabled
    };
  }

  async purgeExpiredDataForUser(userId, customCutoffs = null) {
    const u = this.state.users.find((item) => item.id === userId);
    if (!u) return { purgedGpsCount: 0, purgedAudioRecordings: [] };

    const gpsCutoffMs = customCutoffs?.gpsCutoffMs ?? Date.now() - (u.gpsRetentionDays || 30) * 86400 * 1000;
    const audioCutoffMs = customCutoffs?.audioCutoffMs ?? Date.now() - (u.audioRetentionDays || 14) * 86400 * 1000;

    const beforeGps = this.state.gps_locations.length;
    this.state.gps_locations = this.state.gps_locations.filter(
      (l) => l.ownerId !== userId || new Date(l.recordedAt).getTime() >= gpsCutoffMs
    );
    const purgedGpsCount = beforeGps - this.state.gps_locations.length;

    const expiredRecordings = this.state.audio_recordings.filter(
      (r) => r.ownerId === userId && new Date(r.createdAt).getTime() < audioCutoffMs
    );
    this.state.audio_recordings = this.state.audio_recordings.filter(
      (r) => r.ownerId !== userId || new Date(r.createdAt).getTime() >= audioCutoffMs
    );

    this._saveToDisk();
    return { purgedGpsCount, purgedAudioRecordings: expiredRecordings };
  }

  async deleteUserAccountAndAllData(userId) {
    const userRecordings = this.state.audio_recordings.filter((r) => r.ownerId === userId);
    const userDeviceIds = new Set(
      this.state.devices.filter((d) => d.ownerId === userId).map((d) => d.id)
    );

    this.state.sessions = this.state.sessions.filter((s) => s.userId !== userId);
    this.state.gps_locations = this.state.gps_locations.filter((l) => l.ownerId !== userId);
    this.state.audio_recordings = this.state.audio_recordings.filter((r) => r.ownerId !== userId);
    this.state.audio_sessions = this.state.audio_sessions.filter((s) => s.ownerId !== userId);
    this.state.geofence_states = this.state.geofence_states.filter((gs) => !userDeviceIds.has(gs.deviceId));
    this.state.geofences = this.state.geofences.filter((g) => g.ownerId !== userId);
    this.state.sos_alerts = this.state.sos_alerts.filter((a) => a.ownerId !== userId);
    this.state.live_shares = this.state.live_shares.filter((s) => s.ownerId !== userId);
    this.state.push_tokens = this.state.push_tokens.filter((p) => p.userId !== userId);
    this.state.alert_channels = this.state.alert_channels.filter((c) => c.userId !== userId);
    this.state.devices = this.state.devices.filter((d) => d.ownerId !== userId);
    this.state.users = this.state.users.filter((u) => u.id !== userId);

    this._saveToDisk();
    return { deletedAudioFiles: userRecordings.map((r) => r.filePath).filter(Boolean) };
  }

  // --- SESSIONS (Refresh Tokens) ---
  async createSession({ userId, refreshTokenHash, userAgent, ipAddress, expiresAt }) {
    const session = {
      id: crypto.randomUUID(),
      userId,
      refreshTokenHash,
      userAgent: userAgent || 'unknown',
      ipAddress: ipAddress || '127.0.0.1',
      revoked: false,
      expiresAt,
      createdAt: new Date().toISOString()
    };
    this.state.sessions.push(session);
    this._saveToDisk();
    return session;
  }

  async findValidSession(refreshTokenHash) {
    const now = Date.now();
    return (
      this.state.sessions.find(
        (s) => s.refreshTokenHash === refreshTokenHash && !s.revoked && new Date(s.expiresAt).getTime() > now
      ) || null
    );
  }

  async revokeSession(refreshTokenHash) {
    const s = this.state.sessions.find((item) => item.refreshTokenHash === refreshTokenHash);
    if (s) {
      s.revoked = true;
      this._saveToDisk();
    }
  }

  // --- DEVICES, EXPIRING SINGLE-USE PAIRING & SCOPED TOKENS ---
  async registerDevice({
    ownerId,
    deviceName,
    platform,
    hardwareFingerprint,
    pairingCode,
    pairingCodeExpiresAt,
    tokenScopes = DEFAULT_DEVICE_SCOPES
  }) {
    let existing = this.state.devices.find(
      (d) => d.ownerId === ownerId && d.hardwareFingerprint === hardwareFingerprint
    );
    if (existing) {
      existing.deviceName = deviceName;
      existing.pairingCode = pairingCode;
      existing.pairingCodeExpiresAt = pairingCodeExpiresAt;
      existing.tokenScopes = Array.isArray(tokenScopes) ? tokenScopes : DEFAULT_DEVICE_SCOPES;
      existing.updatedAt = new Date().toISOString();
      this._saveToDisk();
      return existing;
    }
    const device = {
      id: crypto.randomUUID(),
      ownerId,
      deviceName,
      platform,
      hardwareFingerprint,
      pairingCode,
      pairingCodeExpiresAt,
      deviceTokenHash: null,
      tokenScopes: Array.isArray(tokenScopes) ? tokenScopes : DEFAULT_DEVICE_SCOPES,
      tokenRotatedAt: null,
      adaptiveIntervalSeconds: 10,
      isPaired: false,
      trackingActive: false,
      micConsentActive: false,
      batteryLevel: 100,
      isCharging: false,
      lastLatitude: null,
      lastLongitude: null,
      lastAccuracy: null,
      lastSpeed: null,
      lastSeenAt: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    this.state.devices.push(device);
    this._saveToDisk();
    return device;
  }

  async pairDeviceByCode({ pairingCode, deviceTokenHash }) {
    const normalized = String(pairingCode).trim().toUpperCase();
    const dev = this.state.devices.find((d) => d.pairingCode === normalized);
    if (!dev) return { status: 'not_found', device: null };

    if (dev.pairingCodeExpiresAt && new Date(dev.pairingCodeExpiresAt).getTime() < Date.now()) {
      // Single-use cleanup on expired attempt
      dev.pairingCode = null;
      dev.pairingCodeExpiresAt = null;
      this._saveToDisk();
      return { status: 'expired', device: dev };
    }

    dev.isPaired = true;
    dev.deviceTokenHash = deviceTokenHash;
    dev.tokenRotatedAt = new Date().toISOString();
    dev.pairingCode = null;
    dev.pairingCodeExpiresAt = null;
    dev.lastSeenAt = new Date().toISOString();
    dev.updatedAt = new Date().toISOString();
    this._saveToDisk();
    return { status: 'paired', device: dev };
  }

  async rotateDeviceToken(deviceId, newDeviceTokenHash, newScopes = null) {
    const dev = this.state.devices.find((d) => d.id === deviceId);
    if (!dev) return null;
    dev.deviceTokenHash = newDeviceTokenHash;
    dev.tokenRotatedAt = new Date().toISOString();
    if (Array.isArray(newScopes)) {
      dev.tokenScopes = newScopes;
    }
    dev.updatedAt = new Date().toISOString();
    this._saveToDisk();
    return dev;
  }

  async updateDevicePermissions(deviceId, tokenScopes) {
    const dev = this.state.devices.find((d) => d.id === deviceId);
    if (!dev) return null;
    dev.tokenScopes = Array.isArray(tokenScopes) ? tokenScopes : DEFAULT_DEVICE_SCOPES;
    dev.updatedAt = new Date().toISOString();
    this._saveToDisk();
    return dev;
  }

  async getDeviceById(deviceId) {
    return this.state.devices.find((d) => d.id === deviceId) || null;
  }

  async listDevicesByOwner(ownerId) {
    return this.state.devices.filter((d) => d.ownerId === ownerId);
  }

  async updateDeviceState(deviceId, updates) {
    const dev = this.state.devices.find((d) => d.id === deviceId);
    if (dev) {
      Object.assign(dev, updates, { updatedAt: new Date().toISOString() });
      this._saveToDisk();
    }
    return dev || null;
  }

  // --- GPS LOCATIONS ---
  async insertGpsLocation(point) {
    const loc = {
      id: crypto.randomUUID(),
      deviceId: point.deviceId,
      ownerId: point.ownerId,
      latitude: Number(point.latitude),
      longitude: Number(point.longitude),
      altitude: Number(point.altitude || 0),
      accuracy: Number(point.accuracy || 5.0),
      speed: Number(point.speed || 0),
      heading: Number(point.heading || 0),
      batteryLevel: Number(point.batteryLevel ?? 100),
      provider: point.provider || 'fused',
      recordedAt: point.recordedAt || new Date().toISOString()
    };

    this.state.gps_locations.push(loc);
    await this.updateDeviceState(loc.deviceId, {
      lastLatitude: loc.latitude,
      lastLongitude: loc.longitude,
      lastAccuracy: loc.accuracy,
      lastSpeed: loc.speed,
      batteryLevel: loc.batteryLevel,
      isCharging: Boolean(point.isCharging),
      adaptiveIntervalSeconds: Number(point.adaptiveIntervalSeconds || 10),
      lastSeenAt: loc.recordedAt
    });
    return loc;
  }

  async getDeviceGpsHistory(deviceId, limit = 100) {
    return this.state.gps_locations
      .filter((l) => l.deviceId === deviceId)
      .sort((a, b) => new Date(b.recordedAt) - new Date(a.recordedAt))
      .slice(0, limit);
  }

  // --- CONSENT-BASED AUDIO SESSIONS & RECORDINGS ---
  async createAudioSession({
    deviceId,
    ownerId,
    consentTokenHash,
    consentStatement,
    sampleRate = 48000,
    channels = 1,
    mimeType = 'audio/wav'
  }) {
    const session = {
      id: crypto.randomUUID(),
      deviceId,
      ownerId,
      consentTokenHash,
      initiatedByDevice: true,
      consentStatement,
      status: 'active',
      sampleRate,
      channels,
      mimeType,
      startedAt: new Date().toISOString(),
      endedAt: null
    };
    this.state.audio_sessions.push(session);
    await this.updateDeviceState(deviceId, { micConsentActive: true, lastSeenAt: session.startedAt });
    this._saveToDisk();
    return session;
  }

  async getAudioSessionById(sessionId) {
    return this.state.audio_sessions.find((s) => s.id === sessionId) || null;
  }

  async listAudioSessionsByOwner(ownerId) {
    return this.state.audio_sessions
      .filter((s) => s.ownerId === ownerId)
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  }

  async stopAudioSession(sessionId) {
    const session = this.state.audio_sessions.find((s) => s.id === sessionId);
    if (!session) return null;
    session.status = 'stopped';
    session.endedAt = new Date().toISOString();
    await this.updateDeviceState(session.deviceId, { micConsentActive: false });
    this._saveToDisk();
    return session;
  }

  async createAudioRecording(rec) {
    const item = {
      id: crypto.randomUUID(),
      sessionId: rec.sessionId,
      deviceId: rec.deviceId,
      ownerId: rec.ownerId,
      title: rec.title,
      filePath: rec.filePath,
      mimeType: rec.mimeType,
      durationSeconds: Number(rec.durationSeconds || 1),
      sizeBytes: Number(rec.sizeBytes || 0),
      encryptionIv: rec.encryptionIv,
      encryptionAuthTag: rec.encryptionAuthTag,
      sha256Checksum: rec.sha256Checksum,
      waveformPeaks: rec.waveformPeaks || [],
      createdAt: new Date().toISOString()
    };
    this.state.audio_recordings.push(item);
    this._saveToDisk();
    return item;
  }

  async listAudioRecordingsByOwner(ownerId) {
    return this.state.audio_recordings
      .filter((r) => r.ownerId === ownerId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  async getAudioRecordingById(recordingId) {
    return this.state.audio_recordings.find((r) => r.id === recordingId) || null;
  }

  async deleteAudioRecording(recordingId) {
    const idx = this.state.audio_recordings.findIndex((r) => r.id === recordingId);
    if (idx === -1) return null;
    const [removed] = this.state.audio_recordings.splice(idx, 1);
    this._saveToDisk();
    return removed;
  }

  // --- GEOFENCES & STATE TRANSITIONS (ENTER + EXIT) ---
  async createGeofence({
    ownerId,
    deviceId = null,
    name,
    latitude,
    longitude,
    radiusMeters,
    notifyOnEnter = true,
    notifyOnExit = true
  }) {
    const gf = {
      id: crypto.randomUUID(),
      ownerId,
      deviceId,
      name,
      latitude: Number(latitude),
      longitude: Number(longitude),
      radiusMeters: Number(radiusMeters),
      notifyOnEnter: Boolean(notifyOnEnter),
      notifyOnExit: Boolean(notifyOnExit),
      active: true,
      createdAt: new Date().toISOString()
    };
    this.state.geofences.push(gf);
    this._saveToDisk();
    return gf;
  }

  async listGeofencesByOwner(ownerId) {
    return this.state.geofences.filter((g) => g.ownerId === ownerId);
  }

  async deleteGeofence(geofenceId, ownerId) {
    const idx = this.state.geofences.findIndex((g) => g.id === geofenceId && g.ownerId === ownerId);
    if (idx === -1) return false;
    this.state.geofences.splice(idx, 1);
    this.state.geofence_states = this.state.geofence_states.filter((gs) => gs.geofenceId !== geofenceId);
    this._saveToDisk();
    return true;
  }

  async evaluateGeofenceTransition(geofenceId, deviceId, isCurrentlyInside) {
    let record = this.state.geofence_states.find(
      (gs) => gs.geofenceId === geofenceId && gs.deviceId === deviceId
    );
    if (!record) {
      record = {
        id: crypto.randomUUID(),
        geofenceId,
        deviceId,
        isInside: isCurrentlyInside,
        updatedAt: new Date().toISOString()
      };
      this.state.geofence_states.push(record);
      this._saveToDisk();
      return { transition: isCurrentlyInside ? 'ENTER' : 'EXIT', initial: true };
    }

    const wasInside = record.isInside;
    if (wasInside === isCurrentlyInside) {
      return { transition: null, initial: false };
    }
    record.isInside = isCurrentlyInside;
    record.updatedAt = new Date().toISOString();
    this._saveToDisk();
    return {
      transition: isCurrentlyInside ? 'ENTER' : 'EXIT',
      initial: false
    };
  }

  // --- EMERGENCY SOS ALERTS ---
  async createSosAlert({ deviceId, ownerId, latitude, longitude, batteryLevel, message }) {
    const alert = {
      id: crypto.randomUUID(),
      deviceId,
      ownerId,
      latitude: Number(latitude),
      longitude: Number(longitude),
      batteryLevel: Number(batteryLevel ?? 100),
      message: message || 'User-initiated SOS beacon triggered',
      status: 'active',
      triggeredAt: new Date().toISOString(),
      resolvedAt: null
    };
    this.state.sos_alerts.push(alert);
    this._saveToDisk();
    return alert;
  }

  async resolveSosAlert(alertId, ownerId) {
    const alert = this.state.sos_alerts.find((a) => a.id === alertId && a.ownerId === ownerId);
    if (!alert) return null;
    alert.status = 'resolved';
    alert.resolvedAt = new Date().toISOString();
    this._saveToDisk();
    return alert;
  }

  async listSosAlertsByOwner(ownerId) {
    return this.state.sos_alerts
      .filter((a) => a.ownerId === ownerId)
      .sort((a, b) => new Date(b.triggeredAt) - new Date(a.triggeredAt));
  }

  // --- EPHEMERAL LIVE LOCATION SHARES ---
  async createLiveShare({ ownerId, deviceId, label = 'Emergency Family Share', expiresInMinutes = 60 }) {
    const share = {
      id: crypto.randomUUID(),
      ownerId,
      deviceId,
      shareToken: crypto.randomBytes(18).toString('hex'),
      label: String(label).trim(),
      revoked: false,
      expiresAt: new Date(Date.now() + Number(expiresInMinutes) * 60000).toISOString(),
      createdAt: new Date().toISOString()
    };
    this.state.live_shares.push(share);
    this._saveToDisk();
    return share;
  }

  async getLiveShareByToken(shareToken) {
    const now = Date.now();
    return (
      this.state.live_shares.find(
        (s) => s.shareToken === shareToken && !s.revoked && new Date(s.expiresAt).getTime() > now
      ) || null
    );
  }

  async listLiveSharesByOwner(ownerId) {
    return this.state.live_shares
      .filter((s) => s.ownerId === ownerId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  async revokeLiveShare(shareId, ownerId) {
    const share = this.state.live_shares.find((s) => s.id === shareId && s.ownerId === ownerId);
    if (!share) return null;
    share.revoked = true;
    this._saveToDisk();
    return share;
  }

  // --- PUSH TOKENS (FCM & APNs) ---
  async registerPushToken({ userId, deviceId = null, provider = 'fcm', token }) {
    const existing = this.state.push_tokens.find(
      (pt) => pt.userId === userId && pt.provider === provider && pt.token === token
    );
    if (existing) return existing;
    const item = {
      id: crypto.randomUUID(),
      userId,
      deviceId,
      provider,
      token,
      createdAt: new Date().toISOString()
    };
    this.state.push_tokens.push(item);
    this._saveToDisk();
    return item;
  }

  async listPushTokensByUser(userId) {
    return this.state.push_tokens.filter((pt) => pt.userId === userId);
  }

  // --- OUTBOUND CRITICAL ALERT CHANNELS (WEBHOOK / TELEGRAM / EMAIL) ---
  async createAlertChannel({
    userId,
    channelType,
    name,
    target,
    secretHeader = null,
    events = ['EMERGENCY_SOS', 'GEOFENCE_ENTER', 'GEOFENCE_EXIT', 'LOW_BATTERY']
  }) {
    const ch = {
      id: crypto.randomUUID(),
      userId,
      channelType,
      name: String(name).trim(),
      target: String(target).trim(),
      secretHeader,
      events,
      enabled: true,
      createdAt: new Date().toISOString()
    };
    this.state.alert_channels.push(ch);
    this._saveToDisk();
    return ch;
  }

  async listAlertChannelsByUser(userId) {
    return this.state.alert_channels.filter((c) => c.userId === userId);
  }

  async deleteAlertChannel(channelId, userId) {
    const idx = this.state.alert_channels.findIndex((c) => c.id === channelId && c.userId === userId);
    if (idx === -1) return false;
    this.state.alert_channels.splice(idx, 1);
    this._saveToDisk();
    return true;
  }

  // --- SECURITY LOGS ---
  async appendSecurityLog({
    userId = null,
    deviceId = null,
    eventType,
    severity = 'info',
    ipAddress = '127.0.0.1',
    userAgent = 'system',
    details = {}
  }) {
    const entry = {
      id: crypto.randomUUID(),
      userId,
      deviceId,
      eventType,
      severity,
      ipAddress,
      userAgent,
      details,
      createdAt: new Date().toISOString()
    };
    this.state.security_logs.push(entry);
    this._saveToDisk();
    return entry;
  }

  async listSecurityLogsByUser(userId, limit = 100) {
    return this.state.security_logs
      .filter((l) => l.userId === userId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, limit);
  }

  async listAllSecurityLogs(limit = 200) {
    return [...this.state.security_logs]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, limit);
  }
}

module.exports = { DatabaseAdapter, DEFAULT_DEVICE_SCOPES };
