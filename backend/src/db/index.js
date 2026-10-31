'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class DatabaseAdapter {
  constructor(options = {}) {
    this.mode = options.mode || process.env.DB_MODE || 'embedded';
    this.filePath = options.filePath || process.env.EMBEDDED_DB_FILE || path.join(__dirname, '../../storage/db.json');
    this.pgPool = null;

    this.state = {
      users: [],
      sessions: [],
      devices: [],
      gps_locations: [],
      audio_sessions: [],
      audio_recordings: [],
      geofences: [],
      sos_alerts: [],
      security_logs: []
    };

    if (this.mode === 'postgres') {
      try {
        const { Pool } = require('pg');
        this.pgPool = new Pool({
          connectionString: process.env.DATABASE_URL
        });
      } catch (err) {
        console.warn('[DB] `pg` driver not found in current environment; falling back to embedded persistent store.');
        this.mode = 'embedded';
      }
    }

    if (this.mode === 'embedded' && options.persist !== false) {
      this._loadFromDisk();
    }
  }

  _loadFromDisk() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        const parsed = JSON.parse(raw);
        this.state = { ...this.state, ...parsed };
      }
    } catch {}
  }

  _saveToDisk() {
    if (this.mode !== 'embedded' || !this.filePath) return;
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this.state, null, 2), 'utf8');
    } catch {}
  }

  // --- USERS ---
  async createUser({ email, fullName, passwordHash, role = 'owner' }) {
    const normalizedEmail = String(email).trim().toLowerCase();
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `INSERT INTO users (email, full_name, password_hash, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, full_name AS "fullName", role, is_active AS "isActive", created_at AS "createdAt"`,
        [normalizedEmail, fullName, passwordHash, role]
      );
      return rows[0];
    }
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
      isActive: true,
      createdAt: new Date().toISOString()
    };
    this.state.users.push(user);
    this._saveToDisk();
    const { passwordHash: _, ...safe } = user;
    return safe;
  }

  async findUserByEmail(email) {
    const normalizedEmail = String(email).trim().toLowerCase();
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `SELECT id, email, full_name AS "fullName", password_hash AS "passwordHash", role, is_active AS "isActive", created_at AS "createdAt"
         FROM users WHERE email = $1 LIMIT 1`,
        [normalizedEmail]
      );
      return rows[0] || null;
    }
    return this.state.users.find((u) => u.email === normalizedEmail) || null;
  }

  async findUserById(id) {
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `SELECT id, email, full_name AS "fullName", role, is_active AS "isActive", created_at AS "createdAt"
         FROM users WHERE id = $1 LIMIT 1`,
        [id]
      );
      return rows[0] || null;
    }
    const u = this.state.users.find((item) => item.id === id);
    if (!u) return null;
    const { passwordHash: _, ...safe } = u;
    return safe;
  }

  // --- SESSIONS (Refresh Tokens) ---
  async createSession({ userId, refreshTokenHash, userAgent, ipAddress, expiresAt }) {
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at)
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [userId, refreshTokenHash, userAgent, ipAddress, expiresAt]
      );
      return rows[0];
    }
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
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `SELECT id, user_id AS "userId", refresh_token_hash AS "refreshTokenHash", revoked, expires_at AS "expiresAt"
         FROM sessions WHERE refresh_token_hash = $1 AND revoked = FALSE AND expires_at > NOW() LIMIT 1`,
        [refreshTokenHash]
      );
      return rows[0] || null;
    }
    const now = Date.now();
    return (
      this.state.sessions.find(
        (s) => s.refreshTokenHash === refreshTokenHash && !s.revoked && new Date(s.expiresAt).getTime() > now
      ) || null
    );
  }

  async revokeSession(refreshTokenHash) {
    if (this.mode === 'postgres' && this.pgPool) {
      await this.pgPool.query(`UPDATE sessions SET revoked = TRUE WHERE refresh_token_hash = $1`, [refreshTokenHash]);
      return;
    }
    const s = this.state.sessions.find((item) => item.refreshTokenHash === refreshTokenHash);
    if (s) {
      s.revoked = true;
      this._saveToDisk();
    }
  }

  // --- DEVICES ---
  async registerDevice({ ownerId, deviceName, platform, hardwareFingerprint, pairingCode }) {
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `INSERT INTO devices (owner_id, device_name, platform, hardware_fingerprint, pairing_code)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (owner_id, hardware_fingerprint)
         DO UPDATE SET device_name = EXCLUDED.device_name, pairing_code = EXCLUDED.pairing_code, updated_at = NOW()
         RETURNING id, owner_id AS "ownerId", device_name AS "deviceName", platform, hardware_fingerprint AS "hardwareFingerprint",
                   pairing_code AS "pairingCode", is_paired AS "isPaired", tracking_active AS "trackingActive",
                   mic_consent_active AS "micConsentActive", battery_level AS "batteryLevel", is_charging AS "isCharging",
                   last_latitude AS "lastLatitude", last_longitude AS "lastLongitude", last_seen_at AS "lastSeenAt"`,
        [ownerId, deviceName, platform, hardwareFingerprint, pairingCode]
      );
      return rows[0];
    }
    let existing = this.state.devices.find(
      (d) => d.ownerId === ownerId && d.hardwareFingerprint === hardwareFingerprint
    );
    if (existing) {
      existing.deviceName = deviceName;
      existing.pairingCode = pairingCode;
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
      deviceTokenHash: null,
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
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `UPDATE devices
         SET is_paired = TRUE, device_token_hash = $2, pairing_code = NULL, last_seen_at = NOW(), updated_at = NOW()
         WHERE pairing_code = $1
         RETURNING id, owner_id AS "ownerId", device_name AS "deviceName", platform, is_paired AS "isPaired"`,
        [pairingCode, deviceTokenHash]
      );
      return rows[0] || null;
    }
    const dev = this.state.devices.find((d) => d.pairingCode === pairingCode);
    if (!dev) return null;
    dev.isPaired = true;
    dev.deviceTokenHash = deviceTokenHash;
    dev.pairingCode = null;
    dev.lastSeenAt = new Date().toISOString();
    dev.updatedAt = new Date().toISOString();
    this._saveToDisk();
    return dev;
  }

  async getDeviceById(deviceId) {
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `SELECT id, owner_id AS "ownerId", device_name AS "deviceName", platform, hardware_fingerprint AS "hardwareFingerprint",
                is_paired AS "isPaired", tracking_active AS "trackingActive", mic_consent_active AS "micConsentActive",
                battery_level AS "batteryLevel", is_charging AS "isCharging",
                last_latitude AS "lastLatitude", last_longitude AS "lastLongitude",
                last_accuracy AS "lastAccuracy", last_speed AS "lastSpeed", last_seen_at AS "lastSeenAt"
         FROM devices WHERE id = $1 LIMIT 1`,
        [deviceId]
      );
      return rows[0] || null;
    }
    return this.state.devices.find((d) => d.id === deviceId) || null;
  }

  async listDevicesByOwner(ownerId) {
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `SELECT id, owner_id AS "ownerId", device_name AS "deviceName", platform, hardware_fingerprint AS "hardwareFingerprint",
                pairing_code AS "pairingCode", is_paired AS "isPaired", tracking_active AS "trackingActive",
                mic_consent_active AS "micConsentActive", battery_level AS "batteryLevel", is_charging AS "isCharging",
                last_latitude AS "lastLatitude", last_longitude AS "lastLongitude",
                last_accuracy AS "lastAccuracy", last_speed AS "lastSpeed", last_seen_at AS "lastSeenAt"
         FROM devices WHERE owner_id = $1 ORDER BY created_at DESC`,
        [ownerId]
      );
      return rows;
    }
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

    if (this.mode === 'postgres' && this.pgPool) {
      await this.pgPool.query(
        `INSERT INTO gps_locations (id, device_id, owner_id, latitude, longitude, altitude, accuracy, speed, heading, battery_level, provider, recorded_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [loc.id, loc.deviceId, loc.ownerId, loc.latitude, loc.longitude, loc.altitude, loc.accuracy, loc.speed, loc.heading, loc.batteryLevel, loc.provider, loc.recordedAt]
      );
      await this.pgPool.query(
        `UPDATE devices SET last_latitude = $2, last_longitude = $3, last_accuracy = $4, last_speed = $5,
                            battery_level = $6, last_seen_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [loc.deviceId, loc.latitude, loc.longitude, loc.accuracy, loc.speed, loc.batteryLevel]
      );
      return loc;
    }

    this.state.gps_locations.push(loc);
    await this.updateDeviceState(loc.deviceId, {
      lastLatitude: loc.latitude,
      lastLongitude: loc.longitude,
      lastAccuracy: loc.accuracy,
      lastSpeed: loc.speed,
      batteryLevel: loc.batteryLevel,
      lastSeenAt: loc.recordedAt
    });
    return loc;
  }

  async getDeviceGpsHistory(deviceId, limit = 100) {
    if (this.mode === 'postgres' && this.pgPool) {
      const { rows } = await this.pgPool.query(
        `SELECT id, device_id AS "deviceId", latitude, longitude, altitude, accuracy, speed, heading,
                battery_level AS "batteryLevel", provider, recorded_at AS "recordedAt"
         FROM gps_locations WHERE device_id = $1 ORDER BY recorded_at DESC LIMIT $2`,
        [deviceId, limit]
      );
      return rows;
    }
    return this.state.gps_locations
      .filter((l) => l.deviceId === deviceId)
      .sort((a, b) => new Date(b.recordedAt) - new Date(a.recordedAt))
      .slice(0, limit);
  }

  // --- CONSENT-BASED AUDIO SESSIONS & RECORDINGS ---
  async createAudioSession({ deviceId, ownerId, consentTokenHash, consentStatement, sampleRate = 48000, channels = 1, mimeType = 'audio/wav' }) {
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

  // --- GEOFENCES ---
  async createGeofence({ ownerId, deviceId = null, name, latitude, longitude, radiusMeters, notifyOnEnter = true, notifyOnExit = true }) {
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
    this._saveToDisk();
    return true;
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

  // --- SECURITY LOGS ---
  async appendSecurityLog({ userId = null, deviceId = null, eventType, severity = 'info', ipAddress = '127.0.0.1', userAgent = 'system', details = {} }) {
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
}

module.exports = { DatabaseAdapter };
