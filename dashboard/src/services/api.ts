import type {
  User,
  Device,
  GpsLocation,
  AudioSession,
  AudioRecording,
  Geofence,
  SosAlert,
  SecurityLog,
  AlertChannel,
  AdminSecuritySummary,
  PlatformType
} from '../types/platform';

const API_BASE = import.meta.env.VITE_API_BASE || '';

class PlatformApiClient {
  private accessToken: string | null = localStorage.getItem('lt_access_token');
  private refreshToken: string | null = localStorage.getItem('lt_refresh_token');
  private csrfToken: string | null = localStorage.getItem('lt_csrf_token');

  setTokens(access: string, refresh: string, csrf?: string) {
    this.accessToken = access;
    this.refreshToken = refresh;
    localStorage.setItem('lt_access_token', access);
    localStorage.setItem('lt_refresh_token', refresh);
    if (csrf) {
      this.csrfToken = csrf;
      localStorage.setItem('lt_csrf_token', csrf);
    }
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    this.csrfToken = null;
    localStorage.removeItem('lt_access_token');
    localStorage.removeItem('lt_refresh_token');
    localStorage.removeItem('lt_csrf_token');
  }

  getAccessToken() {
    return this.accessToken;
  }

  async ensureCsrfToken(): Promise<string | null> {
    if (this.csrfToken) return this.csrfToken;
    try {
      const res = await fetch(`${API_BASE}/api/auth/csrf-token`);
      if (!res.ok) return null;
      const data = await res.json();
      if (data.csrfToken) {
        this.csrfToken = data.csrfToken;
        localStorage.setItem('lt_csrf_token', data.csrfToken);
      }
      return this.csrfToken;
    } catch {
      return null;
    }
  }

  async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const method = (options.method || 'GET').toUpperCase();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {})
    };
    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrf = await this.ensureCsrfToken();
      if (csrf) {
        headers['X-CSRF-Token'] = csrf;
      }
    }

    let res = await fetch(`${API_BASE}${path}`, { ...options, headers });

    if (res.status === 401 && this.refreshToken && !path.includes('/api/auth/')) {
      const refreshed = await this.tryRefreshToken();
      if (refreshed && this.accessToken) {
        headers['Authorization'] = `Bearer ${this.accessToken}`;
        res = await fetch(`${API_BASE}${path}`, { ...options, headers });
      }
    }

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ message: res.statusText }));
      throw new Error(errBody.message || errBody.error || `HTTP ${res.status}`);
    }
    return res.json() as Promise<T>;
  }

  private async tryRefreshToken(): Promise<boolean> {
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: this.refreshToken })
      });
      if (!res.ok) {
        this.clearTokens();
        return false;
      }
      const data = await res.json();
      this.setTokens(data.accessToken, data.refreshToken);
      return true;
    } catch {
      this.clearTokens();
      return false;
    }
  }

  async register(email: string, fullName: string, password: string) {
    const data = await this.request<{ user: User; accessToken: string; refreshToken: string; csrfToken?: string }>(
      '/api/auth/register',
      { method: 'POST', body: JSON.stringify({ email, fullName, password }) }
    );
    this.setTokens(data.accessToken, data.refreshToken, data.csrfToken);
    return data.user;
  }

  async login(email: string, password: string, totpCode?: string) {
    const data = await this.request<{
      user?: User;
      accessToken?: string;
      refreshToken?: string;
      csrfToken?: string;
      mfaRequired?: boolean;
      mfaChallengeToken?: string;
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, ...(totpCode ? { totpCode } : {}) })
    });
    if (data.mfaRequired) {
      return { mfaRequired: true, mfaChallengeToken: data.mfaChallengeToken };
    }
    if (data.accessToken && data.refreshToken && data.user) {
      this.setTokens(data.accessToken, data.refreshToken, data.csrfToken);
      return { mfaRequired: false, user: data.user };
    }
    throw new Error('Unexpected login response');
  }

  async setupMfa() {
    return this.request<{ secret: string; otpauthUri: string; svgQr: string; recoveryCodes: string[] }>(
      '/api/auth/mfa/setup',
      { method: 'POST', body: JSON.stringify({}) }
    );
  }

  async enableMfa(totpCode: string) {
    return this.request<{ status: string; user: User }>('/api/auth/mfa/enable', {
      method: 'POST',
      body: JSON.stringify({ totpCode })
    });
  }

  async disableMfa(password: string, totpCode: string) {
    return this.request<{ status: string; user: User }>('/api/auth/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ password, totpCode })
    });
  }

  async deleteAccountAndData(password: string, totpCode?: string) {
    const res = await this.request<{ status: string; wipedAudioBlobs: number }>('/api/auth/account', {
      method: 'DELETE',
      body: JSON.stringify({ password, ...(totpCode ? { totpCode } : {}) })
    });
    this.clearTokens();
    return res;
  }

  async logout() {
    if (this.accessToken) {
      await this.request('/api/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: this.refreshToken })
      }).catch(() => {});
    }
    this.clearTokens();
  }

  async getDevices() {
    const res = await this.request<{ devices: Device[] }>('/api/devices');
    return res.devices;
  }

  async registerDevice(deviceName: string, platform: PlatformType, tokenScopes?: string[]) {
    return this.request<{ device: Device; pairingCode: string; pairingCodeExpiresAt: string }>(
      '/api/devices/register',
      { method: 'POST', body: JSON.stringify({ deviceName, platform, tokenScopes }) }
    );
  }

  async rotateDeviceToken(deviceId: string, tokenScopes?: string[]) {
    return this.request<{ status: string; device: Device; deviceAccessToken: string }>(
      `/api/devices/${deviceId}/rotate-token`,
      { method: 'POST', body: JSON.stringify({ tokenScopes }) }
    );
  }

  async updateDevicePermissions(deviceId: string, tokenScopes: string[]) {
    return this.request<{ device: Device }>(`/api/devices/${deviceId}/permissions`, {
      method: 'PUT',
      body: JSON.stringify({ tokenScopes })
    });
  }

  async setDeviceTracking(deviceId: string, active: boolean) {
    const res = await this.request<{ device: Device }>(`/api/devices/${deviceId}/tracking`, {
      method: 'POST',
      body: JSON.stringify({ active })
    });
    return res.device;
  }

  async pushGpsUpdate(payload: {
    deviceId: string;
    latitude: number;
    longitude: number;
    altitude?: number;
    accuracy?: number;
    speed?: number;
    batteryLevel?: number;
    provider?: string;
  }) {
    return this.request<{ location: GpsLocation; adaptiveIntervalSeconds: number; geofenceAlerts: unknown[] }>(
      '/api/gps/update',
      { method: 'POST', body: JSON.stringify(payload) }
    );
  }

  async getGpsHistory(deviceId: string, limit = 100) {
    const res = await this.request<{ history: GpsLocation[] }>(`/api/gps/history/${deviceId}?limit=${limit}`);
    return res.history;
  }

  async getAudioSessions() {
    const res = await this.request<{ sessions: AudioSession[] }>('/api/audio/sessions');
    return res.sessions;
  }

  async startConsentAudioSession(deviceId: string, consentStatement: string) {
    return this.request<{ session: AudioSession; consentToken: string }>('/api/audio/sessions/start', {
      method: 'POST',
      body: JSON.stringify({
        deviceId,
        initiatedByDevice: true,
        userConsentConfirmed: true,
        consentStatement
      })
    });
  }

  async stopConsentAudioSession(sessionId: string) {
    return this.request<{ session: AudioSession }>(`/api/audio/sessions/${sessionId}/stop`, {
      method: 'POST',
      body: JSON.stringify({})
    });
  }

  async getAudioRecordings() {
    const res = await this.request<{ recordings: AudioRecording[] }>('/api/audio/recordings');
    return res.recordings;
  }

  async uploadConsentRecording(payload: {
    sessionId: string;
    deviceId: string;
    consentToken: string;
    title: string;
    mimeType: string;
    durationSeconds: number;
    audioBase64: string;
  }) {
    const res = await this.request<{ recording: AudioRecording }>('/api/audio/recordings/upload', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    return res.recording;
  }

  async deleteAudioRecording(recordingId: string) {
    return this.request(`/api/audio/recordings/${recordingId}`, { method: 'DELETE' });
  }

  async fetchDecryptedAudioBlobUrl(recordingId: string): Promise<string> {
    const res = await fetch(`${API_BASE}/api/audio/recordings/${recordingId}/stream`, {
      headers: this.accessToken ? { Authorization: `Bearer ${this.accessToken}` } : {}
    });
    if (!res.ok) throw new Error('Failed to decrypt and stream recording');
    const blob = await res.blob();
    return URL.createObjectURL(blob);
  }

  async getGeofences() {
    const res = await this.request<{ geofences: Geofence[] }>('/api/geofences');
    return res.geofences;
  }

  async createGeofence(payload: {
    deviceId?: string | null;
    name: string;
    latitude: number;
    longitude: number;
    radiusMeters: number;
    notifyOnEnter?: boolean;
    notifyOnExit?: boolean;
  }) {
    const res = await this.request<{ geofence: Geofence }>('/api/geofences', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    return res.geofence;
  }

  async deleteGeofence(id: string) {
    return this.request(`/api/geofences/${id}`, { method: 'DELETE' });
  }

  async resolveSos(alertId: string) {
    const res = await this.request<{ alert: SosAlert }>(`/api/sos/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    return res.alert;
  }

  async getSosAlerts() {
    const res = await this.request<{ alerts: SosAlert[] }>('/api/sos');
    return res.alerts;
  }

  async getRetentionPolicy() {
    const res = await this.request<{
      retention: { gpsRetentionDays: number; audioRetentionDays: number; autoPurgeEnabled: boolean };
    }>('/api/settings/retention');
    return res.retention;
  }

  async updateRetentionPolicy(payload: {
    gpsRetentionDays: number;
    audioRetentionDays: number;
    autoPurgeEnabled: boolean;
  }) {
    const res = await this.request<{
      retention: { gpsRetentionDays: number; audioRetentionDays: number; autoPurgeEnabled: boolean };
    }>('/api/settings/retention', {
      method: 'PUT',
      body: JSON.stringify(payload)
    });
    return res.retention;
  }

  async purgeExpiredData() {
    return this.request<{ status: string; purgedGpsCount: number; purgedAudioCount: number }>(
      '/api/settings/retention/purge',
      { method: 'POST', body: JSON.stringify({}) }
    );
  }

  async getAlertChannels() {
    const res = await this.request<{ channels: AlertChannel[] }>('/api/alerts/channels');
    return res.channels;
  }

  async createAlertChannel(payload: {
    channelType: 'webhook' | 'telegram' | 'email';
    name: string;
    target: string;
    secretHeader?: string;
  }) {
    const res = await this.request<{ channel: AlertChannel }>('/api/alerts/channels', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    return res.channel;
  }

  async deleteAlertChannel(id: string) {
    return this.request(`/api/alerts/channels/${id}`, { method: 'DELETE' });
  }

  async getSecurityLogs() {
    const res = await this.request<{ logs: SecurityLog[] }>('/api/security-logs');
    return res.logs;
  }

  async getAdminSecuritySummary() {
    return this.request<AdminSecuritySummary>('/api/admin/security-summary');
  }

  connectWebSocket(onEvent: (event: Record<string, any>) => void): WebSocket | null {
    if (!this.accessToken) return null;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/ws?token=${encodeURIComponent(this.accessToken)}`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data);
        onEvent(parsed);
      } catch {}
    };
    return ws;
  }
}

export const api = new PlatformApiClient();
