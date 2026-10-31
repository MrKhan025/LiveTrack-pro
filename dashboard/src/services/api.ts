import type {
  User,
  Device,
  GpsLocation,
  AudioSession,
  AudioRecording,
  Geofence,
  SosAlert,
  SecurityLog,
  PlatformType
} from '../types/platform';

const API_BASE = import.meta.env.VITE_API_BASE || '';

class PlatformApiClient {
  private accessToken: string | null = localStorage.getItem('lt_access_token');
  private refreshToken: string | null = localStorage.getItem('lt_refresh_token');

  setTokens(access: string, refresh: string) {
    this.accessToken = access;
    this.refreshToken = refresh;
    localStorage.setItem('lt_access_token', access);
    localStorage.setItem('lt_refresh_token', refresh);
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('lt_access_token');
    localStorage.removeItem('lt_refresh_token');
  }

  getAccessToken() {
    return this.accessToken;
  }

  async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {})
    };
    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
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
    const data = await this.request<{ user: User; accessToken: string; refreshToken: string }>(
      '/api/auth/register',
      { method: 'POST', body: JSON.stringify({ email, fullName, password }) }
    );
    this.setTokens(data.accessToken, data.refreshToken);
    return data.user;
  }

  async login(email: string, password: string) {
    const data = await this.request<{ user: User; accessToken: string; refreshToken: string }>(
      '/api/auth/login',
      { method: 'POST', body: JSON.stringify({ email, password }) }
    );
    this.setTokens(data.accessToken, data.refreshToken);
    return data.user;
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

  async getOverview() {
    return this.request<{
      summary: {
        totalDevices: number;
        activeTrackingDevices: number;
        activeConsentAudioSessions: number;
        totalAuthorizedRecordings: number;
        activeGeofences: number;
        activeSosAlerts: number;
      };
      devices: Device[];
      recentAudioSessions: AudioSession[];
      recentSecurityLogs: SecurityLog[];
    }>('/api/overview');
  }

  async getDevices() {
    const res = await this.request<{ devices: Device[] }>('/api/devices');
    return res.devices;
  }

  async registerDevice(deviceName: string, platform: PlatformType) {
    return this.request<{ device: Device; pairingCode: string }>('/api/devices/register', {
      method: 'POST',
      body: JSON.stringify({ deviceName, platform })
    });
  }

  async pairDevice(pairingCode: string) {
    return this.request<{ status: string; device: Device; deviceAccessToken: string }>('/api/devices/pair', {
      method: 'POST',
      body: JSON.stringify({ pairingCode })
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
    accuracy?: number;
    speed?: number;
    batteryLevel?: number;
    provider?: string;
  }) {
    return this.request<{ location: GpsLocation; geofenceAlerts: unknown[] }>('/api/gps/update', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
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

  async triggerSos(payload: {
    deviceId: string;
    latitude: number;
    longitude: number;
    batteryLevel: number;
    message: string;
  }) {
    const res = await this.request<{ alert: SosAlert }>('/api/sos/trigger', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    return res.alert;
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

  async getSecurityLogs() {
    const res = await this.request<{ logs: SecurityLog[] }>('/api/security-logs');
    return res.logs;
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
