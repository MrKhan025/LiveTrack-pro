import React, { useEffect, useState, useCallback } from 'react';
import { api } from './services/api';
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
} from './types/platform';
import { LiveGpsMap } from './components/LiveGpsMap';
import { AudioConsentCenter } from './components/AudioConsentCenter';
import { WebDeviceClient } from './components/WebDeviceClient';

type TabKey =
  | 'overview'
  | 'map'
  | 'devices'
  | 'audio-sessions'
  | 'recordings'
  | 'history'
  | 'web-endpoint'
  | 'settings'
  | 'security-logs';

export const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');

  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [gpsHistory, setGpsHistory] = useState<GpsLocation[]>([]);
  const [audioSessions, setAudioSessions] = useState<AudioSession[]>([]);
  const [recordings, setRecordings] = useState<AudioRecording[]>([]);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [sosAlerts, setSosAlerts] = useState<SosAlert[]>([]);
  const [securityLogs, setSecurityLogs] = useState<SecurityLog[]>([]);
  const [liveWaveform, setLiveWaveform] = useState<number[]>([]);

  // Device Registration & Pairing state
  const [newDeviceName, setNewDeviceName] = useState('');
  const [newDevicePlatform, setNewDevicePlatform] = useState<PlatformType>('android');
  const [generatedPairingCode, setGeneratedPairingCode] = useState<string | null>(null);

  // Geofence form state
  const [gfName, setGfName] = useState('');
  const [gfLat, setGfLat] = useState('17.3850');
  const [gfLon, setGfLon] = useState('78.4867');
  const [gfRadius, setGfRadius] = useState('500');

  const refreshAll = useCallback(async () => {
    if (!api.getAccessToken()) return;
    try {
      const [meRes, devList, sessList, recList, gfList, sosList, logList] = await Promise.all([
        api.request<{ user: User }>('/api/auth/me'),
        api.getDevices(),
        api.getAudioSessions(),
        api.getAudioRecordings(),
        api.getGeofences(),
        api.getSosAlerts(),
        api.getSecurityLogs()
      ]);
      setUser(meRes.user);
      setDevices(devList);
      if (!selectedDeviceId && devList.length > 0) {
        setSelectedDeviceId(devList[0].id);
      }
      setAudioSessions(sessList);
      setRecordings(recList);
      setGeofences(gfList);
      setSosAlerts(sosList);
      setSecurityLogs(logList);
    } catch {
      setUser(null);
    }
  }, [selectedDeviceId]);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    if (!selectedDeviceId || !user) return;
    api.getGpsHistory(selectedDeviceId, 120).then(setGpsHistory).catch(() => {});
  }, [selectedDeviceId, user]);

  useEffect(() => {
    if (!user) return;
    const ws = api.connectWebSocket((event) => {
      if (event.type === 'GPS_LOCATION_UPDATE') {
        refreshAll();
        if (event.location?.deviceId === selectedDeviceId) {
          setGpsHistory((prev) => [event.location, ...prev.slice(0, 119)]);
        }
      } else if (
        event.type === 'AUDIO_SESSION_STARTED' ||
        event.type === 'AUDIO_SESSION_STOPPED' ||
        event.type === 'AUDIO_RECORDING_CREATED' ||
        event.type === 'EMERGENCY_SOS_ALERT' ||
        event.type === 'EMERGENCY_SOS_RESOLVED' ||
        event.type === 'DEVICE_TRACKING_STATE'
      ) {
        refreshAll();
      } else if (event.type === 'LIVE_AUDIO_CHUNK' && Array.isArray(event.waveformPeaks)) {
        setLiveWaveform(event.waveformPeaks);
      }
    });
    return () => {
      ws?.close();
    };
  }, [user, selectedDeviceId, refreshAll]);

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    try {
      if (authMode === 'register') {
        const u = await api.register(email, fullName, password);
        setUser(u);
      } else {
        const u = await api.login(email, password);
        setUser(u);
      }
      await refreshAll();
    } catch (err: any) {
      setAuthError(err.message || 'Authentication failed');
    }
  };

  const handleRegisterDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDeviceName.trim()) return;
    const { pairingCode } = await api.registerDevice(newDeviceName.trim(), newDevicePlatform);
    setGeneratedPairingCode(pairingCode);
    setNewDeviceName('');
    await refreshAll();
  };

  const handleToggleTracking = async (dev: Device) => {
    await api.setDeviceTracking(dev.id, !dev.trackingActive);
    await refreshAll();
  };

  const handleCreateGeofence = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.createGeofence({
      deviceId: selectedDeviceId,
      name: gfName,
      latitude: Number(gfLat),
      longitude: Number(gfLon),
      radiusMeters: Number(gfRadius)
    });
    setGfName('');
    await refreshAll();
  };

  if (!user) {
    return (
      <div className="auth-wrapper">
        <div className="auth-card">
          <div className="brand-header">
            <span className="brand-badge">LIVETRACK-PRO</span>
            <h1>LiveTrack-Pro Unified Platform</h1>
            <p className="muted">
              Real-Time Fused GPS Telemetry & Explicit Consent-Based Audio Streaming for Android, Termux, iOS, Windows & Linux
            </p>
          </div>
          {authError && <div className="alert-error">{authError}</div>}
          <form onSubmit={handleAuthSubmit} className="stack-md">
            {authMode === 'register' && (
              <div>
                <label>Full Name</label>
                <input
                  className="input"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Rivera"
                  required
                />
              </div>
            )}
            <div>
              <label>Email Address</label>
              <input
                type="email"
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@livetrack.pro"
                required
              />
            </div>
            <div>
              <label>Password (min 8 chars)</label>
              <input
                type="password"
                className="input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
              />
            </div>
            <button type="submit" className="btn btn-primary btn-block">
              {authMode === 'login' ? 'Sign In to Unified Console' : 'Create Secure Account'}
            </button>
          </form>
          <div className="auth-switch">
            {authMode === 'login' ? (
              <span>
                Need an account?{' '}
                <button className="link-btn" onClick={() => setAuthMode('register')}>
                  Register here
                </button>
              </span>
            ) : (
              <span>
                Already registered?{' '}
                <button className="link-btn" onClick={() => setAuthMode('login')}>
                  Sign in
                </button>
              </span>
            )}
          </div>
        </div>
      </div>
    );
  }

  const activeSos = sosAlerts.filter((a) => a.status === 'active');

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-pill">LIVETRACK-PRO v2.0</span>
          <h2>LiveTrack-Pro</h2>
          <p className="muted-xs">GPS + Consent Audio</p>
        </div>

        <nav className="nav-menu">
          <button className={activeTab === 'overview' ? 'active' : ''} onClick={() => setActiveTab('overview')}>
            📊 Overview
          </button>
          <button className={activeTab === 'map' ? 'active' : ''} onClick={() => setActiveTab('map')}>
            🗺️ Live GPS Map
          </button>
          <button className={activeTab === 'devices' ? 'active' : ''} onClick={() => setActiveTab('devices')}>
            📱 Registered Devices
          </button>
          <button className={activeTab === 'audio-sessions' ? 'active' : ''} onClick={() => setActiveTab('audio-sessions')}>
            🎙️ Audio Sessions
          </button>
          <button className={activeTab === 'recordings' ? 'active' : ''} onClick={() => setActiveTab('recordings')}>
            🔐 Authorized Recordings
          </button>
          <button className={activeTab === 'history' ? 'active' : ''} onClick={() => setActiveTab('history')}>
            🧭 Device History & Geofences
          </button>
          <button className={activeTab === 'web-endpoint' ? 'active' : ''} onClick={() => setActiveTab('web-endpoint')}>
            🌐 Web / iOS Endpoint
          </button>
          <button className={activeTab === 'settings' ? 'active' : ''} onClick={() => setActiveTab('settings')}>
            ⚙️ Account Settings
          </button>
          <button className={activeTab === 'security-logs' ? 'active' : ''} onClick={() => setActiveTab('security-logs')}>
            🛡️ Security Logs
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="user-chip">
            <strong>{user.fullName}</strong>
            <span className="muted-xs">{user.email} ({user.role})</span>
          </div>
          <button
            className="btn btn-sm btn-outline"
            onClick={async () => {
              await api.logout();
              setUser(null);
            }}
          >
            Sign Out
          </button>
        </div>
      </aside>

      <main className="main-content">
        {activeSos.length > 0 && (
          <div className="sos-banner">
            <div>
              <strong>🚨 ACTIVE EMERGENCY SOS BEACON ({activeSos.length}):</strong>{' '}
              {activeSos[0].message} at ({activeSos[0].latitude.toFixed(4)}, {activeSos[0].longitude.toFixed(4)}) — Battery {activeSos[0].batteryLevel}%
            </div>
            <button
              className="btn btn-sm btn-light"
              onClick={async () => {
                await api.resolveSos(activeSos[0].id);
                refreshAll();
              }}
            >
              Mark Resolved
            </button>
          </div>
        )}

        {activeTab === 'overview' && (
          <div className="stack-lg">
            <div className="kpi-grid">
              <div className="kpi-card">
                <span className="kpi-label">Registered Devices</span>
                <strong className="kpi-value">{devices.length}</strong>
                <span className="kpi-sub">Android, Termux, iOS, Desktop</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Active GPS Trackers</span>
                <strong className="kpi-value">{devices.filter((d) => d.trackingActive).length}</strong>
                <span className="kpi-sub">Fused Location + WebSocket</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Live Consent Audio</span>
                <strong className="kpi-value">{audioSessions.filter((s) => s.status === 'active').length}</strong>
                <span className="kpi-sub">User-Initiated Only</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Encrypted Recordings</span>
                <strong className="kpi-value">{recordings.length}</strong>
                <span className="kpi-sub">AES-256-GCM at Rest</span>
              </div>
            </div>

            <LiveGpsMap
              devices={devices}
              selectedDeviceId={selectedDeviceId}
              history={gpsHistory}
              geofences={geofences}
              onSelectDevice={setSelectedDeviceId}
              onToggleTracking={handleToggleTracking}
            />
          </div>
        )}

        {activeTab === 'map' && (
          <LiveGpsMap
            devices={devices}
            selectedDeviceId={selectedDeviceId}
            history={gpsHistory}
            geofences={geofences}
            onSelectDevice={setSelectedDeviceId}
            onToggleTracking={handleToggleTracking}
          />
        )}

        {activeTab === 'devices' && (
          <div className="stack-lg">
            <div className="card">
              <h3>Pair a New Cross-Platform Device</h3>
              <form onSubmit={handleRegisterDevice} className="form-inline">
                <input
                  className="input"
                  placeholder="Device Name (e.g., Pixel 9 Pro, Termux Pocket Node, iPhone 16)"
                  value={newDeviceName}
                  onChange={(e) => setNewDeviceName(e.target.value)}
                  required
                />
                <select
                  className="input"
                  value={newDevicePlatform}
                  onChange={(e) => setNewDevicePlatform(e.target.value as PlatformType)}
                >
                  <option value="android">Android (Kotlin App)</option>
                  <option value="termux">Termux (Android CLI)</option>
                  <option value="ios">iOS (iPhone/iPad PWA)</option>
                  <option value="linux">Linux Desktop/Server</option>
                  <option value="windows">Windows PC</option>
                  <option value="macos">macOS</option>
                  <option value="web">Web Browser</option>
                </select>
                <button type="submit" className="btn btn-primary">
                  Generate Pairing Code
                </button>
              </form>
              {generatedPairingCode && (
                <div className="pairing-box">
                  <strong>One-Time Pairing Code:</strong> <code>{generatedPairingCode}</code>
                  <p className="muted-xs">
                    Enter this code in the Android Kotlin App, or run:{' '}
                    <code>node cli-agent/livetrack-agent.js --pair {generatedPairingCode}</code> on Termux/Linux/Windows/macOS.
                  </p>
                </div>
              )}
            </div>

            <div className="card">
              <h3>Registered Fleet Inventory</h3>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Device Name</th>
                    <th>Platform</th>
                    <th>Paired</th>
                    <th>Battery</th>
                    <th>GPS Status</th>
                    <th>Mic Indicator</th>
                    <th>Last Seen</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id}>
                      <td><strong>{d.deviceName}</strong></td>
                      <td><span className="platform-pill">{d.platform.toUpperCase()}</span></td>
                      <td>{d.isPaired ? '✅ Paired' : `⏳ Code: ${d.pairingCode || 'Pending'}`}</td>
                      <td>🔋 {d.batteryLevel}%</td>
                      <td>{d.trackingActive ? '🟢 Active' : '⚪ Paused'}</td>
                      <td>{d.micConsentActive ? '🔴 LIVE CONSENT MIC' : 'Muted'}</td>
                      <td>{d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : 'Never'}</td>
                      <td>
                        <button className="btn btn-sm btn-primary" onClick={() => handleToggleTracking(d)}>
                          {d.trackingActive ? 'Stop GPS' : 'Start GPS'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {(activeTab === 'audio-sessions' || activeTab === 'recordings') && (
          <AudioConsentCenter
            devices={devices}
            sessions={audioSessions}
            recordings={recordings}
            liveWaveform={liveWaveform}
            onRefresh={refreshAll}
          />
        )}

        {activeTab === 'history' && (
          <div className="panel-grid-2">
            <div className="card">
              <div className="card-header">
                <h3>Location History ({gpsHistory.length} points)</h3>
                {selectedDeviceId && (
                  <div className="row-actions">
                    <a
                      className="btn btn-sm btn-outline"
                      href={`/api/gps/export/${selectedDeviceId}?format=gpx`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Download GPX
                    </a>
                    <a
                      className="btn btn-sm btn-outline"
                      href={`/api/gps/export/${selectedDeviceId}?format=geojson`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Download GeoJSON
                    </a>
                  </div>
                )}
              </div>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Coordinates</th>
                      <th>Speed / Accuracy</th>
                      <th>Battery</th>
                    </tr>
                  </thead>
                  <tbody>
                    {gpsHistory.map((pt) => (
                      <tr key={pt.id}>
                        <td>{new Date(pt.recordedAt).toLocaleTimeString()}</td>
                        <td>{pt.latitude.toFixed(5)}, {pt.longitude.toFixed(5)}</td>
                        <td>{pt.speed} m/s (±{pt.accuracy}m)</td>
                        <td>{pt.batteryLevel}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <h3>Smart Geofence Zones</h3>
              <form onSubmit={handleCreateGeofence} className="stack-sm">
                <input
                  className="input"
                  placeholder="Zone Name (e.g., Campus Perimeter)"
                  value={gfName}
                  onChange={(e) => setGfName(e.target.value)}
                  required
                />
                <div className="form-inline">
                  <input className="input" placeholder="Latitude" value={gfLat} onChange={(e) => setGfLat(e.target.value)} required />
                  <input className="input" placeholder="Longitude" value={gfLon} onChange={(e) => setGfLon(e.target.value)} required />
                  <input className="input" placeholder="Radius (m)" value={gfRadius} onChange={(e) => setGfRadius(e.target.value)} required />
                </div>
                <button type="submit" className="btn btn-primary">Add Geofence</button>
              </form>
              <table className="data-table" style={{ marginTop: '1rem' }}>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Center</th>
                    <th>Radius</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {geofences.map((g) => (
                    <tr key={g.id}>
                      <td>{g.name}</td>
                      <td>{g.latitude.toFixed(4)}, {g.longitude.toFixed(4)}</td>
                      <td>{g.radiusMeters}m</td>
                      <td>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={async () => {
                            await api.deleteGeofence(g.id);
                            refreshAll();
                          }}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'web-endpoint' && (
          <WebDeviceClient devices={devices} onRefresh={refreshAll} />
        )}

        {activeTab === 'settings' && (
          <div className="card">
            <h3>Account & Cryptographic Security Profile</h3>
            <div className="stack-md">
              <div><strong>Full Name:</strong> {user.fullName}</div>
              <div><strong>Email:</strong> {user.email}</div>
              <div><strong>Access Role:</strong> <span className="badge badge-info">{user.role.toUpperCase()}</span></div>
              <div><strong>Password Storage:</strong> Scrypt KDF (16-byte random salt, 64-byte key, timing-safe comparison)</div>
              <div><strong>Session Transport:</strong> Short-lived HS256 JWT + Automatic Refresh Token Rotation</div>
              <div><strong>Audio Vault Encryption:</strong> AES-256-GCM with per-recording 96-bit IV + 128-bit Auth Tag + SHA-256 checksum</div>
            </div>
          </div>
        )}

        {activeTab === 'security-logs' && (
          <div className="card">
            <h3>Immutable Security & Anti-Covert Audit Logs ({securityLogs.length})</h3>
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Event Type</th>
                    <th>IP Address</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {securityLogs.map((log) => (
                    <tr key={log.id}>
                      <td>{new Date(log.createdAt).toLocaleString()}</td>
                      <td>
                        <span className={`badge badge-${log.severity === 'critical' || log.severity === 'high' ? 'danger' : log.severity === 'warn' ? 'warning' : 'info'}`}>
                          {log.severity.toUpperCase()}
                        </span>
                      </td>
                      <td><code>{log.eventType}</code></td>
                      <td>{log.ipAddress}</td>
                      <td><code>{JSON.stringify(log.details)}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
