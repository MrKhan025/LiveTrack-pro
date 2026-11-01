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
  AlertChannel,
  AdminSecuritySummary,
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
  const [totpCode, setTotpCode] = useState('');
  const [mfaPromptRequired, setMfaPromptRequired] = useState(false);
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
  const [adminSummary, setAdminSummary] = useState<AdminSecuritySummary | null>(null);
  const [alertChannels, setAlertChannels] = useState<AlertChannel[]>([]);
  const [liveWaveform, setLiveWaveform] = useState<number[]>([]);

  // Device Registration & Pairing state
  const [newDeviceName, setNewDeviceName] = useState('');
  const [newDevicePlatform, setNewDevicePlatform] = useState<PlatformType>('android');
  const [generatedPairingCode, setGeneratedPairingCode] = useState<string | null>(null);
  const [rotatedDeviceToken, setRotatedDeviceToken] = useState<string | null>(null);

  // Geofence form state
  const [gfName, setGfName] = useState('');
  const [gfLat, setGfLat] = useState('17.3850');
  const [gfLon, setGfLon] = useState('78.4867');
  const [gfRadius, setGfRadius] = useState('500');

  // MFA Setup & Retention & GDPR state
  const [mfaSetupData, setMfaSetupData] = useState<{ secret: string; recoveryCodes: string[] } | null>(null);
  const [mfaEnableCode, setMfaEnableCode] = useState('');
  const [gpsRetentionDays, setGpsRetentionDays] = useState(30);
  const [audioRetentionDays, setAudioRetentionDays] = useState(14);
  const [gdprPassword, setGdprPassword] = useState('');

  const refreshAll = useCallback(async () => {
    if (!api.getAccessToken()) return;
    try {
      const [meRes, devList, sessList, recList, gfList, sosList, logList, secSum, chList, retPol] = await Promise.all([
        api.request<{ user: User }>('/api/auth/me'),
        api.getDevices(),
        api.getAudioSessions(),
        api.getAudioRecordings(),
        api.getGeofences(),
        api.getSosAlerts(),
        api.getSecurityLogs(),
        api.getAdminSecuritySummary().catch(() => null),
        api.getAlertChannels().catch(() => []),
        api.getRetentionPolicy().catch(() => ({ gpsRetentionDays: 30, audioRetentionDays: 14, autoPurgeEnabled: true }))
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
      setAdminSummary(secSum);
      setAlertChannels(chList);
      setGpsRetentionDays(retPol.gpsRetentionDays);
      setAudioRetentionDays(retPol.audioRetentionDays);
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
        event.type === 'GEOFENCE_ENTER' ||
        event.type === 'GEOFENCE_EXIT' ||
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
        const res = await api.login(email, password, totpCode || undefined);
        if (res.mfaRequired) {
          setMfaPromptRequired(true);
          return;
        }
        if (res.user) setUser(res.user);
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
      radiusMeters: Number(gfRadius),
      notifyOnEnter: true,
      notifyOnExit: true
    });
    setGfName('');
    await refreshAll();
  };

  if (!user) {
    return (
      <div className="auth-wrapper">
        <div className="auth-card">
          <div className="brand-header">
            <span className="brand-badge">LIVETRACK-PRO v3.0</span>
            <h1>LiveTrack-Pro Unified Platform</h1>
            <p className="muted">
              Hardened Real-Time Fused GPS Telemetry &amp; Explicit Consent-Based Audio Streaming
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
              <label>Password (min 12 chars, upper, lower, digit &amp; symbol)</label>
              <input
                type="password"
                className="input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
              />
            </div>
            {mfaPromptRequired && (
              <div>
                <label>6-Digit Authenticator TOTP Code</label>
                <input
                  className="input"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="123456"
                  required
                />
              </div>
            )}
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
          <span className="brand-pill">LIVETRACK-PRO v3.0</span>
          <h2>LiveTrack-Pro</h2>
          <p className="muted-xs">GPS + Consent Audio</p>
        </div>

        <nav className="nav-menu">
          <button className={activeTab === 'overview' ? 'active' : ''} onClick={() => setActiveTab('overview')}>
            📊 Overview
          </button>
          <button className={activeTab === 'map' ? 'active' : ''} onClick={() => setActiveTab('map')}>
            🗺️ Live GPS &amp; Replay
          </button>
          <button className={activeTab === 'devices' ? 'active' : ''} onClick={() => setActiveTab('devices')}>
            📱 Devices &amp; Tokens
          </button>
          <button className={activeTab === 'audio-sessions' ? 'active' : ''} onClick={() => setActiveTab('audio-sessions')}>
            🎙️ Audio Sessions
          </button>
          <button className={activeTab === 'recordings' ? 'active' : ''} onClick={() => setActiveTab('recordings')}>
            🔐 Encrypted Vault
          </button>
          <button className={activeTab === 'history' ? 'active' : ''} onClick={() => setActiveTab('history')}>
            🧭 History &amp; Geofences
          </button>
          <button className={activeTab === 'web-endpoint' ? 'active' : ''} onClick={() => setActiveTab('web-endpoint')}>
            🌐 Web / iOS Endpoint
          </button>
          <button className={activeTab === 'settings' ? 'active' : ''} onClick={() => setActiveTab('settings')}>
            ⚙️ MFA, Retention &amp; GDPR
          </button>
          <button className={activeTab === 'security-logs' ? 'active' : ''} onClick={() => setActiveTab('security-logs')}>
            🛡️ Admin Security &amp; Logs
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="user-chip">
            <strong>{user.fullName}</strong>
            <span className="muted-xs">
              {user.email} ({user.role}) {user.mfaEnabled ? '🔒 MFA' : ''}
            </span>
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
              <strong>🚨 ACTIVE EMERGENCY SOS BEACON ({activeSos.length}):</strong> {activeSos[0].message} at (
              {activeSos[0].latitude.toFixed(4)}, {activeSos[0].longitude.toFixed(4)}) — Battery{' '}
              {activeSos[0].batteryLevel}%
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
                <span className="kpi-sub">Scoped Tokens + Adaptive GPS</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Active GPS Trackers</span>
                <strong className="kpi-value">{devices.filter((d) => d.trackingActive).length}</strong>
                <span className="kpi-sub">Fused Location + Clustering</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Live Consent Audio</span>
                <strong className="kpi-value">{audioSessions.filter((s) => s.status === 'active').length}</strong>
                <span className="kpi-sub">User-Initiated Only</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Encrypted Recordings</span>
                <strong className="kpi-value">{recordings.length}</strong>
                <span className="kpi-sub">AES-256-GCM (0600 Mode)</span>
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
              <h3>Pair a New Cross-Platform Device (Single-Use 10-Min Pairing Code)</h3>
              <form onSubmit={handleRegisterDevice} className="form-inline">
                <input
                  className="input"
                  placeholder="Device Name (e.g., Pixel 9 Pro, Termux Node, iPhone 16)"
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
                  Generate Expiring Code
                </button>
              </form>
              {generatedPairingCode && (
                <div className="pairing-box" style={{ marginTop: '0.75rem' }}>
                  <strong>Single-Use Pairing Code (10-min TTL):</strong> <code>{generatedPairingCode}</code>
                </div>
              )}
              {rotatedDeviceToken && (
                <div className="pairing-box" style={{ marginTop: '0.75rem' }}>
                  <strong>Rotated Device-Scoped API Token:</strong>{' '}
                  <code>{rotatedDeviceToken.slice(0, 36)}...</code>
                </div>
              )}
            </div>

            <div className="card">
              <h3>Registered Fleet &amp; Scoped API Token Permissions</h3>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Device Name</th>
                    <th>Platform</th>
                    <th>Paired / Code</th>
                    <th>Scopes</th>
                    <th>Adaptive GPS</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <strong>{d.deviceName}</strong>
                      </td>
                      <td>
                        <span className="platform-pill">{d.platform.toUpperCase()}</span>
                      </td>
                      <td>{d.isPaired ? '✅ Paired' : `⏳ ${d.pairingCode || 'Expired'}`}</td>
                      <td>
                        <code>{(d.tokenScopes || []).join(', ')}</code>
                      </td>
                      <td>{d.adaptiveIntervalSeconds ?? 10}s</td>
                      <td className="row-actions">
                        <button className="btn btn-sm btn-primary" onClick={() => handleToggleTracking(d)}>
                          {d.trackingActive ? 'Stop GPS' : 'Start GPS'}
                        </button>
                        <button
                          className="btn btn-sm btn-outline"
                          onClick={async () => {
                            const res = await api.rotateDeviceToken(d.id);
                            setRotatedDeviceToken(res.deviceAccessToken);
                            refreshAll();
                          }}
                        >
                          Rotate Token
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
                      GPX
                    </a>
                    <a
                      className="btn btn-sm btn-outline"
                      href={`/api/gps/export/${selectedDeviceId}?format=kml`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      KML
                    </a>
                    <a
                      className="btn btn-sm btn-outline"
                      href={`/api/gps/export/${selectedDeviceId}?format=csv`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      CSV
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
                      <th>Speed / Alt</th>
                      <th>Battery</th>
                    </tr>
                  </thead>
                  <tbody>
                    {gpsHistory.map((pt) => (
                      <tr key={pt.id}>
                        <td>{new Date(pt.recordedAt).toLocaleTimeString()}</td>
                        <td>
                          {pt.latitude.toFixed(5)}, {pt.longitude.toFixed(5)}
                        </td>
                        <td>
                          {pt.speed} m/s ({pt.altitude}m)
                        </td>
                        <td>{pt.batteryLevel}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <h3>Smart Geofence Zones (Enter + Exit Alerts)</h3>
              <form onSubmit={handleCreateGeofence} className="stack-sm">
                <input
                  className="input"
                  placeholder="Zone Name (e.g., Campus Perimeter)"
                  value={gfName}
                  onChange={(e) => setGfName(e.target.value)}
                  required
                />
                <div className="form-inline">
                  <input
                    className="input"
                    placeholder="Latitude"
                    value={gfLat}
                    onChange={(e) => setGfLat(e.target.value)}
                    required
                  />
                  <input
                    className="input"
                    placeholder="Longitude"
                    value={gfLon}
                    onChange={(e) => setGfLon(e.target.value)}
                    required
                  />
                  <input
                    className="input"
                    placeholder="Radius (m)"
                    value={gfRadius}
                    onChange={(e) => setGfRadius(e.target.value)}
                    required
                  />
                </div>
                <button type="submit" className="btn btn-primary">
                  Add Geofence (Enter &amp; Exit)
                </button>
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
                      <td>
                        {g.latitude.toFixed(4)}, {g.longitude.toFixed(4)}
                      </td>
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

        {activeTab === 'web-endpoint' && <WebDeviceClient devices={devices} onRefresh={refreshAll} />}

        {activeTab === 'settings' && (
          <div className="stack-lg">
            <div className="panel-grid-2">
              <div className="card">
                <h3>TOTP Multi-Factor Authentication (MFA)</h3>
                <p className="muted">
                  Status: <strong>{user.mfaEnabled ? '✅ Enabled (RFC-6238 TOTP)' : '⚪ Disabled'}</strong>
                </p>
                {!user.mfaEnabled && (
                  <div className="stack-md" style={{ marginTop: '0.75rem' }}>
                    <button
                      className="btn btn-primary"
                      onClick={async () => {
                        const data = await api.setupMfa();
                        setMfaSetupData({ secret: data.secret, recoveryCodes: data.recoveryCodes });
                      }}
                    >
                      Generate TOTP Secret &amp; Recovery Codes
                    </button>
                    {mfaSetupData && (
                      <div className="stack-md">
                        <div>
                          <strong>Base32 Secret:</strong> <code>{mfaSetupData.secret}</code>
                        </div>
                        <div>
                          <strong>Recovery Codes:</strong> <code>{mfaSetupData.recoveryCodes.join(', ')}</code>
                        </div>
                        <div className="form-inline">
                          <input
                            className="input"
                            placeholder="Enter 6-digit code to activate"
                            value={mfaEnableCode}
                            onChange={(e) => setMfaEnableCode(e.target.value)}
                          />
                          <button
                            className="btn btn-primary"
                            onClick={async () => {
                              await api.enableMfa(mfaEnableCode);
                              setMfaSetupData(null);
                              refreshAll();
                            }}
                          >
                            Verify &amp; Enable
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="card">
                <h3>Configurable Data Retention Policy</h3>
                <div className="stack-md">
                  <div>
                    <label>GPS History Retention (Days)</label>
                    <input
                      type="number"
                      className="input"
                      value={gpsRetentionDays}
                      onChange={(e) => setGpsRetentionDays(Number(e.target.value))}
                    />
                  </div>
                  <div>
                    <label>Encrypted Audio Retention (Days)</label>
                    <input
                      type="number"
                      className="input"
                      value={audioRetentionDays}
                      onChange={(e) => setAudioRetentionDays(Number(e.target.value))}
                    />
                  </div>
                  <div className="row-actions">
                    <button
                      className="btn btn-primary"
                      onClick={async () => {
                        await api.updateRetentionPolicy({
                          gpsRetentionDays,
                          audioRetentionDays,
                          autoPurgeEnabled: true
                        });
                        refreshAll();
                      }}
                    >
                      Save Retention Policy
                    </button>
                    <button
                      className="btn btn-outline"
                      onClick={async () => {
                        await api.purgeExpiredData();
                        refreshAll();
                      }}
                    >
                      Run Purge Now
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="card">
              <h3>GDPR Right to Erasure — Delete My Account &amp; All Data</h3>
              <p className="muted">
                Permanently deletes your account, wipes all AES-256-GCM encrypted audio recordings from storage, and cascades deletion of all devices, GPS tracks, and shares.
              </p>
              <div className="form-inline">
                <input
                  type="password"
                  className="input"
                  placeholder="Confirm your current password"
                  value={gdprPassword}
                  onChange={(e) => setGdprPassword(e.target.value)}
                />
                <button
                  className="btn btn-danger"
                  onClick={async () => {
                    if (!gdprPassword) return;
                    await api.deleteAccountAndData(gdprPassword);
                    setUser(null);
                  }}
                >
                  Permanently Delete Account &amp; Data
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'security-logs' && (
          <div className="stack-lg">
            {adminSummary && (
              <div className="kpi-grid">
                <div className="kpi-card">
                  <span className="kpi-label">Rate Limiter Engine</span>
                  <strong className="kpi-value" style={{ fontSize: '1.15rem' }}>
                    {adminSummary.rateLimitStatistics.backend}
                  </strong>
                  <span className="kpi-sub">
                    Allowed: {adminSummary.rateLimitStatistics.totalAllowed} | Blocked:{' '}
                    {adminSummary.rateLimitStatistics.totalBlocked}
                  </span>
                </div>
                <div className="kpi-card">
                  <span className="kpi-label">Critical / High Alerts</span>
                  <strong className="kpi-value">
                    {adminSummary.severityBreakdown.critical + adminSummary.severityBreakdown.high}
                  </strong>
                  <span className="kpi-sub">Covert Mic / IDOR / SOS / Lockouts</span>
                </div>
                <div className="kpi-card">
                  <span className="kpi-label">Warning Events</span>
                  <strong className="kpi-value">{adminSummary.severityBreakdown.warn}</strong>
                  <span className="kpi-sub">Geofence Exits &amp; Failed Logins</span>
                </div>
                <div className="kpi-card">
                  <span className="kpi-label">Active Alert Channels</span>
                  <strong className="kpi-value">{alertChannels.length}</strong>
                  <span className="kpi-sub">Webhook • Telegram • Email • Push</span>
                </div>
              </div>
            )}

            <div className="card">
              <h3>Immutable Security &amp; Anti-Covert Audit Logs ({securityLogs.length})</h3>
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
                          <span
                            className={`badge badge-${
                              log.severity === 'critical' || log.severity === 'high'
                                ? 'danger'
                                : log.severity === 'warn'
                                ? 'warning'
                                : 'info'
                            }`}
                          >
                            {log.severity.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <code>{log.eventType}</code>
                        </td>
                        <td>{log.ipAddress}</td>
                        <td>
                          <code>{JSON.stringify(log.details)}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
