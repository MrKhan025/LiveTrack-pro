import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import type { Device, GpsLocation, Geofence } from '../types/platform';

interface LiveGpsMapProps {
  devices: Device[];
  selectedDeviceId: string | null;
  history: GpsLocation[];
  geofences: Geofence[];
  onSelectDevice: (id: string) => void;
  onToggleTracking: (device: Device) => void;
}

export const LiveGpsMap: React.FC<LiveGpsMapProps> = ({
  devices,
  selectedDeviceId,
  history,
  geofences,
  onSelectDevice,
  onToggleTracking
}) => {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const layerGroupRef = useRef<L.LayerGroup | null>(null);
  const chartCanvasRef = useRef<HTMLCanvasElement | null>(null);

  const [clusteringEnabled, setClusteringEnabled] = useState(true);
  const [replayIndex, setReplayIndex] = useState<number>(0);
  const [isReplaying, setIsReplaying] = useState(false);

  const chronologicalHistory = [...history].reverse();

  useEffect(() => {
    if (!mapContainerRef.current || mapInstanceRef.current) return;
    const map = L.map(mapContainerRef.current).setView([17.385, 78.4867], 13);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap contributors | LiveTrack-Pro'
    }).addTo(map);
    const group = L.layerGroup().addTo(map);
    mapInstanceRef.current = map;
    layerGroupRef.current = group;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!isReplaying || chronologicalHistory.length === 0) return;
    const timer = window.setInterval(() => {
      setReplayIndex((prev) => {
        if (prev + 1 >= chronologicalHistory.length) {
          setIsReplaying(false);
          return 0;
        }
        return prev + 1;
      });
    }, 600);
    return () => window.clearInterval(timer);
  }, [isReplaying, chronologicalHistory.length]);

  useEffect(() => {
    const map = mapInstanceRef.current;
    const group = layerGroupRef.current;
    if (!map || !group) return;

    group.clearLayers();

    geofences.forEach((gf) => {
      L.circle([gf.latitude, gf.longitude], {
        radius: gf.radiusMeters,
        color: '#38bdf8',
        fillColor: '#0284c7',
        fillOpacity: 0.15
      })
        .bindPopup(
          `<strong>Geofence: ${gf.name}</strong><br/>Radius: ${gf.radiusMeters}m<br/>Alerts: ${
            gf.notifyOnEnter ? 'Enter ' : ''
          }${gf.notifyOnExit ? 'Exit' : ''}`
        )
        .addTo(group);
    });

    // Multi-Device Grid Clustering when clusteringEnabled is true
    const locatedDevices = devices.filter((d) => d.lastLatitude != null && d.lastLongitude != null);
    if (clusteringEnabled && locatedDevices.length > 1) {
      const clusters: Record<string, Device[]> = {};
      locatedDevices.forEach((dev) => {
        const key = `${(dev.lastLatitude || 0).toFixed(2)}_${(dev.lastLongitude || 0).toFixed(2)}`;
        clusters[key] = clusters[key] || [];
        clusters[key].push(dev);
      });

      Object.values(clusters).forEach((bucket) => {
        if (bucket.length === 1) {
          const dev = bucket[0];
          L.circleMarker([dev.lastLatitude!, dev.lastLongitude!], {
            radius: dev.id === selectedDeviceId ? 11 : 8,
            color: dev.micConsentActive ? '#ef4444' : dev.trackingActive ? '#22c55e' : '#94a3b8',
            fillColor: dev.micConsentActive ? '#ef4444' : dev.trackingActive ? '#10b981' : '#64748b',
            fillOpacity: 0.9,
            weight: 3
          })
            .bindPopup(`<strong>${dev.deviceName}</strong> (${dev.platform.toUpperCase()})<br/>Battery: ${dev.batteryLevel}%`)
            .on('click', () => onSelectDevice(dev.id))
            .addTo(group);
        } else {
          const avgLat = bucket.reduce((s, d) => s + (d.lastLatitude || 0), 0) / bucket.length;
          const avgLon = bucket.reduce((s, d) => s + (d.lastLongitude || 0), 0) / bucket.length;
          L.circleMarker([avgLat, avgLon], {
            radius: 16,
            color: '#38bdf8',
            fillColor: '#0284c7',
            fillOpacity: 0.85,
            weight: 3
          })
            .bindPopup(
              `<strong>Device Cluster (${bucket.length} units)</strong><br/>` +
                bucket.map((d) => `• ${d.deviceName} (${d.batteryLevel}%)`).join('<br/>')
            )
            .addTo(group);
        }
      });
    } else {
      locatedDevices.forEach((dev) => {
        L.circleMarker([dev.lastLatitude!, dev.lastLongitude!], {
          radius: dev.id === selectedDeviceId ? 11 : 8,
          color: dev.micConsentActive ? '#ef4444' : dev.trackingActive ? '#22c55e' : '#94a3b8',
          fillColor: dev.micConsentActive ? '#ef4444' : dev.trackingActive ? '#10b981' : '#64748b',
          fillOpacity: 0.9,
          weight: 3
        })
          .bindPopup(`<strong>${dev.deviceName}</strong><br/>Battery: ${dev.batteryLevel}%`)
          .on('click', () => onSelectDevice(dev.id))
          .addTo(group);
      });
    }

    // Historical Route Polyline & Replay Cursor
    if (chronologicalHistory.length > 1) {
      const coords = chronologicalHistory.map((pt) => [pt.latitude, pt.longitude] as [number, number]);
      L.polyline(coords, { color: '#38bdf8', weight: 4, opacity: 0.85 }).addTo(group);
      const safeIdx = Math.min(replayIndex, chronologicalHistory.length - 1);
      const replayPt = chronologicalHistory[safeIdx];
      if (replayPt) {
        L.circleMarker([replayPt.latitude, replayPt.longitude], {
          radius: 9,
          color: '#f59e0b',
          fillColor: '#fbbf24',
          fillOpacity: 1,
          weight: 3
        })
          .bindPopup(
            `<strong>Route Replay Point #${safeIdx + 1}</strong><br/>Speed: ${replayPt.speed} m/s | Alt: ${replayPt.altitude}m`
          )
          .addTo(group);
      }
    }
  }, [devices, selectedDeviceId, chronologicalHistory, geofences, clusteringEnabled, replayIndex, onSelectDevice]);

  // Speed (m/s) & Altitude (m) Dual Telemetry Canvas Chart
  useEffect(() => {
    const canvas = chartCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    if (chronologicalHistory.length < 2) {
      ctx.fillStyle = '#94a3b8';
      ctx.font = '12px sans-serif';
      ctx.fillText('Send 2+ GPS points to render live Speed (m/s) & Altitude (m) profile chart.', 16, h / 2);
      return;
    }

    const maxSpeed = Math.max(10, ...chronologicalHistory.map((p) => p.speed || 0));
    const maxAlt = Math.max(100, ...chronologicalHistory.map((p) => p.altitude || 0));

    // Speed Line (Sky Blue)
    ctx.strokeStyle = '#38bdf8';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    chronologicalHistory.forEach((pt, idx) => {
      const x = (idx / (chronologicalHistory.length - 1)) * (w - 24) + 12;
      const y = h - 16 - ((pt.speed || 0) / maxSpeed) * (h - 32);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Altitude Line (Emerald)
    ctx.strokeStyle = '#10b981';
    ctx.lineWidth = 2;
    ctx.beginPath();
    chronologicalHistory.forEach((pt, idx) => {
      const x = (idx / (chronologicalHistory.length - 1)) * (w - 24) + 12;
      const y = h - 16 - ((pt.altitude || 0) / maxAlt) * (h - 32);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }, [chronologicalHistory]);

  return (
    <div className="stack-lg">
      <div className="panel-grid">
        <div className="card map-card">
          <div className="card-header">
            <div>
              <h2>Live OpenStreetMap Telemetry &amp; Clustering</h2>
              <p className="muted">Real-time Fused GPS coordinates, marker clustering, and geofence enter/exit perimeters</p>
            </div>
            <div className="row-actions">
              <label style={{ fontSize: '0.8rem' }}>
                <input
                  type="checkbox"
                  checked={clusteringEnabled}
                  onChange={(e) => setClusteringEnabled(e.target.checked)}
                />{' '}
                Cluster Markers
              </label>
            </div>
          </div>
          <div ref={mapContainerRef} className="leaflet-map-box" />

          {/* Historical Route Replay Bar */}
          {chronologicalHistory.length > 1 && (
            <div className="row-actions" style={{ marginTop: '0.75rem' }}>
              <button className="btn btn-sm btn-primary" onClick={() => setIsReplaying(!isReplaying)}>
                {isReplaying ? '⏸ Pause Replay' : '▶ Replay Route'}
              </button>
              <input
                type="range"
                min={0}
                max={chronologicalHistory.length - 1}
                value={replayIndex}
                onChange={(e) => setReplayIndex(Number(e.target.value))}
                style={{ flex: 1 }}
              />
              <span style={{ fontSize: '0.78rem' }}>
                Point {replayIndex + 1} / {chronologicalHistory.length}
              </span>
            </div>
          )}
        </div>

        <div className="card device-sidebar-card">
          <h3>Registered Endpoints ({devices.length})</h3>
          <div className="device-list">
            {devices.map((d) => (
              <div
                key={d.id}
                className={`device-item ${d.id === selectedDeviceId ? 'selected' : ''}`}
                onClick={() => onSelectDevice(d.id)}
              >
                <div className="device-item-top">
                  <strong>{d.deviceName}</strong>
                  <span className="platform-pill">{d.platform.toUpperCase()}</span>
                </div>
                <div className="device-meta">
                  <span>🔋 {d.batteryLevel}%</span>
                  <span>⏱ Adaptive: {d.adaptiveIntervalSeconds ?? 10}s</span>
                </div>
                {d.micConsentActive && (
                  <div className="mic-indicator-banner">
                    🔴 VISIBLE MIC INDICATOR: User-Initiated Audio Active
                  </div>
                )}
                <div className="device-actions">
                  <button
                    className={`btn btn-sm ${d.trackingActive ? 'btn-danger' : 'btn-primary'}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleTracking(d);
                    }}
                  >
                    {d.trackingActive ? 'Stop GPS' : 'Start GPS'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Historical Speed (Sky Blue) &amp; Altitude (Emerald) Telemetry Profile</h3>
        <canvas ref={chartCanvasRef} width={820} height={110} className="waveform-canvas" />
      </div>
    </div>
  );
};
