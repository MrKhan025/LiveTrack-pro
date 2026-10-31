import React, { useEffect, useRef } from 'react';
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
    const map = mapInstanceRef.current;
    const group = layerGroupRef.current;
    if (!map || !group) return;

    group.clearLayers();

    // Draw Geofences
    geofences.forEach((gf) => {
      L.circle([gf.latitude, gf.longitude], {
        radius: gf.radiusMeters,
        color: '#38bdf8',
        fillColor: '#0284c7',
        fillOpacity: 0.15
      })
        .bindPopup(`<strong>Geofence: ${gf.name}</strong><br/>Radius: ${gf.radiusMeters}m`)
        .addTo(group);
    });

    // Draw Device Markers
    devices.forEach((dev) => {
      if (dev.lastLatitude != null && dev.lastLongitude != null) {
        const marker = L.circleMarker([dev.lastLatitude, dev.lastLongitude], {
          radius: dev.id === selectedDeviceId ? 11 : 8,
          color: dev.micConsentActive ? '#ef4444' : dev.trackingActive ? '#22c55e' : '#94a3b8',
          fillColor: dev.micConsentActive ? '#ef4444' : dev.trackingActive ? '#10b981' : '#64748b',
          fillOpacity: 0.9,
          weight: 3
        });
        marker
          .bindPopup(
            `<div>
              <strong>${dev.deviceName}</strong> (${dev.platform.toUpperCase()})<br/>
              Battery: ${dev.batteryLevel}% ${dev.isCharging ? '⚡' : ''}<br/>
              Speed: ${dev.lastSpeed ?? 0} m/s | Accuracy: ±${dev.lastAccuracy ?? 5}m<br/>
              Mic Consent: ${dev.micConsentActive ? '🔴 LIVE CONSENT ACTIVE' : 'Off'}<br/>
              Last Seen: ${dev.lastSeenAt ? new Date(dev.lastSeenAt).toLocaleTimeString() : 'N/A'}
            </div>`
          )
          .on('click', () => onSelectDevice(dev.id))
          .addTo(group);
      }
    });

    // Draw Selected Device Polyline History
    if (history.length > 1) {
      const coords = history.map((pt) => [pt.latitude, pt.longitude] as [number, number]);
      L.polyline(coords, { color: '#38bdf8', weight: 4, opacity: 0.85 }).addTo(group);
      map.fitBounds(coords, { padding: [32, 32], maxZoom: 16 });
    } else {
      const activeDev = devices.find((d) => d.id === selectedDeviceId && d.lastLatitude != null);
      if (activeDev && activeDev.lastLatitude != null && activeDev.lastLongitude != null) {
        map.setView([activeDev.lastLatitude, activeDev.lastLongitude], 15);
      }
    }
  }, [devices, selectedDeviceId, history, geofences, onSelectDevice]);

  return (
    <div className="panel-grid">
      <div className="card map-card">
        <div className="card-header">
          <div>
            <h2>Live OpenStreetMap Telemetry</h2>
            <p className="muted">Real-time Fused GPS coordinates, route trails, and geofence perimeters</p>
          </div>
          <div className="legend-row">
            <span className="badge badge-success">● Tracking Active</span>
            <span className="badge badge-danger">● Consent Mic Live</span>
            <span className="badge badge-info">◯ Geofence Zone</span>
          </div>
        </div>
        <div ref={mapContainerRef} className="leaflet-map-box" />
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
                <span>
                  {d.lastLatitude != null
                    ? `${d.lastLatitude.toFixed(4)}, ${d.lastLongitude?.toFixed(4)}`
                    : 'No GPS Fix'}
                </span>
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
                  {d.trackingActive ? 'Stop GPS Tracking' : 'Start GPS Tracking'}
                </button>
                {d.lastLatitude != null && (
                  <a
                    className="btn btn-sm btn-outline"
                    href={`/api/gps/export/${d.id}?format=gpx`}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(e) => e.stopPropagation()}
                  >
                    Export GPX
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
