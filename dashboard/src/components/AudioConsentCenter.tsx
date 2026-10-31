import React, { useEffect, useRef, useState } from 'react';
import type { AudioSession, AudioRecording, Device } from '../types/platform';
import { api } from '../services/api';

interface AudioConsentCenterProps {
  devices: Device[];
  sessions: AudioSession[];
  recordings: AudioRecording[];
  liveWaveform: number[];
  onRefresh: () => void;
}

export const AudioConsentCenter: React.FC<AudioConsentCenterProps> = ({
  devices,
  sessions,
  recordings,
  liveWaveform,
  onRefresh
}) => {
  const [playingId, setPlayingId] = useState<string | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [selectedPeaks, setSelectedPeaks] = useState<number[]>([]);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const peaks = liveWaveform.length > 0 ? liveWaveform : selectedPeaks.length > 0 ? selectedPeaks : Array(64).fill(0.12);
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    const barWidth = Math.max(3, Math.floor(width / peaks.length) - 2);
    peaks.forEach((peak, idx) => {
      const barHeight = Math.max(6, peak * (height - 16));
      const x = idx * (barWidth + 2);
      const y = (height - barHeight) / 2;
      ctx.fillStyle = liveWaveform.length > 0 ? '#ef4444' : '#38bdf8';
      ctx.beginPath();
      if (typeof ctx.roundRect === 'function') { ctx.roundRect(x, y, barWidth, barHeight, 3); } else { ctx.rect(x, y, barWidth, barHeight); }
      ctx.fill();
    });
  }, [liveWaveform, selectedPeaks]);

  const handlePlay = async (rec: AudioRecording) => {
    try {
      if (audioUrl) URL.revokeObjectURL(audioUrl);
      const url = await api.fetchDecryptedAudioBlobUrl(rec.id);
      setPlayingId(rec.id);
      setSelectedPeaks(rec.waveformPeaks || []);
      setAudioUrl(url);
    } catch (err: any) {
      alert(err.message || 'Playback failed');
    }
  };

  const handleDelete = async (id: string) => {
    await api.deleteAudioRecording(id);
    if (playingId === id) {
      setPlayingId(null);
      setAudioUrl(null);
    }
    onRefresh();
  };

  const activeSessions = sessions.filter((s) => s.status === 'active');

  return (
    <div className="stack-lg">
      <div className="consent-policy-banner">
        <div>
          <strong>🔒 Zero-Covert Microphone Guarantee:</strong> Remote or silent microphone activation is disabled at the protocol and cryptographic level. Every audio stream or recording requires explicit on-device user action, a signed consent statement, and a persistent OS notification.
        </div>
      </div>

      {activeSessions.length > 0 && (
        <div className="live-mic-alert">
          <span className="pulse-dot" />
          <strong>VISIBLE MICROPHONE INDICATOR:</strong> {activeSessions.length} Device-Consented Audio Session(s) Currently Active
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Real-Time & Playback Waveform Visualizer</h3>
            <p className="muted">64-band RMS amplitude envelope (AES-256-GCM decrypted on-the-fly)</p>
          </div>
          {playingId && <span className="badge badge-info">Playing Recording #{playingId.slice(0, 8)}</span>}
        </div>
        <canvas ref={canvasRef} width={760} height={120} className="waveform-canvas" />
        {audioUrl && (
          <div className="audio-player-bar">
            <audio controls autoPlay src={audioUrl} className="full-audio-element" />
          </div>
        )}
      </div>

      <div className="panel-grid-2">
        <div className="card">
          <h3>Consent-Based Audio Sessions ({sessions.length})</h3>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Status</th>
                  <th>Explicit Consent Statement</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => {
                  const dev = devices.find((d) => d.id === s.deviceId);
                  return (
                    <tr key={s.id}>
                      <td>{dev?.deviceName || s.deviceId.slice(0, 8)}</td>
                      <td>
                        <span className={`badge ${s.status === 'active' ? 'badge-danger' : 'badge-neutral'}`}>
                          {s.status === 'active' ? '🔴 LIVE MIC' : 'Stopped'}
                        </span>
                      </td>
                      <td>{s.consentStatement}</td>
                      <td>{new Date(s.startedAt).toLocaleString()}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <h3>Authorized Encrypted Recordings ({recordings.length})</h3>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Duration / Size</th>
                  <th>SHA-256 Integrity</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {recordings.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <strong>{r.title}</strong>
                      <div className="muted-xs">{new Date(r.createdAt).toLocaleString()}</div>
                    </td>
                    <td>
                      {r.durationSeconds}s ({(r.sizeBytes / 1024).toFixed(1)} KB)
                    </td>
                    <td>
                      <code>{r.sha256Checksum.slice(0, 12)}…</code>
                    </td>
                    <td className="row-actions">
                      <button className="btn btn-sm btn-primary" onClick={() => handlePlay(r)}>
                        ▶ Play
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={() => handleDelete(r.id)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
