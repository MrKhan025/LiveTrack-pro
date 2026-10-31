import React, { useState, useRef } from 'react';
import type { Device } from '../types/platform';
import { api } from '../services/api';

interface WebDeviceClientProps {
  devices: Device[];
  onRefresh: () => void;
}

export const WebDeviceClient: React.FC<WebDeviceClientProps> = ({ devices, onRefresh }) => {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [consentChecked, setConsentChecked] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [statusLog, setStatusLog] = useState<string[]>([]);
  const watchIdRef = useRef<number | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const activeSessionRef = useRef<{ sessionId: string; consentToken: string } | null>(null);

  const appendLog = (msg: string) => {
    setStatusLog((prev) => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev.slice(0, 19)]);
  };

  const startBrowserGps = () => {
    if (!selectedDeviceId) return alert('Select a registered device first');
    if (!('geolocation' in navigator)) {
      return alert('Geolocation API is not available in this browser');
    }
    appendLog('Starting W3C Geolocation watchPosition (iOS/Android/Windows/Linux)...');
    watchIdRef.current = navigator.geolocation.watchPosition(
      async (pos) => {
        await api.pushGpsUpdate({
          deviceId: selectedDeviceId,
          latitude: pos.coords.latitude,
          longitude: pos.coords.longitude,
          accuracy: pos.coords.accuracy,
          speed: pos.coords.speed || 0,
          batteryLevel: 95,
          provider: 'w3c-pwa'
        });
        appendLog(`GPS sent: ${pos.coords.latitude.toFixed(5)}, ${pos.coords.longitude.toFixed(5)}`);
        onRefresh();
      },
      (err) => appendLog(`GPS error: ${err.message}`),
      { enableHighAccuracy: true, maximumAge: 5000 }
    );
  };

  const stopBrowserGps = () => {
    if (watchIdRef.current != null) {
      navigator.geolocation.clearWatch(watchIdRef.current);
      watchIdRef.current = null;
      appendLog('Stopped browser GPS emitter.');
    }
  };

  const startExplicitConsentAudio = async () => {
    if (!selectedDeviceId) return alert('Select a device first');
    if (!consentChecked) {
      return alert('You must check the explicit microphone consent box before recording.');
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const { session, consentToken } = await api.startConsentAudioSession(
        selectedDeviceId,
        'User explicitly initiated microphone capture via Cross-Platform Web/PWA Client with visible indicator.'
      );
      activeSessionRef.current = { sessionId: session.id, consentToken };

      const chunks: BlobPart[] = [];
      const recorder = new MediaRecorder(stream);
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunks.push(e.data);
      };
      recorder.onstop = async () => {
        const blob = new Blob(chunks, { type: 'audio/webm' });
        const buf = await blob.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        const base64 = btoa(binary);

        if (activeSessionRef.current) {
          await api.uploadConsentRecording({
            sessionId: activeSessionRef.current.sessionId,
            deviceId: selectedDeviceId,
            consentToken: activeSessionRef.current.consentToken,
            title: `PWA Consent Recording (${new Date().toLocaleTimeString()})`,
            mimeType: 'audio/webm',
            durationSeconds: 5,
            audioBase64: base64
          });
          await api.stopConsentAudioSession(activeSessionRef.current.sessionId);
        }
        stream.getTracks().forEach((t) => t.stop());
        setIsRecording(false);
        appendLog('Encrypted recording uploaded & consent session closed.');
        onRefresh();
      };

      mediaRecorderRef.current = recorder;
      recorder.start();
      setIsRecording(true);
      appendLog('🔴 VISIBLE MIC ACTIVE: Recording user-initiated audio...');
    } catch (err: any) {
      appendLog(`Audio error: ${err.message}`);
    }
  };

  const stopExplicitConsentAudio = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
  };

  return (
    <div className="card">
      <h3>Cross-Platform Web / iOS / Windows / Linux Sensor Emitter</h3>
      <p className="muted">
        Use this built-in PWA transmitter on iOS (Safari), Windows, macOS, Linux, or Android browsers to stream live GPS and explicit user-consented microphone audio.
      </p>

      {isRecording && (
        <div className="live-mic-alert">
          <span className="pulse-dot" />
          <strong>PERSISTENT RECORDING INDICATOR:</strong> Microphone is actively capturing audio with your explicit consent.
        </div>
      )}

      <div className="form-row">
        <label>Target Registered Device:</label>
        <select value={selectedDeviceId} onChange={(e) => setSelectedDeviceId(e.target.value)} className="input">
          <option value="">-- Select Device --</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.deviceName} ({d.platform.toUpperCase()})
            </option>
          ))}
        </select>
      </div>

      <div className="consent-checkbox-box">
        <label>
          <input
            type="checkbox"
            checked={consentChecked}
            onChange={(e) => setConsentChecked(e.target.checked)}
          />{' '}
          I explicitly consent to initiate microphone recording on this device and display a persistent recording banner.
        </label>
      </div>

      <div className="row-actions">
        <button className="btn btn-primary" onClick={startBrowserGps}>
          Start Live Browser GPS
        </button>
        <button className="btn btn-outline" onClick={stopBrowserGps}>
          Stop Browser GPS
        </button>
        {!isRecording ? (
          <button className="btn btn-danger" onClick={startExplicitConsentAudio} disabled={!consentChecked}>
            🎙 Start Consent Mic Recording
          </button>
        ) : (
          <button className="btn btn-warning" onClick={stopExplicitConsentAudio}>
            ⏹ Stop & Encrypt Recording
          </button>
        )}
      </div>

      <div className="terminal-log">
        {statusLog.map((line, i) => (
          <div key={i}>{line}</div>
        ))}
      </div>
    </div>
  );
};
