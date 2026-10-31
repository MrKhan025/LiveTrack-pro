export type PlatformType = 'android' | 'termux' | 'ios' | 'windows' | 'linux' | 'macos' | 'web';

export interface User {
  id: string;
  email: string;
  fullName: string;
  role: 'admin' | 'owner' | 'viewer' | 'auditor';
  createdAt: string;
}

export interface Device {
  id: string;
  ownerId: string;
  deviceName: string;
  platform: PlatformType;
  hardwareFingerprint: string;
  pairingCode?: string | null;
  isPaired: boolean;
  trackingActive: boolean;
  micConsentActive: boolean;
  batteryLevel: number;
  isCharging: boolean;
  lastLatitude: number | null;
  lastLongitude: number | null;
  lastAccuracy: number | null;
  lastSpeed: number | null;
  lastSeenAt: string | null;
}

export interface GpsLocation {
  id: string;
  deviceId: string;
  latitude: number;
  longitude: number;
  altitude: number;
  accuracy: number;
  speed: number;
  heading: number;
  batteryLevel: number;
  provider: string;
  recordedAt: string;
}

export interface AudioSession {
  id: string;
  deviceId: string;
  ownerId: string;
  initiatedByDevice: boolean;
  consentStatement: string;
  status: 'active' | 'stopped' | 'expired';
  sampleRate: number;
  channels: number;
  mimeType: string;
  startedAt: string;
  endedAt: string | null;
}

export interface AudioRecording {
  id: string;
  sessionId: string;
  deviceId: string;
  ownerId: string;
  title: string;
  mimeType: string;
  durationSeconds: number;
  sizeBytes: number;
  sha256Checksum: string;
  waveformPeaks: number[];
  createdAt: string;
}

export interface Geofence {
  id: string;
  ownerId: string;
  deviceId: string | null;
  name: string;
  latitude: number;
  longitude: number;
  radiusMeters: number;
  notifyOnEnter: boolean;
  notifyOnExit: boolean;
  active: boolean;
}

export interface SosAlert {
  id: string;
  deviceId: string;
  ownerId: string;
  latitude: number;
  longitude: number;
  batteryLevel: number;
  message: string;
  status: 'active' | 'resolved';
  triggeredAt: string;
  resolvedAt: string | null;
}

export interface SecurityLog {
  id: string;
  userId: string | null;
  deviceId: string | null;
  eventType: string;
  severity: 'info' | 'warn' | 'high' | 'critical';
  ipAddress: string;
  userAgent: string;
  details: Record<string, unknown>;
  createdAt: string;
}
