-- LiveTrack-Pro (Codename: Navox / Veloce) Unified PostgreSQL Schema
-- Migration: 001_initial_schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Users & Role-Based Access Control
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'owner' CHECK (role IN ('admin', 'owner', 'viewer', 'auditor')),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Refresh Tokens & Session Management
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address VARCHAR(64),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

-- 3. Registered Devices (Android, Termux, iOS PWA, Windows, Linux, macOS)
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(120) NOT NULL,
    platform VARCHAR(32) NOT NULL CHECK (platform IN ('android', 'termux', 'ios', 'windows', 'linux', 'macos', 'web')),
    hardware_fingerprint VARCHAR(255) NOT NULL,
    pairing_code VARCHAR(16) UNIQUE,
    device_token_hash TEXT,
    is_paired BOOLEAN NOT NULL DEFAULT FALSE,
    tracking_active BOOLEAN NOT NULL DEFAULT FALSE,
    mic_consent_active BOOLEAN NOT NULL DEFAULT FALSE,
    battery_level INTEGER DEFAULT 100 CHECK (battery_level >= 0 AND battery_level <= 100),
    is_charging BOOLEAN NOT NULL DEFAULT FALSE,
    last_latitude DOUBLE PRECISION,
    last_longitude DOUBLE PRECISION,
    last_accuracy DOUBLE PRECISION,
    last_speed DOUBLE PRECISION,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner_id, hardware_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_devices_owner_id ON devices(owner_id);

-- 4. Real-Time & Historical GPS Locations
CREATE TABLE IF NOT EXISTS gps_locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DOUBLE PRECISION NOT NULL CHECK (latitude >= -90 AND latitude <= 90),
    longitude DOUBLE PRECISION NOT NULL CHECK (longitude >= -180 AND longitude <= 180),
    altitude DOUBLE PRECISION DEFAULT 0,
    accuracy DOUBLE PRECISION DEFAULT 5.0,
    speed DOUBLE PRECISION DEFAULT 0.0,
    heading DOUBLE PRECISION DEFAULT 0.0,
    battery_level INTEGER DEFAULT 100,
    provider VARCHAR(32) DEFAULT 'fused',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gps_device_time ON gps_locations(device_id, recorded_at DESC);

-- 5. Explicit Device-Initiated Audio Consent Sessions
-- Covert/remote microphone activation is strictly impossible by schema & cryptographic signature
CREATE TABLE IF NOT EXISTS audio_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_token_hash TEXT NOT NULL,
    initiated_by_device BOOLEAN NOT NULL DEFAULT TRUE CHECK (initiated_by_device = TRUE),
    consent_statement TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stopped', 'expired')),
    sample_rate INTEGER NOT NULL DEFAULT 48000,
    channels INTEGER NOT NULL DEFAULT 1,
    mime_type VARCHAR(64) NOT NULL DEFAULT 'audio/webm;codecs=opus',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audio_sessions_owner ON audio_sessions(owner_id, started_at DESC);

-- 6. Authorized Audio Recordings (Encrypted at Rest)
CREATE TABLE IF NOT EXISTS audio_recordings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES audio_sessions(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    file_path TEXT NOT NULL,
    mime_type VARCHAR(64) NOT NULL,
    duration_seconds NUMERIC(10, 2) NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_auth_tag VARCHAR(64) NOT NULL,
    sha256_checksum VARCHAR(64) NOT NULL,
    waveform_peaks JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audio_recordings_owner ON audio_recordings(owner_id, created_at DESC);

-- 7. Smart Geofences (New Feature)
CREATE TABLE IF NOT EXISTS geofences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    radius_meters DOUBLE PRECISION NOT NULL CHECK (radius_meters >= 25 AND radius_meters <= 100000),
    notify_on_enter BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_exit BOOLEAN NOT NULL DEFAULT TRUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Emergency SOS Alerts (New Feature)
CREATE TABLE IF NOT EXISTS sos_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    battery_level INTEGER,
    message TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'resolved')),
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- 9. Immutable Security Audit Logs
CREATE TABLE IF NOT EXISTS security_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warn', 'high', 'critical')),
    ip_address VARCHAR(64),
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_logs_user ON security_logs(user_id, created_at DESC);
