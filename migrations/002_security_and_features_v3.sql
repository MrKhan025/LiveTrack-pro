-- LiveTrack-Pro v3.0 Migration: Security Hardening, TOTP MFA, Geofence States, Scoped Tokens, Retention & Alerting
-- Migration: 002_security_and_features_v3.sql

-- 1. Enhance users table with TOTP MFA, progressive login lockout, and data retention policies
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_encrypted TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_codes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS gps_retention_days INTEGER NOT NULL DEFAULT 30 CHECK (gps_retention_days >= 1 AND gps_retention_days <= 3650);
ALTER TABLE users ADD COLUMN IF NOT EXISTS audio_retention_days INTEGER NOT NULL DEFAULT 14 CHECK (audio_retention_days >= 1 AND audio_retention_days <= 3650);
ALTER TABLE users ADD COLUMN IF NOT EXISTS auto_purge_enabled BOOLEAN NOT NULL DEFAULT TRUE;

-- 2. Enhance devices table with expiring single-use pairing codes, fine-grained token scopes, and adaptive GPS intervals
ALTER TABLE devices ADD COLUMN IF NOT EXISTS pairing_code_expires_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS token_scopes JSONB NOT NULL DEFAULT '["gps:write","audio:consent","sos:trigger","device:status"]'::jsonb;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS token_rotated_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS adaptive_interval_seconds INTEGER NOT NULL DEFAULT 10;

-- 3. Geofence Per-Device State Tracking (enables exact ENTER and EXIT transition detection)
CREATE TABLE IF NOT EXISTS geofence_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    geofence_id UUID NOT NULL REFERENCES geofences(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    is_inside BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(geofence_id, device_id)
);

-- 4. Push Notification Tokens (FCM for Android + APNs for iOS)
CREATE TABLE IF NOT EXISTS push_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    provider VARCHAR(16) NOT NULL CHECK (provider IN ('fcm', 'apns', 'webpush')),
    token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, provider, token)
);

-- 5. Outbound Critical Event Alert Channels (Webhook, Telegram, Email)
CREATE TABLE IF NOT EXISTS alert_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_type VARCHAR(24) NOT NULL CHECK (channel_type IN ('webhook', 'telegram', 'email')),
    name VARCHAR(120) NOT NULL,
    target TEXT NOT NULL,
    secret_header TEXT,
    events JSONB NOT NULL DEFAULT '["EMERGENCY_SOS","GEOFENCE_ENTER","GEOFENCE_EXIT","LOW_BATTERY"]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
