# LiveTrack-Pro Unified REST & WebSocket API Reference

## 1. Unified Authentication
- `POST /api/auth/register` – Register a new account (`email`, `fullName`, `password`, optional `role`). Returns `user`, `accessToken`, and `refreshToken`.
- `POST /api/auth/login` – Authenticate and receive short-lived HS256 `accessToken` (15m) + rotating `refreshToken` (7d).
- `POST /api/auth/refresh` – Rotate `refreshToken` and invalidate previous token hash (prevents replay attacks).
- `POST /api/auth/logout` – Revoke active session.
- `GET /api/auth/me` – Retrieve current user profile.
- `GET /api/auth/csrf-token` – Generate cryptographic CSRF token for state-changing requests.

## 2. Device Pairing & Ownership Verification
- `POST /api/devices/register` – Register a device (`android`, `termux`, `ios`, `windows`, `linux`, `macos`, `web`) and receive a 6-character `pairingCode`.
- `POST /api/devices/pair` – Exchange `pairingCode` for a scoped `deviceAccessToken`.
- `GET /api/devices` – List all devices owned by the authenticated user.
- `GET /api/devices/:id` – Inspect a single device (strictly protected against IDOR; unauthorized access logs `IDOR_ATTEMPT_BLOCKED` and returns `403`).
- `POST /api/devices/:id/tracking` – Start or stop GPS tracking (`{ "active": true | false }`).

## 3. GPS Telemetry, Geofences, SOS & Export
- `POST /api/gps/update` – Submit live coordinates (`deviceId`, `latitude`, `longitude`, `accuracy`, `speed`, `heading`, `batteryLevel`). Evaluates Haversine geofences and broadcasts via WebSockets.
- `POST /api/gps/batch` – Synchronize offline store-and-forward location batches.
- `GET /api/gps/history/:deviceId?limit=100` – Fetch historical coordinates.
- `GET /api/gps/export/:deviceId?format=gpx|geojson` – Export route history as standard `.gpx` XML or `.geojson`.
- `POST /api/geofences` / `GET /api/geofences` / `DELETE /api/geofences/:id` – Manage circular geofence zones.
- `POST /api/sos/trigger` / `POST /api/sos/:id/resolve` / `GET /api/sos` – Trigger and resolve high-priority user-initiated SOS beacons.

## 4. Consent-Based Audio Module
- `POST /api/audio/sessions/start` – Requires `initiatedByDevice: true`, `userConsentConfirmed: true`, and non-empty `consentStatement`. Any remote or unconsented request is rejected with `403 COVERT_RECORDING_PROHIBITED`. Returns a one-time `consentToken`.
- `POST /api/audio/sessions/:sessionId/stop` – Terminate active consent session and clear microphone indicator.
- `POST /api/audio/recordings/upload` – Validate active consent session + `consentToken` + audio magic bytes (`RIFF/WAVE`, `WebM`, `OggS`), compute 64-bar waveform peaks, and encrypt payload at rest using `AES-256-GCM`.
- `GET /api/audio/recordings` – List authorized recordings with waveform metadata and SHA-256 checksums.
- `GET /api/audio/recordings/:id/stream` – Verify ownership, decrypt `AES-256-GCM` payload on-the-fly, and stream audio to the dashboard player.
- `DELETE /api/audio/recordings/:id` – Permanently wipe encrypted audio blob from disk and database.

## 5. Real-Time WebSocket Protocol (`/ws?token=<JWT>`)
- **Incoming Client Frames**: `AUTH`, `GPS_PING`, `AUDIO_STREAM_CHUNK`.
- **Outgoing Broadcast Events**: `GPS_LOCATION_UPDATE`, `DEVICE_TRACKING_STATE`, `AUDIO_SESSION_STARTED`, `LIVE_AUDIO_CHUNK`, `AUDIO_SESSION_STOPPED`, `AUDIO_RECORDING_CREATED`, `EMERGENCY_SOS_ALERT`.
