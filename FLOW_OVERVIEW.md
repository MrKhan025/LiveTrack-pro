# LiveTrack-Pro Flow Overview

This document captures the repo-specific end-to-end flow for the core security and telemetry systems in LiveTrack-Pro: device pairing, GPS + geofencing, and encrypted consent-based audio.

## 1) Device pairing flow: CLI agent to backend

Flow:

CLI agent / Android device
  -> POST /api/devices/register
  -> backend creates a single-use pairing code and expiry timestamp
  -> CLI agent sends POST /api/devices/pair with the pairing code
  -> backend validates the code and checks whether it has expired or been used
  -> backend calls `db.pairDeviceByCode(...)`
  -> backend generates a fresh raw device secret
  -> backend hashes it with `sha256Hex(...)`
  -> backend stores the token hash on the paired device record
  -> backend signs a device-scoped JWT containing:
       - `sub` (owner user id)
       - `deviceId`
       - `role = owner`
       - `scope = device_telemetry`
       - `tokenHash`
  -> backend returns `deviceAccessToken`
  -> future device calls use that token for scoped API access

Key backend entry points:
- `app.post('/api/devices/register', ...)`
- `app.post('/api/devices/pair', ...)`
- `app.post('/api/devices/:id/rotate-token', ...)`
- `verifyDeviceOwnershipOrReject(...)`

Relevant security checks:
- single-use pairing code
- code expiry
- owner validation
- token hash matching
- device scope enforcement
- rotate-token support for new credentials

This is the trust model:
- a device is not trusted by username/password alone
- it is trusted by a valid pairing code + valid device JWT + ownership validation

---

## 2) GPS telemetry + geofence flow

Flow:

Device / CLI / Android client
  -> POST /api/gps/update
     or POST /api/gps/batch
  -> backend validates ownership with `verifyDeviceOwnershipOrReject(...)`
  -> backend calls `processGpsPoint(reqUser, point, ipAddress)`
  -> `processGpsPoint` does the following:
       - validates latitude and longitude range
       - computes an adaptive reporting interval
       - stores the location using `db.insertGpsLocation(...)`
       - checks low-battery conditions
       - loads geofences for the owner
       - computes distance to each geofence with `haversineMeters(...)`
       - evaluates transition with `db.evaluateGeofenceTransition(...)`
       - emits a websocket event if state changed
       - dispatches notification / alert when needed
  -> dashboard receives GPS_LOCATION_UPDATE, GEOFENCE_ENTER, or GEOFENCE_EXIT events

Key backend entry points:
- `app.post('/api/gps/update', ...)`
- `app.post('/api/gps/batch', ...)`
- `app.get('/api/gps/history/:deviceId', ...)`
- `app.get('/api/gps/export/:deviceId', ...)`
- `processGpsPoint(...)`

Geofence setup and enforcement:
- `app.post('/api/geofences', ...)`
- `app.get('/api/geofences', ...)`
- `app.delete('/api/geofences/:id', ...)`

Geofence enforcement rule:
- distance = haversineMeters(currentLat, currentLon, geofenceCenter)
- inside = distance <= radiusMeters
- if previous state differed, treat as `ENTER` or `EXIT`
- trigger a log, websocket event, and notification

This logic is central to the platform’s real-time safety and fleet monitoring model.

---

## 3) Encrypted audio consent flow

Flow:

Device / CLI / Android client
  -> POST /api/audio/sessions/start
  -> backend verifies:
       - device exists
       - device belongs to the authenticated owner
       - `initiatedByDevice === true`
       - `userConsentConfirmed === true`
       - `consentStatement` is present
  -> if any check fails:
       return 403 `COVERT_RECORDING_PROHIBITED`
  -> backend creates an active audio consent session
  -> backend stores a hash of the consent token
  -> backend returns `session` + `consentToken`

Then:

Device
  -> POST /api/audio/recordings/upload
     with `sessionId`, `deviceId`, `consentToken`, and `audioBase64`
  -> backend checks:
       - correct device and active session
       - matching consent token hash
       - valid audio container header (WAV/WebM/OGG)
  -> backend does the following:
       - decode Base64 audio data
       - compute waveform peaks
       - `encryptBuffer(audioBuffer)`
       - write encrypted blob to disk with `0o600` permissions
       - save metadata in DB with:
         - filePath
         - encryptionIv
         - encryptionAuthTag
         - sha256Checksum
         - waveformPeaks
         - sizeBytes
         - durationSeconds
  -> websocket broadcasts `AUDIO_RECORDING_CREATED`

Playback:

Client
  -> GET /api/audio/recordings/:id/stream
  -> backend verifies ownership
  -> reads the encrypted file from disk
  -> decrypts with `decryptBuffer(...)`
  -> sends the decrypted audio bytes as the HTTP response

Key backend entry points:
- `app.post('/api/audio/sessions/start', ...)`
- `app.post('/api/audio/recordings/upload', ...)`
- `app.get('/api/audio/recordings/:id/stream', ...)`

Key utilities:
- `validateAudioMagicBytes(...)`
- `computeWaveformPeaks(...)`
- `encryptBuffer(...)`
- `decryptBuffer(...)`

Critical security properties:
- no covert or remote microphone activation allowed
- no audio upload without an active consent session
- no plaintext audio stored on disk
- file permissions are restricted to `0600`
- playback is restricted to authorized users/devices
- every significant event is logged

---

## 4) Where the core logic lives in the repo

Pairing, auth, and device trust:
- `backend/src/app.js`
- `backend/src/db/`
- `backend/src/lib/cryptoAuth.js`

GPS + geofence logic:
- `backend/src/app.js`
- `backend/src/lib/cryptoAuth.js` (`haversineMeters`, `calculateAdaptiveGpsInterval`)
- `backend/src/db/`

Encrypted audio + consent flow:
- `backend/src/app.js`
- `backend/src/lib/cryptoAuth.js`
- `backend/src/db/`

Client integrations:
- `dashboard/src/App.tsx` for web dashboard behavior
- `android/app/...` for Android client behavior
- `cli-agent/...` for terminal / cross-platform device integration

---

## 5) One-line summary

LiveTrack-Pro is built around a secure device-first model: paired devices send GPS updates, geofences trigger alert transitions in real time, and all audio capture requires explicit physical consent and encrypted storage before it can be accessed.
