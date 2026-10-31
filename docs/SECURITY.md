# Security Architecture & Anti-Covert Guarantees

## 1. Zero-Covert Tracking & Microphone Enforcement
- **No Remote Microphone Trigger**: Neither the WebSocket protocol nor the REST API exposes any command to remotely activate a device's microphone.
- **Cryptographic Consent Handshake**: Recording uploads (`POST /api/audio/recordings/upload`) and live WebSocket audio chunks (`AUDIO_STREAM_CHUNK`) require an active `sessionId` and a cryptographic `consentToken` generated only when `initiatedByDevice: true` and `userConsentConfirmed: true` are asserted by the physical device.
- **Critical Audit Logging**: Any malformed or unauthorized attempt to start an audio session without consent flags is immediately blocked (`403 COVERT_RECORDING_PROHIBITED`) and recorded in `security_logs` with `severity: critical`.

## 2. Cryptography & Storage Security
- **Password Hashing**: `scrypt` key derivation function (`N=16384`, 16-byte random salt, 64-byte output) verified with `crypto.timingSafeEqual`.
- **Token Security**: Short-lived `HS256` access tokens (15 minutes) paired with rotating refresh tokens stored as `SHA-256` hashes in the `sessions` table. Replaying a rotated refresh token immediately fails with `401`.
- **Encryption at Rest**: Every uploaded audio file is validated for container magic bytes (`WAV`, `WebM`, `OGG`) and encrypted via `AES-256-GCM` with a unique 96-bit IV and 128-bit authentication tag before touching disk.

## 3. API Hardening (IDOR, CSRF, Rate Limiting, Headers)
- **IDOR Prevention**: Every device, GPS history, audio session, and audio stream route verifies `resource.ownerId === req.user.id` before returning data. Cross-tenant requests return `403 IDOR_FORBIDDEN` and log `IDOR_ATTEMPT_BLOCKED`.
- **Rate Limiting**: Built-in sliding window rate limiter in `app.js` and Nginx `limit_req_zone` protect `/api/auth/` and telemetry endpoints against brute-force and DoS floods.
- **HTTP Security Headers**: Enforces `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, and `Referrer-Policy`.
