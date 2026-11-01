# Security Architecture & Hardening Guide (LiveTrack-Pro v3.0)

## 1. Fail-Fast Cryptographic Secret Enforcement (Zero Hard-Coded Secrets)
- `backend/src/lib/cryptoAuth.js` and `backend/src/server.js` contain **zero** fallback or development secrets.
- On startup, `validateRequiredSecrets()` verifies that `JWT_ACCESS_SECRET` (>= 32 chars), `JWT_REFRESH_SECRET` (>= 32 chars, distinct from access secret), and `AUDIO_ENCRYPTION_KEY` (exact 64-character hex / 256-bit key) are set in environment variables and do not match any known placeholder strings. If any check fails, the server immediately refuses to start (`FATAL_SECURITY_CONFIG`).

## 2. Strict CORS & HTTPS Enforcement
- `Access-Control-Allow-Origin: *` is completely prohibited.
- `CORS_ORIGIN` accepts a comma-separated allowlist of trusted origins. Requests from unlisted origins are rejected with `403 CORS_ORIGIN_FORBIDDEN`.
- In production (`NODE_ENV=production`), non-HTTPS requests are rejected with `403 HTTPS_REQUIRED_IN_PRODUCTION`.

## 3. Password Complexity, Breach Check & Progressive Lockout
- Passwords must be **at least 12 characters** and include at least one uppercase letter (`A-Z`), one lowercase letter (`a-z`), one digit (`0-9`), and one special symbol (`[^A-Za-z0-9]`), without 4+ repeated characters, common breached passwords, or the user's email prefix.
- After 5 failed login attempts, the account enters **exponential backoff lockout** (`30s`, `60s`, `120s`, `240s`... up to `15m`), returning `429 ACCOUNT_TEMPORARILY_LOCKED` with `Retry-After` and logging `ACCOUNT_LOCKOUT_TRIGGERED`.

## 4. Real RFC-6238 TOTP Multi-Factor Authentication (MFA)
- Users can enroll in TOTP MFA (`POST /api/auth/mfa/setup` & `POST /api/auth/mfa/enable`), receiving an encrypted-at-rest Base32 secret, an `otpauth://` QR matrix, and 8 single-use recovery codes.
- When `mfaEnabled` is true, `POST /api/auth/login` requires a valid 6-digit TOTP code or returns `202 MFA_REQUIRED` with a short-lived challenge token for `POST /api/auth/mfa/verify`.

## 5. Mandatory Browser CSRF Protection & Production Redis Rate Limiting
- Browser state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) must include a valid `X-CSRF-Token` issued by `GET /api/auth/csrf-token`.
- `ProductionRateLimiter` (`backend/src/lib/rateLimiter.js`) uses **Redis** (`REDIS_URL`) for distributed rate limiting and falls back to a bounded, self-pruning sliding-window store with an explicit production warning if `REDIS_URL` is unset.

## 6. Encrypted Embedded Store, 0600 File Permissions & GDPR Right to Erasure
- When running in embedded mode (`DB_MODE=embedded`), the state file (`db.json.enc`) is encrypted at rest using `AES-256-GCM` with `0600` file permissions. Embedded mode is blocked in production unless `ALLOW_EMBEDDED_IN_PROD=true` is explicitly set.
- All encrypted audio recordings in `storage/audio/*.enc` are written with strict `0600` (`rw-------`) permissions and `0700` directory permissions.
- `DELETE /api/auth/account` implements GDPR Right to Erasure: verifies password + TOTP, wipes all encrypted audio files from disk, and cascades deletion of all user records across all database tables.

## 7. Expiring Single-Use Pairing Codes & Device-Scoped API Tokens
- Device pairing codes use an 8-character Crockford Base32 format (`XXXX-XXXX`, 40-bit entropy) that **expires automatically after 10 minutes** and is **single-use** (`410 PAIRING_CODE_EXPIRED` if expired).
- Paired devices receive a scoped token (`gps:write`, `audio:consent`, `sos:trigger`, `device:status`) that can be rotated at any time (`POST /api/devices/:id/rotate-token`) or restricted (`PUT /api/devices/:id/permissions`).
