# Changelog

## [3.0.0] - 2026-10-31
### Security Fixes (Part 1)
- Removed all hard-coded fallback secrets from `backend/src/lib/cryptoAuth.js` and added fail-fast startup validation (`validateRequiredSecrets`).
- Disabled wildcard CORS (`*`) and enforced strict `CORS_ORIGIN` allowlist validation + HTTPS enforcement in production.
- Strengthened password policy to 12+ characters with uppercase, lowercase, digit, symbol, and breached-password checks + progressive exponential login lockout (`429 ACCOUNT_TEMPORARILY_LOCKED`).
- Added `ProductionRateLimiter` (`backend/src/lib/rateLimiter.js`) with Redis (`REDIS_URL`) support and admin telemetry statistics.
- Enforced mandatory CSRF validation (`X-CSRF-Token`) for browser state-changing requests.
- Encrypted embedded database (`db.json.enc`) at rest with `AES-256-GCM` and blocked unapproved embedded mode in production.
- Upgraded device pairing codes to 8-character single-use `XXXX-XXXX` codes with 10-minute expiration (`410 PAIRING_CODE_EXPIRED`).
- Implemented complete Geofence Enter (`GEOFENCE_ENTER`) and Exit (`GEOFENCE_EXIT`) transition detection.
- Implemented RFC-6238 TOTP Multi-Factor Authentication (`/api/auth/mfa/setup`, `/enable`, `/verify`, `/disable`).
- Enforced `0600` file permissions on encrypted audio blobs and added GDPR account & data erasure (`DELETE /api/auth/account`).

### New Features (Part 2)
- Device-scoped API tokens with on-demand rotation (`POST /api/devices/:id/rotate-token`) and fine-grained permission scopes (`PUT /api/devices/:id/permissions`).
- Push Notifications (`FCM` for Android + `APNs` for iOS) and Outbound Alert Channels (`Webhook` with HMAC-SHA256, `Telegram`, `Email`).
- Historical Route Replay scrubber + HTML5 Canvas Speed & Altitude telemetry charts + Multi-Device Marker Clustering on the React dashboard.
- Configurable Data Retention Policies (`GET/PUT /api/settings/retention` & `POST /api/settings/retention/purge`).
- Adaptive GPS reporting interval engine (`GET /api/devices/:id/adaptive-config`) based on battery, charging state, speed, and network quality.
- Admin Security & Rate-Limit Statistics endpoint (`GET /api/admin/security-summary`) and dashboard view.
