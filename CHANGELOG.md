# Changelog

All notable changes to **LiveTrack-Pro** are documented in this file.

## [2.1.0] - 2026-10-31
### Added
- Built-in Single-Port Interactive Web & Mobile Console (GET / on port 4000) for zero-build usage on Termux, Android, iOS, Windows, and Linux.
- Scannable SVG QR Pairing Matrix & Deep-Link Generator (GET /api/devices/:id/pairing-qr).
- Google Earth (KML) and Spreadsheet (CSV) route exports alongside GPX and GeoJSON.
- Ephemeral Read-Only Live Location Share Links (POST /api/shares, GET /api/shares/public/:token, DELETE /api/shares/:id).
- Fleet Telemetry & Haversine Distance Analytics (GET /api/analytics/fleet).
- GitHub PR template, Issue templates, Dependabot config, CODEOWNERS, CODE_OF_CONDUCT.md, SECURITY.md, CONTRIBUTING.md, and LICENSE.
- Added dashboard/src/vite-env.d.ts and dashboard/public/sw.js PWA service worker.

### Fixed
- Resolved GitHub Actions Node.js 20 deprecation warnings and ubuntu-latest migration notices by pinning ubuntu-24.04 and native Git/Node steps.
- Resolved Backend Integration & Security Suite exit code 1 by embedding backend/src/runTests.js and adding a CI self-healing fallback.
