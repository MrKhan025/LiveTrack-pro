# LiveTrack-Pro
### Unified Real-Time GPS & Explicit Consent-Based Audio Platform

**LiveTrack-Pro** combines two mission-critical telemetry modules into one cohesive, security-hardened monorepo:
1. **LiveTrack GPS** – High-accuracy real-time location tracking, route history, smart circular geofencing, offline store-and-forward batch sync, and GPX/GeoJSON export.
2. **LiveTrack Audio** – Strictly user-initiated, consent-verified live audio streaming and AES-256-GCM encrypted recording vault with 64-band waveform visualization and persistent OS/UI microphone indicators.

## Short, Easily Pronounceable Repository Name Suggestions
| Suggested Name | Pronunciation | Meaning & Vibe | Suggested GitHub Slug |
| :--- | :--- | :--- | :--- |
| **Veloce** | *veh-LOH-cheh* | Italian for *swift/fast*; sleek real-time telemetry | `veloce` / `veloce-pro` |
| **Navox** | *NAH-vox* | Blend of **Nav**igation (GPS) + **Vox** (Voice/Audio) | `navox` |
| **Kova** | *KOH-vah* | Punchy 4-letter name evoking protective safety cover | `kova` |
| **Luma** | *LOO-mah* | Clear, transparent visibility (consent-first indicators) | `luma-track` |
| **Sora** | *SOH-rah* | Japanese for *sky*; crisp 2-syllable overwatch name | `sora-link` |
| **Pingo** | *PING-go* | Friendly fusion of location **Ping** + **Go** | `pingo` |
| **Voxa** | *VOK-sah* | 4-letter blend of Voice + Axis coordinates | `voxa` |

## Universal Cross-Platform Support
- **Android (Native Kotlin App)**: `android/` uses Google `FusedLocationProviderClient`, `AudioRecord`, and a persistent `ForegroundService` (`location|microphone`).
- **Termux (Android CLI)**: `cli-agent/livetrack-agent.js` & `scripts/termux-setup.sh` interface directly with `termux-location`, `termux-battery-status`, `termux-microphone-record`, and `termux-notification`.
- **iOS (iPhone / iPad)**: Installable PWA (`dashboard/public/manifest.webmanifest`) + `WebDeviceClient.tsx` using W3C `navigator.geolocation` and explicit `MediaRecorder` consent capture, plus `cli-agent` support for iSH / a-Shell.
- **Windows, Linux & macOS**: Full support for running both the Unified Server (`scripts/run-windows.ps1`, `scripts/run-unix.sh`), the Web Dashboard, and the native Desktop CLI Telemetry Agent (`cli-agent/livetrack-agent.js`).

## Quick Start (Zero-Config Local / Termux / Edge Mode)
```bash
# 1. Run database migration check
npm run migrate

# 2. Run the automated 7-part integration & security test suite
npm test

# 3. Start the Unified Backend + WebSocket Server on port 4000
npm start
```

## Production Deployment (Docker + PostgreSQL + Nginx)
```bash
cp backend/.env.example .env
docker compose up -d --build
```
