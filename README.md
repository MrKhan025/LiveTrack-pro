<div align="center">

# LiveTrack-Pro

**Unified Real-Time GPS Telemetry & Explicit Consent-Based Audio Platform**

[![CI & Security Audit](https://github.com/MrKhan025/LiveTrack-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/MrKhan025/LiveTrack-pro/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/Dashboard-React%2018%20%2B%20TypeScript-3178C6?logo=typescript&logoColor=white)](./dashboard)
[![Android](https://img.shields.io/badge/Android-Kotlin%20Fused%20GPS-3DDC84?logo=android&logoColor=white)](./android)
[![License: MIT](https://img.shields.io/badge/License-MIT-0284c7.svg)](./LICENSE)

*One integrated repository combining high-precision real-time location tracking, circular geofencing, emergency SOS beacons, and consent-verified encrypted audio streaming across **Android, iOS, Termux, Windows, Linux, and macOS**.*

</div>

---

## Table of Contents

1. [Platform Overview & Core Modules](#1-platform-overview--core-modules)
2. [Ethical & Cryptographic Security Architecture](#2-ethical--cryptographic-security-architecture)
3. [Repository Directory Structure](#3-repository-directory-structure)
4. [Step-by-Step Guide: Running on Termux (Android Phone)](#4-step-by-step-guide-running-on-termux-android-phone)
5. [Step-by-Step Guide: Running on Android Mobile Phones](#5-step-by-step-guide-running-on-android-mobile-phones)
6. [Step-by-Step Guide: Running on iOS (iPhone & iPad)](#6-step-by-step-guide-running-on-ios-iphone--ipad)
7. [Step-by-Step Guide: Running on Windows 10 / 11](#7-step-by-step-guide-running-on-windows-10--11)
8. [Step-by-Step Guide: Running on Linux & macOS](#8-step-by-step-guide-running-on-linux--macos)
9. [Production Deployment with Docker, PostgreSQL & Nginx](#9-production-deployment-with-docker-postgresql--nginx)
10. [Complete REST & WebSocket API Reference](#10-complete-rest--websocket-api-reference)
11. [Running Automated Tests & Updating GitHub](#11-running-automated-tests--updating-github)

---

## 1. Platform Overview & Core Modules

**LiveTrack-Pro** unifies two safety and telemetry subsystems into a single cohesive platform with shared authentication, role-based access control, and real-time WebSocket synchronization:

### Module 1: LiveTrack GPS
- **Real-Time Location Streaming**: Ingests live coordinates (`latitude`, `longitude`, `altitude`, `accuracy`, `speed`, `heading`, and `batteryLevel`) via REST (`POST /api/gps/update`) and RFC-6455 WebSockets (`GPS_PING`).
- **Multi-Device Fleet Management**: Pair and monitor multiple devices simultaneously across Android, Termux, iOS, Windows, Linux, and macOS using 6-character pairing codes or scannable SVG QR codes (`GET /api/devices/:id/pairing-qr`).
- **Smart Circular Geofencing**: Define circular perimeter zones (`25m` to `100,000m` radius). The backend computes real-time Haversine distances on every GPS ping and broadcasts instant `GEOFENCE_EXIT` alerts.
- **Offline Store-and-Forward Batch Sync**: Buffers coordinates when mobile connectivity drops and synchronizes historical batches (`POST /api/gps/batch`) upon reconnection.
- **Multi-Format Route Export**: Export historical device tracks directly to **GPX**, **GeoJSON**, **KML** (Google Earth), or **CSV** (`GET /api/gps/export/:deviceId?format=gpx|geojson|kml|csv`).
- **Ephemeral Live Share Links**: Generate time-limited, read-only public tracking links (`POST /api/shares`) for family members or emergency responders that can be revoked at any time.
- **Fleet Distance & Speed Analytics**: Automatically calculates total kilometers traveled (via Haversine integration), maximum speed, and low-battery warnings (`GET /api/analytics/fleet`).

### Module 2: LiveTrack Audio (Strictly Consent-Based)
- **Explicit Device-Initiated Recording Only**: Audio sessions can **only** be started when the physical device user checks the explicit consent confirmation and initiates recording on their device (`initiatedByDevice: true`, `userConsentConfirmed: true`).
- **Zero Covert or Remote Activation**: Any attempt to start a microphone session without physical device consent flags is rejected with `HTTP 403 COVERT_RECORDING_PROHIBITED` and logged as a `critical` event in the immutable security audit trail.
- **Persistent Visible Indicators**: Displays an ongoing Android Foreground Service notification (`FOREGROUND_SERVICE_LOCATION|MICROPHONE`), a Termux status notification, or a bright red recording banner in the Web/PWA console whenever audio capture is active.
- **AES-256-GCM Encrypted Audio Vault**: Validates uploaded audio container magic bytes (`WAV`, `WebM/Opus`, `OGG`), extracts a 64-band RMS waveform envelope, and encrypts the audio payload at rest using **AES-256-GCM** with a unique 96-bit IV, 128-bit authentication tag, and SHA-256 checksum.
- **Authenticated On-the-Fly Decryption & Waveform Player**: Decrypts authorized recordings on demand (`GET /api/audio/recordings/:id/stream`) and renders interactive 64-bar HTML5 Canvas waveforms.

---

## 2. Ethical & Cryptographic Security Architecture

| Security Layer | Implementation Details |
| :--- | :--- |
| **Password Hashing** | `scrypt` key derivation function with a 16-byte cryptographic salt, 64-byte derived key, and timing-safe verification (`crypto.timingSafeEqual`). |
| **JWT & Token Rotation** | Short-lived `HS256` access tokens (15 minutes) paired with 7-day refresh tokens stored as `SHA-256` hashes. Replaying an old refresh token immediately revokes access (`401`). |
| **IDOR Protection** | Every device, GPS history, share link, and audio stream route verifies `resource.ownerId === req.user.id`. Cross-account access attempts return `403 IDOR_FORBIDDEN` and log `IDOR_ATTEMPT_BLOCKED`. |
| **Audio Encryption** | `AES-256-GCM` authenticated encryption at rest with per-recording random IV, auth tag verification, and `SHA-256` integrity headers. |
| **Transport & Headers** | Enforces `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Referrer-Policy`, CSRF tokens, and sliding-window API rate limiting. |

---

## 3. Repository Directory Structure

```text
LiveTrack-pro/
├── .github/workflows/ci.yml           # Automated GitHub Actions CI & Security Audit (Ubuntu 24.04)
├── android/                           # Native Android App (Kotlin, FusedLocationProviderClient, AudioRecord)
│   ├── app/src/main/AndroidManifest.xml
│   └── app/src/main/java/pro/livetrack/app/
│       ├── MainActivity.kt
│       ├── telemetry/LiveTrackForegroundService.kt
│       └── audio/ConsentAudioStreamer.kt
├── backend/                           # Node.js Backend API + RFC-6455 WebSocket Server + Standalone Console
│   ├── Dockerfile
│   ├── package.json
│   ├── src/
│   │   ├── app.js                     # Unified REST routes, RBAC, IDOR guards, Geofencing, SOS, Encrypted Audio
│   │   ├── server.js                  # HTTP + WebSocket Server entrypoint (default port 4000)
│   │   ├── runTests.js                # Self-contained 9-part automated integration & security test runner
│   │   ├── db/index.js                # Dual-driver PostgreSQL Pool + Zero-Config Embedded Engine
│   │   ├── db/migrate.js              # SQL migration validator and runner
│   │   └── lib/
│   │       ├── cryptoAuth.js          # Scrypt, HS256 JWT, AES-256-GCM, Waveform & SVG QR Matrix generator
│   │       ├── microExpress.js        # Zero-dependency Express-compatible HTTP router
│   │       ├── standaloneConsoleHtml.js # Built-in Single-Port Mobile/Desktop Web Console at GET /
│   │       └── wsServer.js            # RFC-6455 WebSocket server with owner-isolated broadcasts
│   └── tests/platform.test.js         # Automated test suite mirror
├── cli-agent/                         # Universal Cross-Platform Agent (Termux, Linux, Windows, macOS, iOS shell)
│   ├── livetrack-agent.js
│   └── package.json
├── dashboard/                         # React 18 + TypeScript + Vite + Leaflet/OpenStreetMap Dashboard
│   ├── Dockerfile
│   ├── public/
│   │   ├── manifest.webmanifest       # Installable Android / iOS / Desktop PWA manifest
│   │   └── sw.js                      # Offline PWA Service Worker
│   └── src/
│       ├── vite-env.d.ts              # Vite TypeScript environment declarations
│       ├── App.tsx                    # Full 9-Tab Unified Management Console
│       ├── components/LiveGpsMap.tsx
│       ├── components/AudioConsentCenter.tsx
│       └── components/WebDeviceClient.tsx
├── docs/                              # Detailed API, Android Build, Security, Deployment & Termux Guides
├── migrations/001_initial_schema.sql  # Complete PostgreSQL schema (10 tables + indexes)
├── nginx/nginx.conf                   # Production reverse proxy, WSS upgrade & rate-limiting rules
├── scripts/                           # One-command launchers for Termux, Linux/macOS, and Windows PowerShell
└── docker-compose.yml                 # Multi-container PostgreSQL + Backend + Dashboard + Nginx stack
```

---

## 4. Step-by-Step Guide: Running on Termux (Android Phone)

**LiveTrack-Pro** is specially engineered to run **both** as a self-hosted server and as a hardware GPS/Audio telemetry agent directly inside **Termux** on any Android phone—with zero native C++ compilation required.

### Step 1: Install Termux & Required Packages
1. Install **Termux** and **Termux:API** from F-Droid on your Android device.
2. Open Termux and grant location and microphone permissions when prompted, then install `git`, `nodejs`, and `termux-api`:
   ```bash
   pkg update -y && pkg upgrade -y
   pkg install -y git nodejs termux-api
   ```

### Step 2: Clone & Start the LiveTrack-Pro Server on Your Phone
```bash
git clone https://github.com/MrKhan025/LiveTrack-pro.git
cd LiveTrack-pro

# Verify the database schema and run the 9-part automated test suite
npm run migrate
npm test

# Start the Unified Server on port 4000 (uses zero-config embedded database automatically)
npm start
```
- Now open Chrome or Firefox on your Android phone and visit **`http://127.0.0.1:4000`**.
- The built-in **LiveTrack-Pro Mobile & Desktop Web Console** loads immediately on port `4000`—allowing you to register an account, view the live OpenStreetMap, generate a pairing code, stream GPS, and record consent audio right from your phone!

### Step 3: Pair & Run the Termux Hardware CLI Agent
Open a second Termux session (swipe from the left edge -> **New Session**) to stream hardware GPS (`termux-location`), battery level (`termux-battery-status`), and consent-verified audio:
```bash
cd ~/LiveTrack-pro

# 1. Pair with the 6-character code generated in the Web Console
node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --pair <YOUR_6_CHAR_CODE>

# 2. Send a live hardware GPS + battery ping
node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --ping-once

# 3. Record and encrypt an explicit user-consented audio clip (displays persistent Termux notification)
node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --consent-audio
```

---

## 5. Step-by-Step Guide: Running on Android Mobile Phones

You can use **LiveTrack-Pro** on an Android phone in two ways:

### Option A: Instant Mobile Web / PWA App (No APK Build Needed)
1. Start the LiveTrack-Pro server on your PC, cloud VPS, or Termux (`npm start`).
2. Open Chrome on your Android phone and navigate to your server URL (e.g., `http://<SERVER_IP>:4000` or your HTTPS domain).
3. Tap the Chrome menu (`⋮`) -> **Add to Home screen** / **Install app** to install **LiveTrack-Pro** as a standalone full-screen Progressive Web App (PWA).
4. Sign in, register your phone under **Step 2**, and use **Step 3 (Mobile / Browser Live Sensor Transmitter)** to stream live GPS and consent-verified microphone audio with a visible red indicator banner.

### Option B: Build & Install the Native Kotlin Android APK
1. Open the `android/` directory in **Android Studio** (Ladybug 2024.2+ with Android SDK 34 and JDK 17), or build via command line:
   ```bash
   cd android
   ./gradlew assembleDebug
   ```
2. Install the generated APK (`android/app/build/outputs/apk/debug/app-debug.apk`) onto your phone via USB Debugging:
   ```bash
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```
3. Open **LiveTrack-Pro** on your phone, enter your Server URL and 6-digit Pairing Code, tap **Pair Device**, and toggle **Start Fused Location GPS Tracking** or check the explicit consent box to start **User-Initiated Microphone Recording**.

---

## 6. Step-by-Step Guide: Running on iOS (iPhone & iPad)

### Option A: iOS Safari Progressive Web App (PWA)
1. Open **Safari** on your iPhone or iPad and visit your LiveTrack-Pro server URL (e.g., `https://your-domain.com` or `http://<LAN_IP>:4000`).
2. Tap the **Share** icon at the bottom of Safari and select **Add to Home Screen**.
3. Launch **LiveTrack-Pro** from your iOS Home Screen.
4. Register or select your iPhone/iPad device, allow Safari Location access to stream real-time W3C GPS coordinates, and check the explicit consent box to record authorized microphone audio with a persistent on-screen recording indicator.

### Option B: iOS Terminal Shells (a-Shell / iSH)
If you use **a-Shell** or **iSH** on iOS with Node.js installed:
```bash
git clone https://github.com/MrKhan025/LiveTrack-pro.git
cd LiveTrack-pro
node cli-agent/livetrack-agent.js --server https://your-domain.com --pair <CODE>
node cli-agent/livetrack-agent.js --server https://your-domain.com --ping-once
```

---

## 7. Step-by-Step Guide: Running on Windows 10 / 11

### Step 1: Install Prerequisites
1. Install [Node.js LTS (v20 or v24)](https://nodejs.org/) and [Git for Windows](https://git-scm.com/download/win).

### Step 2: Clone, Test & Launch via PowerShell
Open **PowerShell** and run:
```powershell
git clone https://github.com/MrKhan025/LiveTrack-pro.git
cd LiveTrack-pro

# Run the automated verification suite
npm test

# Start the Unified Server using the Windows PowerShell launcher
.\scriptsun-windows.ps1
```
- Open **`http://localhost:4000`** in Edge, Chrome, or Firefox to use the built-in Unified Web Console immediately.

### Step 3: Optional — Run the Full Vite + React TypeScript Development Dashboard
If you also want to run the standalone React + TypeScript development server with hot-reload on port `3000`:
```powershell
cd dashboard
npm install
npm run dev
```
Then open **`http://localhost:3000`**.

---

## 8. Step-by-Step Guide: Running on Linux & macOS

### Step 1: Clone, Verify & Start the Unified Server
Open your terminal on Ubuntu, Debian, Fedora, Arch Linux, or macOS ( require Node.js >= 18):
```bash
git clone https://github.com/MrKhan025/LiveTrack-pro.git
cd LiveTrack-pro

# Validate SQL migrations & run all 9 automated tests
npm run migrate
npm test

# Launch the Unified Server on port 4000
bash scripts/run-unix.sh
```
- Visit **`http://localhost:4000`** in your browser.

### Step 2: Pair Your Linux or macOS Machine as a Tracked Endpoint
```bash
node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --pair <PAIRING_CODE>
node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --ping-once
node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --consent-audio
```

---

## 9. Production Deployment with Docker, PostgreSQL & Nginx

For production cloud hosting (AWS, DigitalOcean, Hetzner, Linode, or on-premise Linux servers), use the included multi-container Docker Compose stack:

```bash
# 1. Create your production .env file and set strong cryptographic secrets
cp backend/.env.example .env

# 2. Build and launch PostgreSQL 16, Backend API/WS, React Dashboard, and Nginx Reverse Proxy
docker compose up -d --build

# 3. Check container health
docker compose ps
```
- **Nginx** listens on port `80` (and `443` when TLS certificates are mounted), enforces rate-limiting zones (`api_limit` and `auth_limit`), upgrades `/ws` connections for real-time WebSockets, routes `/api/*` to the Node.js backend, and serves the compiled React + TypeScript dashboard at `/`.

---

## 10. Complete REST & WebSocket API Reference

| Method & Endpoint | Auth Required | Description |
| :--- | :--- | :--- |
| `GET /` | Public | Built-in single-port Interactive Mobile & Desktop Web Console |
| `GET /api/health` | Public | Health check, active DB mode, and supported client platforms |
| `POST /api/auth/register` | Public | Register a new user account and issue `accessToken` + `refreshToken` |
| `POST /api/auth/login` | Public | Authenticate with email/password and issue JWT tokens |
| `POST /api/auth/refresh` | Public | Rotate refresh token and invalidate previous token hash |
| `POST /api/auth/logout` | Bearer JWT | Revoke active refresh token session |
| `POST /api/devices/register` | Bearer JWT | Register a device (`android`, `termux`, `ios`, `windows`, `linux`, `macos`, `web`) |
| `GET /api/devices/:id/pairing-qr` | Bearer JWT | Generate SVG QR code, `livetrack://pair` deep link, and CLI pairing command |
| `POST /api/devices/pair` | Public (Code) | Exchange 6-character `pairingCode` for a scoped `deviceAccessToken` |
| `POST /api/devices/:id/tracking` | Bearer JWT | Start or stop GPS tracking (`{ "active": true \| false }`) |
| `POST /api/gps/update` | Bearer JWT | Submit live GPS coordinates + battery status; evaluates geofences & broadcasts via WS |
| `POST /api/gps/batch` | Bearer JWT | Synchronize offline store-and-forward location batches |
| `GET /api/gps/history/:deviceId` | Bearer JWT | Retrieve historical coordinates for a device |
| `GET /api/gps/export/:deviceId` | Bearer JWT | Export route history (`?format=gpx`, `geojson`, `kml`, or `csv`) |
| `POST /api/audio/sessions/start` | Bearer JWT | Start device-initiated consent audio session (`initiatedByDevice: true` required) |
| `POST /api/audio/sessions/:id/stop`| Bearer JWT | Stop active consent audio session and clear microphone indicator |
| `POST /api/audio/recordings/upload`| Bearer JWT | Validate consent token + magic bytes, extract waveform, and encrypt with AES-256-GCM |
| `GET /api/audio/recordings/:id/stream`| Bearer JWT | Verify ownership, decrypt AES-256-GCM payload on-the-fly, and stream audio |
| `DELETE /api/audio/recordings/:id` | Bearer JWT | Permanently delete encrypted audio blob and database record |
| `POST /api/geofences` | Bearer JWT | Create circular geofence zone (`latitude`, `longitude`, `radiusMeters`) |
| `POST /api/shares` | Bearer JWT | Create time-limited read-only public location share link |
| `GET /api/shares/public/:token` | Public (Token)| View live location and battery status for an active shared token |
| `GET /api/analytics/fleet` | Bearer JWT | Compute total Haversine distance (km), max speed, and battery health across devices |
| `POST /api/sos/trigger` | Bearer JWT | Trigger high-priority user-initiated Emergency SOS beacon |
| `GET /api/security-logs` | Bearer JWT | View immutable security and anti-covert audit logs |
| `WS /ws?token=<JWT>` | Bearer JWT | Real-time bidirectional WebSocket stream (`GPS_PING`, `AUDIO_STREAM_CHUNK`) |

---

## 11. Running Automated Tests & Updating GitHub

### Run the Automated Integration & Security Test Suite
```bash
npm test
```
This executes all 9 automated verification suites (`backend/src/runTests.js`), verifying HTTP security headers, `scrypt` authentication, refresh token replay blocking, SVG QR pairing, IDOR cross-account protection, Haversine geofence triggers, `GPX`/`KML`/`CSV`/`GeoJSON` exports, `403` blocking of covert/remote microphone activation, `AES-256-GCM` audio encryption/decryption, ephemeral share links, SOS beacons, RFC-6455 WebSockets, and the cross-platform CLI agent.

### Updating Your GitHub Repository (`MrKhan025/LiveTrack-pro`)
To push all files cleanly without missing subdirectories or changing folder capitalization (`nginx/`, `dashboard/public/`, `backend/tests/`), run from the extracted folder:
```bash
git init -b main
git remote add origin https://github.com/MrKhan025/LiveTrack-pro.git
git add .
git commit -m "Fix CI errors/warnings/notices, add vite-env.d.ts, QR pairing, KML/CSV export & platform guides"
git push -u origin main --force
```
