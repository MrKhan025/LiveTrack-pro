# Security Policy & Ethical Telemetry Guarantee

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Zero-Covert Tracking & Microphone Enforcement

**LiveTrack-Pro** is strictly an ethical, consent-first location and audio safety platform:
1. **No Remote or Covert Microphone Activation**: Neither the REST API nor the WebSocket protocol implements any command capable of remotely turning on a device's microphone.
2. **Cryptographic Consent Verification**: Audio streaming (`AUDIO_STREAM_CHUNK`) and recording uploads (`POST /api/audio/recordings/upload`) require an active `sessionId` and a cryptographic `consentToken` issued only when the physical device asserts `initiatedByDevice: true` and `userConsentConfirmed: true`.
3. **Mandatory Visible OS Notifications**: Both the native Android Foreground Service (`FOREGROUND_SERVICE_LOCATION` and `FOREGROUND_SERVICE_MICROPHONE`), the Termux CLI agent, and the Web/PWA endpoint display persistent, non-dismissible recording and tracking banners.
4. **AES-256-GCM Encryption at Rest**: All uploaded audio recordings are verified for valid container magic bytes (`WAV`, `WebM`, `OGG`) and encrypted using `AES-256-GCM` with a unique 96-bit IV and 128-bit authentication tag before being written to storage.
5. **IDOR & Replay Protection**: Every resource endpoint verifies `ownerId === req.user.id` and logs unauthorized attempts (`IDOR_ATTEMPT_BLOCKED`) to an immutable audit trail.

## Reporting a Vulnerability

Please report suspected security vulnerabilities by opening a private security advisory on GitHub (`Security` -> `Report a vulnerability`). Do not include live credentials or personal telemetry in public issues.
