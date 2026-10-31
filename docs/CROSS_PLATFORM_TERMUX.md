# Cross-Platform Execution Matrix (Termux, Android, iOS, Windows, Linux, macOS)

| Platform | Server Support | Client GPS Provider | Client Consent Audio Provider | Setup Command |
| :--- | :--- | :--- | :--- | :--- |
| **Android (Kotlin App)** | Connects to any host | Google `FusedLocationProviderClient` | Android `AudioRecord` (48kHz PCM/WAV) | `./gradlew assembleDebug` |
| **Termux (Android)** | Yes (`DB_MODE=embedded` or PG) | `termux-location -p gps` | `termux-microphone-record` + CLI WAV | `bash scripts/termux-setup.sh` |
| **iOS (iPhone / iPad)** | Connects via PWA / iSH | W3C `navigator.geolocation.watchPosition` | WebAudio + `MediaRecorder` with banner | Open Dashboard -> `Web / iOS Endpoint` |
| **Linux** | Yes (Docker or Native) | GeoClue / Browser / CLI Agent | ALSA / PulseAudio / WebRTC | `bash scripts/run-unix.sh` |
| **Windows** | Yes (Docker or Native) | Windows Location API / Browser / CLI | WASAPI / Browser `MediaRecorder` | `.\scripts\run-windows.ps1` |
| **macOS** | Yes (Docker or Native) | CoreLocation / Browser / CLI | CoreAudio / Browser `MediaRecorder` | `bash scripts/run-unix.sh` |
