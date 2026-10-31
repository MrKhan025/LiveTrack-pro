# Android Native App (Kotlin) Build Instructions

## Requirements
- Android Studio Ladybug (2024.2+) or command-line Android SDK Platform 34
- JDK 17+
- Android device or emulator running Android 8.0 (API 26) through Android 14/15 (API 34+)

## Building the APK
1. Open the `android/` directory in Android Studio, or run from the terminal:
   ```bash
   cd android
   ./gradlew assembleDebug
   ```
2. The compiled APK will be generated at `android/app/build/outputs/apk/debug/app-debug.apk`.
3. Install on a connected Android phone via ADB:
   ```bash
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```

## Mandatory Transparency & Anti-Covert Architecture
- `AndroidManifest.xml` declares `android:foregroundServiceType="location|microphone"`.
- `LiveTrackForegroundService.kt` displays an ongoing, non-dismissible system notification whenever Fused Location tracking is active.
- `MainActivity.kt` and `ConsentAudioStreamer.kt` require the physical user to check the explicit consent checkbox and tap **Start User-Initiated Microphone Recording**, immediately displaying a bright red recording banner (`VISIBLE MICROPHONE INDICATOR`). Remote microphone activation from the web dashboard does not exist in the codebase.
