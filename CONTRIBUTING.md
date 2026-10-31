# Contributing to LiveTrack-Pro

Thank you for contributing to **LiveTrack-Pro**!

## Development Workflow

1. **Clone the repository**:
   ```bash
   git clone https://github.com/MrKhan025/LiveTrack-pro.git
   cd LiveTrack-pro
   ```
2. **Run database schema verification & automated tests**:
   ```bash
   npm run migrate
   npm test
   ```
3. **Verify dashboard TypeScript types**:
   ```bash
   cd dashboard
   npm install
   npm run typecheck
   ```

## Architectural Rules
- **Consent-First Audio**: Never introduce endpoints or background services that activate a microphone without explicit, interactive user consent and a visible OS/UI indicator.
- **Strict Ownership Checks**: Every route accessing device telemetry, geofences, shares, or audio recordings must validate device ownership via `verifyDeviceOwnershipOrReject`.
- **Zero Hardcoded Secrets**: Always read production keys from environment variables (`process.env`).
