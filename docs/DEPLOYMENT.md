# Production Deployment Guide (Docker, Nginx, PostgreSQL, Termux & Cross-Platform)

## 1. Docker Compose + Nginx + PostgreSQL Deployment
1. Copy the environment template and generate strong secrets:
   ```bash
   cp backend/.env.example .env
   openssl rand -hex 32 # Use for JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, and AUDIO_ENCRYPTION_KEY
   ```
2. Launch the full stack:
   ```bash
   docker compose up -d --build
   ```
3. Nginx listens on ports `80`/`443`, routing `/api/*` and `/ws` (WebSockets) to the Node.js backend container and `/` to the React + TypeScript dashboard container.

## 2. Running on Termux (Android Phone), Linux, Windows, macOS & iOS
- **Termux (Android)**:
  ```bash
  bash scripts/termux-setup.sh
  # Or run the Termux CLI telemetry agent:
  node cli-agent/livetrack-agent.js --server http://127.0.0.1:4000 --pair <PAIRING_CODE>
  node cli-agent/livetrack-agent.js --ping-once
  node cli-agent/livetrack-agent.js --consent-audio
  ```
- **Linux / macOS / iOS (iSH)**:
  ```bash
  bash scripts/run-unix.sh
  ```
- **Windows PowerShell**:
  ```powershell
  .\scripts\run-windows.ps1
  ```
