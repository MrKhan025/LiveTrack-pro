#!/usr/bin/env bash
set -e
echo "=== Starting LiveTrack-Pro Unified Platform (Linux / macOS / iOS Shell) ==="
export DB_MODE=${DB_MODE:-embedded}
export PORT=${PORT:-4000}
node backend/src/server.js
