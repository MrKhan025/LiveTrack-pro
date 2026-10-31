#!/data/data/com.termux/files/usr/bin/bash
set -e
echo "=== LiveTrack-Pro Termux Android Setup ==="
pkg update -y
pkg install -y nodejs termux-api
echo "Starting LiveTrack-Pro Unified Backend in Embedded Mode on port 4000..."
export DB_MODE=embedded
export PORT=4000
node backend/src/server.js
