Write-Host "=== Starting LiveTrack-Pro Unified Platform (Windows PowerShell) ==="
$env:DB_MODE = if ($env:DB_MODE) { $env:DB_MODE } else { "embedded" }
$env:PORT = if ($env:PORT) { $env:PORT } else { "4000" }
node backend/src/server.js
