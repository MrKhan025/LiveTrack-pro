'use strict';

const { validateRequiredSecrets } = require('./lib/cryptoAuth');
const { createPlatformServer } = require('./app');

// Fail-fast check before binding port: refuses to start if secrets are missing or use development placeholders
try {
  validateRequiredSecrets(process.env);
} catch (err) {
  console.error(`[LiveTrack-Pro Startup Refused] ${err.message}`);
  process.exit(1);
}

const PORT = Number(process.env.PORT || 4000);
const { server, db } = createPlatformServer();

server.listen(PORT, () => {
  console.log(`[LiveTrack-Pro v3.0] Unified GPS & Consent Audio Platform listening on port ${PORT} (DB mode: ${db.mode})`);
});
