'use strict';

const { createPlatformServer } = require('./app');

const PORT = Number(process.env.PORT || 4000);
const { server, db } = createPlatformServer();

server.listen(PORT, () => {
  console.log(`[LiveTrack-Pro] Unified GPS & Consent Audio Platform listening on port ${PORT} (DB mode: ${db.mode})`);
});
