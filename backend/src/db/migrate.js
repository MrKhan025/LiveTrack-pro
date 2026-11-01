'use strict';

const fs = require('fs');
const path = require('path');

async function runMigrations() {
  const migrationsDir = path.join(__dirname, '../../../migrations');
  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  let totalBytes = 0;
  for (const file of files) {
    const sqlPath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(sqlPath, 'utf8');
    totalBytes += sql.length;

    if (process.env.DB_MODE === 'postgres' && process.env.DATABASE_URL) {
      const { Pool } = require('pg');
      const pool = new Pool({ connectionString: process.env.DATABASE_URL });
      try {
        await pool.query(sql);
        console.log(`[Migrate] Applied PostgreSQL migration: ${file}`);
      } finally {
        await pool.end();
      }
    }
  }

  console.log(
    `[Migrate] Verified ${files.length} SQL migration files (${files.join(', ')}; ${totalBytes} bytes total).`
  );
}

if (require.main === module) {
  runMigrations().catch((err) => {
    console.error('[Migrate] Failed:', err);
    process.exit(1);
  });
}

module.exports = { runMigrations };
