'use strict';

const crypto = require('crypto');

const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET ||
  crypto.createHash('sha256').update('livetrack-dev-access-secret-override-in-prod').digest('hex');
const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ||
  crypto.createHash('sha256').update('livetrack-dev-refresh-secret-override-in-prod').digest('hex');
const ENC_KEY_HEX =
  process.env.AUDIO_ENCRYPTION_KEY ||
  crypto.createHash('sha256').update('livetrack-dev-audio-aes256-key').digest('hex');
const ENC_KEY = Buffer.from(ENC_KEY_HEX.slice(0, 64), 'hex');

function base64UrlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function hashPassword(plainPassword) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(plainPassword), salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(plainPassword, storedHash) {
  if (!storedHash || !storedHash.startsWith('scrypt$')) return false;
  const parts = storedHash.split('$');
  if (parts.length !== 3) return false;
  const [, salt, originalHex] = parts;
  const derived = crypto.scryptSync(String(plainPassword), salt, 64);
  const original = Buffer.from(originalHex, 'hex');
  if (derived.length !== original.length) return false;
  return crypto.timingSafeEqual(derived, original);
}

function signJwt(payload, secret = ACCESS_SECRET, expiresInSeconds = 900) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
    jti: crypto.randomUUID()
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedBody = base64UrlEncode(JSON.stringify(body));
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const signature = crypto.createHmac('sha256', secret).update(signingInput).digest();
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

function verifyJwt(token, secret = ACCESS_SECRET) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedBody, encodedSig] = parts;
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const expectedSig = crypto.createHmac('sha256', secret).update(signingInput).digest();
  const actualSig = base64UrlDecode(encodedSig);
  if (expectedSig.length !== actualSig.length || !crypto.timingSafeEqual(expectedSig, actualSig)) {
    return null;
  }
  try {
    const payload = JSON.parse(base64UrlDecode(encodedBody).toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return null;
    return payload;
  } catch {
    return null;
  }
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function encryptBuffer(plainBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    sha256: sha256Hex(plainBuffer)
  };
}

function decryptBuffer(encryptedBuffer, ivHex, authTagHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

function computeWaveformPeaks(buffer, buckets = 64) {
  if (!buffer || buffer.length === 0) return Array(buckets).fill(0.1);
  const step = Math.max(1, Math.floor(buffer.length / buckets));
  const peaks = [];
  for (let i = 0; i < buckets; i++) {
    let sum = 0;
    let count = 0;
    const start = i * step;
    const end = Math.min(buffer.length, start + step);
    for (let j = start; j < end; j++) {
      const centered = Math.abs(buffer[j] - 128) / 128;
      sum += centered;
      count++;
    }
    const avg = count > 0 ? sum / count : 0.1;
    peaks.push(Number(Math.min(1, Math.max(0.08, avg * 1.6)).toFixed(3)));
  }
  return peaks;
}

function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/**
 * Generates an SVG visual pairing matrix badge for mobile pairing codes
 */
function generatePairingSvgMatrix(pairingPayload, codeLabel = '') {
  const hash = crypto.createHash('sha256').update(String(pairingPayload)).digest();
  const grid = 21;
  const cell = 8;
  const margin = 16;
  const size = grid * cell + margin * 2;
  const rects = [];

  const isFinder = (r, c) =>
    (r < 7 && c < 7) || (r < 7 && c >= grid - 7) || (r >= grid - 7 && c < 7);

  const drawFinder = (rowOffset, colOffset) => {
    const x = margin + colOffset * cell;
    const y = margin + rowOffset * cell;
    rects.push(`<rect x="${x}" y="${y}" width="${7 * cell}" height="${7 * cell}" fill="#0f172a"/>`);
    rects.push(`<rect x="${x + cell}" y="${y + cell}" width="${5 * cell}" height="${5 * cell}" fill="#ffffff"/>`);
    rects.push(`<rect x="${x + 2 * cell}" y="${y + 2 * cell}" width="${3 * cell}" height="${3 * cell}" fill="#0284c7"/>`);
  };

  drawFinder(0, 0);
  drawFinder(0, grid - 7);
  drawFinder(grid - 7, 0);

  let bitIdx = 0;
  for (let r = 0; r < grid; r++) {
    for (let c = 0; c < grid; c++) {
      if (isFinder(r, c)) continue;
      const byte = hash[Math.floor(bitIdx / 8) % hash.length];
      const bit = (byte >> (bitIdx % 8)) & 1;
      bitIdx++;
      if (bit) {
        rects.push(
          `<rect x="${margin + c * cell}" y="${margin + r * cell}" width="${cell}" height="${cell}" fill="#0f172a" rx="1"/>`
        );
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size + 24}" width="${size}" height="${size + 24}">
  <rect width="100%" height="100%" fill="#ffffff" rx="8"/>
  ${rects.join('\n  ')}
  <text x="${size / 2}" y="${size + 15}" text-anchor="middle" font-family="monospace" font-size="12" font-weight="bold" fill="#0f172a">CODE: ${codeLabel}</text>
</svg>`;
}

module.exports = {
  ACCESS_SECRET,
  REFRESH_SECRET,
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  sha256Hex,
  encryptBuffer,
  decryptBuffer,
  computeWaveformPeaks,
  haversineMeters,
  generatePairingSvgMatrix
};
