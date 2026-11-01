'use strict';

const crypto = require('crypto');

const FORBIDDEN_PLACEHOLDERS = [
  'livetrack-dev-access-secret-override-in-prod',
  'livetrack-dev-refresh-secret-override-in-prod',
  'livetrack-dev-audio-aes256-key',
  'replace_with_64_byte_hex_random_secret_for_access_tokens',
  'replace_with_64_byte_hex_random_secret_for_refresh_tokens',
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'generate_with_openssl_rand_hex_32_minimum_64_hex_characters_required',
  'generate_different_openssl_rand_hex_32_minimum_64_hex_characters_here',
  'generate_64_char_hex_key_with_openssl_rand_hex_32_for_aes_256_gcm'
];

const COMMON_BREACHED_PASSWORDS = new Set([
  'password123!',
  'password1234!',
  'admin123456!',
  'welcome12345!',
  'qwerty123456!',
  'livetrack123!',
  'changeme1234!',
  'letmein12345!',
  'iloveyou1234!',
  '1234567890ab!'
]);

function isForbiddenSecretValue(val) {
  if (!val || typeof val !== 'string') return true;
  const lower = val.trim().toLowerCase();
  if (FORBIDDEN_PLACEHOLDERS.includes(lower)) return true;
  if (lower.startsWith('livetrack-dev-') || lower.startsWith('replace_with_') || lower.startsWith('generate_')) {
    return true;
  }
  return false;
}

/**
 * Validates that JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, and AUDIO_ENCRYPTION_KEY
 * are explicitly set in environment variables and do not use development/placeholder values.
 * Throws a fatal error if any secret is missing or weak.
 */
function validateRequiredSecrets(env = process.env) {
  const accessSecret = env.JWT_ACCESS_SECRET;
  const refreshSecret = env.JWT_REFRESH_SECRET;
  const audioKeyHex = env.AUDIO_ENCRYPTION_KEY;

  if (isForbiddenSecretValue(accessSecret) || String(accessSecret).trim().length < 32) {
    throw new Error(
      'FATAL_SECURITY_CONFIG: JWT_ACCESS_SECRET is missing, uses a forbidden development placeholder, or is shorter than 32 characters. Generate a strong secret with `openssl rand -hex 32`.'
    );
  }

  if (isForbiddenSecretValue(refreshSecret) || String(refreshSecret).trim().length < 32) {
    throw new Error(
      'FATAL_SECURITY_CONFIG: JWT_REFRESH_SECRET is missing, uses a forbidden development placeholder, or is shorter than 32 characters. Generate a strong secret with `openssl rand -hex 32`.'
    );
  }

  if (accessSecret === refreshSecret) {
    throw new Error(
      'FATAL_SECURITY_CONFIG: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be distinct secrets.'
    );
  }

  if (
    isForbiddenSecretValue(audioKeyHex) ||
    !/^[0-9a-fA-F]{64}$/.test(String(audioKeyHex).trim())
  ) {
    throw new Error(
      'FATAL_SECURITY_CONFIG: AUDIO_ENCRYPTION_KEY is missing, uses a forbidden placeholder, or is not a valid 64-character hexadecimal (256-bit) key. Generate one with `openssl rand -hex 32`.'
    );
  }

  return {
    ACCESS_SECRET: String(accessSecret).trim(),
    REFRESH_SECRET: String(refreshSecret).trim(),
    ENC_KEY: Buffer.from(String(audioKeyHex).trim(), 'hex')
  };
}

function getSecrets() {
  return validateRequiredSecrets(process.env);
}

function base64UrlEncode(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

/**
 * Strong Password Policy Validator:
 * - Minimum 12 characters
 * - At least one uppercase letter [A-Z]
 * - At least one lowercase letter [a-z]
 * - At least one digit [0-9]
 * - At least one special character [^A-Za-z0-9]
 * - Not in common breached password list or containing email prefix
 */
function validateStrongPassword(password, email = '') {
  if (typeof password !== 'string' || password.length < 12) {
    return {
      valid: false,
      reason: 'Password must be at least 12 characters long.'
    };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one uppercase letter (A-Z).' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one lowercase letter (a-z).' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one number (0-9).' };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one special character (e.g. !@#$%^&*).' };
  }
  if (/(.){3,}/.test(password)) {
    return { valid: false, reason: 'Password cannot contain 4 or more consecutive identical characters.' };
  }
  const lower = password.toLowerCase();
  if (COMMON_BREACHED_PASSWORDS.has(lower)) {
    return { valid: false, reason: 'Password appears in known breached password lists. Choose a unique passphrase.' };
  }
  if (email && typeof email === 'string') {
    const localPart = email.split('@')[0].trim().toLowerCase();
    if (localPart.length >= 4 && lower.includes(localPart)) {
      return { valid: false, reason: 'Password must not contain your email username.' };
    }
  }
  return { valid: true };
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

function signJwt(payload, secretOverride = null, expiresInSeconds = 900) {
  const { ACCESS_SECRET } = getSecrets();
  const secret = secretOverride || ACCESS_SECRET;
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

function verifyJwt(token, secretOverride = null) {
  if (!token || typeof token !== 'string') return null;
  const { ACCESS_SECRET } = getSecrets();
  const secret = secretOverride || ACCESS_SECRET;
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
  const { ENC_KEY } = getSecrets();
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
  const { ENC_KEY } = getSecrets();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

function encryptText(plainText) {
  const { encrypted, iv, authTag } = encryptBuffer(Buffer.from(String(plainText), 'utf8'));
  return `${iv}:${authTag}:${encrypted.toString('base64')}`;
}

function decryptText(serialized) {
  if (!serialized || typeof serialized !== 'string') return null;
  const [ivHex, authTagHex, b64] = serialized.split(':');
  if (!ivHex || !authTagHex || !b64) return null;
  const decrypted = decryptBuffer(Buffer.from(b64, 'base64'), ivHex, authTagHex);
  return decrypted.toString('utf8');
}

/**
 * Generates an 8-character human-friendly Crockford Base32 pairing code (XXXX-XXXX)
 * with 40 bits of cryptographic entropy and a 10-minute expiration timestamp.
 */
const PAIRING_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateSecurePairingCode(ttlMinutes = 10) {
  const bytes = crypto.randomBytes(8);
  let chars = '';
  for (let i = 0; i < 8; i++) {
    chars += PAIRING_ALPHABET[bytes[i] % PAIRING_ALPHABET.length];
  }
  const code = `${chars.slice(0, 4)}-${chars.slice(4, 8)}`;
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
  return { code, expiresAt };
}

/**
 * RFC-4648 Base32 & RFC-6238 TOTP Multi-Factor Authentication
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str) {
  const cleaned = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  const secretBytes = crypto.randomBytes(20);
  const secretBase32 = base32Encode(secretBytes);
  const recoveryCodes = Array.from({ length: 8 }, () =>
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );
  return { secretBase32, recoveryCodes };
}

function generateTotpCode(secretBase32, timestampMs = Date.now(), stepSeconds = 30, digits = 6) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binary % 10 ** digits;
  return String(otp).padStart(digits, '0');
}

function verifyTotpCode(secretBase32, token, timestampMs = Date.now(), windowSteps = 1) {
  if (!secretBase32 || !token) return false;
  const cleanToken = String(token).trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;
  for (let w = -windowSteps; w <= windowSteps; w++) {
    const candidate = generateTotpCode(secretBase32, timestampMs + w * 30000);
    if (candidate === cleanToken) return true;
  }
  return false;
}

function buildOtpAuthUri(email, secretBase32, issuer = 'LiveTrack-Pro') {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secretBase32)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
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
  <text x="${size / 2}" y="${size + 15}" text-anchor="middle" font-family="monospace" font-size="12" font-weight="bold" fill="#0f172a">${codeLabel}</text>
</svg>`;
}

/**
 * Calculates adaptive GPS reporting interval (in seconds) based on battery level, charging state, speed, and network quality
 */
function calculateAdaptiveGpsInterval({ batteryLevel = 100, isCharging = false, speed = 0, networkType = 'wifi' }) {
  if (isCharging) return 5;
  if (batteryLevel < 15) return 90;
  if (batteryLevel < 30) return speed > 3 ? 25 : 60;
  if (networkType === 'cellular-2g' || networkType === 'offline') return 45;
  if (speed > 8) return 5;
  if (speed > 1.5) return 10;
  return 20;
}

module.exports = {
  validateRequiredSecrets,
  getSecrets,
  validateStrongPassword,
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  sha256Hex,
  encryptBuffer,
  decryptBuffer,
  encryptText,
  decryptText,
  generateSecurePairingCode,
  generateTotpSecret,
  generateTotpCode,
  verifyTotpCode,
  buildOtpAuthUri,
  computeWaveformPeaks,
  haversineMeters,
  generatePairingSvgMatrix,
  calculateAdaptiveGpsInterval
};
