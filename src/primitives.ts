/**
 * Real cryptographic primitives for the Simplified TLS 1.3 Handshake demo.
 *
 * Everything here is genuine: X25519 ECDHE and Ed25519 signatures come from
 * @noble/curves; SHA-256, HMAC, HKDF, and AES-128-GCM come from WebCrypto
 * (SubtleCrypto). Nothing is faked or stubbed. The HKDF here is the exact
 * RFC 5869 / RFC 8446 construction (HKDF-Expand-Label included) and is checked
 * against the RFC 8448 test vector in scripts/phase-checks.ts.
 *
 * The teaching subject of this demo is the *handshake key schedule and message
 * flow*, so HKDF-Expand-Label and Derive-Secret are hand-rolled and inspectable
 * rather than hidden inside a TLS library.
 */
import { x25519, ed25519 } from '@noble/curves/ed25519.js';

export const X25519_BYTES = 32;
export const ED25519_PUB_BYTES = 32;
export const ED25519_SIG_BYTES = 64;

export const HASH_SIZE = 32; // SHA-256
export const AES128_KEY_BYTES = 16;
export const AEAD_IV_BYTES = 12; // TLS 1.3 record nonce length (RFC 8446 5.3)

const HASH_ALGO = 'SHA-256';
const HMAC_ALGO = 'HMAC';

export interface KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function ensureLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes, got ${bytes.length}`);
  }
}

/** SubtleCrypto wants a real ArrayBuffer; copy so we never pass a shared view. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = Uint8Array.from(bytes);
  return copy.buffer;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time equality. Used for Finished-MAC and key-agreement checks. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc |= a[i] ^ b[i];
  }
  return acc === 0;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

// ---------------------------------------------------------------------------
// Hashing & HMAC
// ---------------------------------------------------------------------------

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(HASH_ALGO, toArrayBuffer(data));
  return new Uint8Array(digest);
}

export async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: HMAC_ALGO, hash: HASH_ALGO },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign(HMAC_ALGO, key, toArrayBuffer(data));
  return new Uint8Array(mac);
}

// ---------------------------------------------------------------------------
// X25519 ephemeral key exchange (forward secrecy comes from these being
// generated per session and discarded after the handshake).
// ---------------------------------------------------------------------------

export function x25519Keygen(): KeyPair {
  const secretKey = randomBytes(X25519_BYTES);
  const publicKey = x25519.getPublicKey(secretKey);
  ensureLength(publicKey, X25519_BYTES, 'X25519 public key');
  return { secretKey, publicKey };
}

export function x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  ensureLength(secretKey, X25519_BYTES, 'X25519 secret key');
  ensureLength(peerPublicKey, X25519_BYTES, 'X25519 peer public key');
  const shared = x25519.getSharedSecret(secretKey, peerPublicKey);
  ensureLength(shared, X25519_BYTES, 'X25519 shared secret');
  return shared;
}

// ---------------------------------------------------------------------------
// Ed25519 signatures (server authentication: certificates + CertificateVerify).
// ---------------------------------------------------------------------------

export function ed25519Keygen(): KeyPair {
  const secretKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(secretKey);
  ensureLength(publicKey, ED25519_PUB_BYTES, 'Ed25519 public key');
  return { secretKey, publicKey };
}

export function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const sig = ed25519.sign(message, secretKey);
  ensureLength(sig, ED25519_SIG_BYTES, 'Ed25519 signature');
  return sig;
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== ED25519_SIG_BYTES || publicKey.length !== ED25519_PUB_BYTES) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869) + TLS 1.3 HKDF-Expand-Label / Derive-Secret (RFC 8446 7.1).
// ---------------------------------------------------------------------------

export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  const mac = await hmacSha256(salt, ikm);
  ensureLength(mac, HASH_SIZE, 'HKDF-Extract output');
  return mac;
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  if (length <= 0) {
    return new Uint8Array();
  }
  const blocks = Math.ceil(length / HASH_SIZE);
  if (blocks > 255) {
    throw new Error('HKDF-Expand length too large');
  }

  const output = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let offset = 0;

  for (let i = 1; i <= blocks; i += 1) {
    const input = concatBytes(previous, info, new Uint8Array([i]));
    previous = Uint8Array.from(await hmacSha256(prk, input));
    const take = Math.min(length - offset, previous.length);
    output.set(previous.subarray(0, take), offset);
    offset += take;
  }
  return output;
}

/** HKDF-Expand-Label per RFC 8446 §7.1 (label is prefixed with "tls13 "). */
export async function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length < 0 || length > 0xffff) {
    throw new Error(`Invalid HKDF-Expand-Label length: ${length}`);
  }
  const labelBytes = utf8(`tls13 ${label}`);
  if (labelBytes.length > 255) {
    throw new Error('TLS 1.3 label is too long');
  }
  if (context.length > 255) {
    throw new Error('TLS 1.3 context is too long');
  }

  const hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
  hkdfLabel[0] = (length >> 8) & 0xff;
  hkdfLabel[1] = length & 0xff;
  hkdfLabel[2] = labelBytes.length;
  hkdfLabel.set(labelBytes, 3);
  hkdfLabel[3 + labelBytes.length] = context.length;
  hkdfLabel.set(context, 4 + labelBytes.length);

  return hkdfExpand(secret, hkdfLabel, length);
}

/** Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length). */
export async function deriveSecret(secret: Uint8Array, label: string, messages: Uint8Array): Promise<Uint8Array> {
  const transcriptHash = await sha256(messages);
  return hkdfExpandLabel(secret, label, transcriptHash, HASH_SIZE);
}

// ---------------------------------------------------------------------------
// AES-128-GCM record layer (RFC 8446 §5.2). Real authenticated encryption.
// ---------------------------------------------------------------------------

export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  ensureLength(key, AES128_KEY_BYTES, 'AES-128 key');
  ensureLength(nonce, AEAD_IV_BYTES, 'AEAD nonce');
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad) },
    cryptoKey,
    toArrayBuffer(plaintext),
  );
  return new Uint8Array(ct);
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  ensureLength(key, AES128_KEY_BYTES, 'AES-128 key');
  ensureLength(nonce, AEAD_IV_BYTES, 'AEAD nonce');
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad) },
    cryptoKey,
    toArrayBuffer(ciphertext),
  );
  return new Uint8Array(pt);
}

/**
 * Per-record nonce (RFC 8446 §5.3): the 64-bit record sequence number, padded
 * left to the IV length, XORed with the static write_iv. Distinct per record so
 * the same key never reuses a GCM nonce.
 */
export function recordNonce(writeIv: Uint8Array, seq: number): Uint8Array {
  ensureLength(writeIv, AEAD_IV_BYTES, 'write_iv');
  const nonce = Uint8Array.from(writeIv);
  // Write the sequence number into the low 8 bytes, big-endian.
  for (let i = 0; i < 8; i += 1) {
    const shift = BigInt(8 * (7 - i));
    const byte = Number((BigInt(seq) >> shift) & 0xffn);
    nonce[AEAD_IV_BYTES - 8 + i] ^= byte;
  }
  return nonce;
}
