/**
 * The TLS 1.3 key schedule (RFC 8446 §7.1) — the heart of how one X25519 shared
 * secret becomes the many independent keys a connection needs.
 *
 *               0
 *               |
 *   PSK ->  HKDF-Extract  = Early Secret
 *               |
 *          Derive-Secret(., "derived", "")
 *               |
 *  (EC)DHE ->  HKDF-Extract = Handshake Secret
 *               |  +--> Derive-Secret(., "c hs traffic", CH..SH)
 *               |  +--> Derive-Secret(., "s hs traffic", CH..SH)
 *          Derive-Secret(., "derived", "")
 *               |
 *      0 ->  HKDF-Extract = Master Secret
 *                  +--> Derive-Secret(., "c ap traffic", CH..server Finished)
 *                  +--> Derive-Secret(., "s ap traffic", CH..server Finished)
 *
 * This demo uses the (EC)DHE-only path (no PSK / 0-RTT), which is the common
 * full handshake. Every value below is a real HKDF output, derived from the
 * actual session's X25519 secret and message transcript.
 */
import {
  AEAD_IV_BYTES,
  AES128_KEY_BYTES,
  HASH_SIZE,
  deriveSecret,
  equalBytes,
  hkdfExpandLabel,
  hkdfExtract,
  hmacSha256,
  sha256,
} from './primitives';

export interface TrafficKeys {
  /** The traffic secret this key/iv pair was derived from. */
  secret: Uint8Array;
  key: Uint8Array;
  iv: Uint8Array;
}

export interface KeySchedule {
  earlySecret: Uint8Array;
  handshakeSecret: Uint8Array;
  masterSecret: Uint8Array;
  clientHandshakeTrafficSecret: Uint8Array;
  serverHandshakeTrafficSecret: Uint8Array;
  clientApplicationTrafficSecret: Uint8Array;
  serverApplicationTrafficSecret: Uint8Array;
  exporterMasterSecret: Uint8Array;
}

const ZEROS = new Uint8Array(HASH_SIZE);
const EMPTY = new Uint8Array();

/**
 * Run the full (EC)DHE key schedule.
 *
 * @param sharedSecret  the X25519 ECDHE shared secret (the (EC)DHE input)
 * @param transcriptHelloHash  Hash(ClientHello..ServerHello) — handshake-phase context
 * @param transcriptToServerFinishedHash  Hash(ClientHello..server Finished) — app-phase context
 */
export async function deriveKeySchedule(
  sharedSecret: Uint8Array,
  transcriptHelloHash: Uint8Array,
  transcriptToServerFinishedHash: Uint8Array,
): Promise<KeySchedule> {
  // Early Secret = HKDF-Extract(0, PSK). With no PSK, both the salt and the PSK
  // are Hash.length zero bytes (RFC 8446 §7.1), giving the well-known constant
  // 33ad0a1c…f170f92a verified in scripts/phase-checks.ts.
  const earlySecret = await hkdfExtract(ZEROS, ZEROS);

  // Handshake Secret = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE).
  const emptyHash = await sha256(EMPTY);
  const derivedForHandshake = await hkdfExpandLabel(earlySecret, 'derived', emptyHash, HASH_SIZE);
  const handshakeSecret = await hkdfExtract(derivedForHandshake, sharedSecret);

  const clientHandshakeTrafficSecret = await deriveSecretFromHash(
    handshakeSecret,
    'c hs traffic',
    transcriptHelloHash,
  );
  const serverHandshakeTrafficSecret = await deriveSecretFromHash(
    handshakeSecret,
    's hs traffic',
    transcriptHelloHash,
  );

  // Master Secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0).
  const derivedForMaster = await hkdfExpandLabel(handshakeSecret, 'derived', emptyHash, HASH_SIZE);
  const masterSecret = await hkdfExtract(derivedForMaster, ZEROS);

  const clientApplicationTrafficSecret = await deriveSecretFromHash(
    masterSecret,
    'c ap traffic',
    transcriptToServerFinishedHash,
  );
  const serverApplicationTrafficSecret = await deriveSecretFromHash(
    masterSecret,
    's ap traffic',
    transcriptToServerFinishedHash,
  );
  const exporterMasterSecret = await deriveSecretFromHash(
    masterSecret,
    'exp master',
    transcriptToServerFinishedHash,
  );

  return {
    earlySecret,
    handshakeSecret,
    masterSecret,
    clientHandshakeTrafficSecret,
    serverHandshakeTrafficSecret,
    clientApplicationTrafficSecret,
    serverApplicationTrafficSecret,
    exporterMasterSecret,
  };
}

/**
 * Derive the record-protection key and IV from a traffic secret
 * (RFC 8446 §7.3): "key" and "iv" HKDF-Expand-Labels with empty context.
 */
export async function deriveTrafficKeys(trafficSecret: Uint8Array): Promise<TrafficKeys> {
  const key = await hkdfExpandLabel(trafficSecret, 'key', EMPTY, AES128_KEY_BYTES);
  const iv = await hkdfExpandLabel(trafficSecret, 'iv', EMPTY, AEAD_IV_BYTES);
  return { secret: trafficSecret, key, iv };
}

/**
 * Finished message verify_data (RFC 8446 §4.4.4):
 *   finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
 *   verify_data  = HMAC(finished_key, Transcript-Hash(handshake context))
 * The BaseKey is the *handshake* traffic secret of whichever side is sending.
 */
export async function finishedMac(baseKey: Uint8Array, transcriptHash: Uint8Array): Promise<Uint8Array> {
  const finishedKey = await hkdfExpandLabel(baseKey, 'finished', EMPTY, HASH_SIZE);
  return hmacSha256(finishedKey, transcriptHash);
}

export async function verifyFinished(
  baseKey: Uint8Array,
  transcriptHash: Uint8Array,
  received: Uint8Array,
): Promise<boolean> {
  const expected = await finishedMac(baseKey, transcriptHash);
  return equalBytes(expected, received);
}

// Derive-Secret takes Messages, but the caller often already has the transcript
// hash; expose a hash-taking variant so we never re-hash a long transcript.
async function deriveSecretFromHash(secret: Uint8Array, label: string, transcriptHash: Uint8Array): Promise<Uint8Array> {
  return hkdfExpandLabel(secret, label, transcriptHash, HASH_SIZE);
}

// Re-export so callers building transcripts can compute Derive-Secret directly.
export { deriveSecret };
