/** Real TLS 1.3 application-data records for 0-RTT and resumed 1-RTT traffic. */
import { deriveTrafficKeys } from './keyschedule';
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  concatBytes,
  equalBytes,
  recordNonce,
  toHex,
  utf8,
} from './primitives';

const RECORD_APPLICATION_DATA = 0x17;
const TLS12_LEGACY = 0x0303;

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

export interface ProtectedApplicationRecord {
  wire: Uint8Array;
  wireHex: string;
  aad: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  plaintext: Uint8Array;
  sequenceNumber: number;
}

/** Seal plaintext under a traffic secret, including the TLSInnerPlaintext content type. */
export async function sealApplicationRecord(
  trafficSecret: Uint8Array,
  plaintext: Uint8Array,
  sequenceNumber = 0,
): Promise<ProtectedApplicationRecord> {
  const keys = await deriveTrafficKeys(trafficSecret);
  const nonce = recordNonce(keys.iv, sequenceNumber);
  const inner = concatBytes(plaintext, new Uint8Array([RECORD_APPLICATION_DATA]));
  const ciphertextLength = inner.length + 16;
  const aad = concatBytes(new Uint8Array([RECORD_APPLICATION_DATA]), u16(TLS12_LEGACY), u16(ciphertextLength));
  const ciphertext = await aesGcmEncrypt(keys.key, nonce, inner, aad);
  const wire = concatBytes(aad, ciphertext);
  return {
    wire,
    wireHex: toHex(wire),
    aad,
    nonce,
    ciphertext,
    plaintext: Uint8Array.from(plaintext),
    sequenceNumber,
  };
}

/** Authenticate, decrypt, and strictly parse one TLS 1.3 application-data record. */
export async function openApplicationRecord(
  trafficSecret: Uint8Array,
  wire: Uint8Array,
  sequenceNumber = 0,
): Promise<Uint8Array> {
  if (wire.length < 5 + 16 + 1) throw new Error('TLSCiphertext is too short');
  if (wire[0] !== RECORD_APPLICATION_DATA || wire[1] !== 0x03 || wire[2] !== 0x03) {
    throw new Error('unexpected TLSCiphertext header');
  }
  const declared = (wire[3]! << 8) | wire[4]!;
  if (declared !== wire.length - 5) throw new Error('TLSCiphertext length mismatch');
  const aad = wire.subarray(0, 5);
  const ciphertext = wire.subarray(5);
  const keys = await deriveTrafficKeys(trafficSecret);
  const nonce = recordNonce(keys.iv, sequenceNumber);
  const inner = await aesGcmDecrypt(keys.key, nonce, ciphertext, aad);
  if (inner.length === 0 || inner[inner.length - 1] !== RECORD_APPLICATION_DATA) {
    throw new Error('unexpected TLSInnerPlaintext content type');
  }
  return Uint8Array.from(inner.subarray(0, inner.length - 1));
}

export async function applicationRecordRoundTrip(
  trafficSecret: Uint8Array,
  message: string,
): Promise<boolean> {
  const plaintext = utf8(message);
  const record = await sealApplicationRecord(trafficSecret, plaintext);
  const opened = await openApplicationRecord(trafficSecret, record.wire);
  return equalBytes(opened, plaintext);
}
