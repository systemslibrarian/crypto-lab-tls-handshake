/**
 * Minimal TLS 1.3 resumption ClientHello encoder/parser for this lab.
 *
 * It emits real TLS handshake framing and the extensions the resumption exhibit
 * teaches.  `pre_shared_key` is always last, and `truncated` ends immediately
 * after OfferedPsks.identities while retaining every enclosing length as if the
 * 32-byte binder were present (RFC 9846 §4.3.11.2).
 */
import { concatBytes, toHex } from './primitives';

export type PskMode = 'psk_dhe_ke' | 'psk_ke';

/** A server that cannot select an offered PSK mode falls back to a full handshake. */
export function selectPskMode(offered: readonly PskMode[], allowed: readonly PskMode[]): PskMode | null {
  return offered.find((mode) => allowed.includes(mode)) ?? null;
}

const HANDSHAKE_CLIENT_HELLO = 0x01;
const TLS12_LEGACY = 0x0303;
const TLS13 = 0x0304;
const TLS_AES_128_GCM_SHA256 = 0x1301;
const X25519 = 0x001d;

const EXT_SUPPORTED_VERSIONS = 0x002b;
const EXT_KEY_SHARE = 0x0033;
const EXT_EARLY_DATA = 0x002a;
const EXT_PSK_MODES = 0x002d;
const EXT_PRE_SHARED_KEY = 0x0029;

const BINDER_BYTES = 32;

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function u24(value: number): Uint8Array {
  return new Uint8Array([(value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function u32(value: number): Uint8Array {
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function vec(payload: Uint8Array, width: 1 | 2): Uint8Array {
  if (width === 1) {
    if (payload.length > 0xff) throw new Error('vector exceeds uint8 length');
    return concatBytes(new Uint8Array([payload.length]), payload);
  }
  if (payload.length > 0xffff) throw new Error('vector exceeds uint16 length');
  return concatBytes(u16(payload.length), payload);
}

function extension(type: number, data: Uint8Array): Uint8Array {
  return concatBytes(u16(type), vec(data, 2));
}

function modeCode(mode: PskMode): number {
  return mode === 'psk_dhe_ke' ? 1 : 0;
}

export interface PskClientHelloInput {
  random: Uint8Array;
  identity: Uint8Array;
  obfuscatedTicketAge: number;
  mode: PskMode;
  /** A client share is sent in both demos so the server can fall back to full TLS. */
  keyShare: Uint8Array;
  binder: Uint8Array;
}

export interface PskClientHello {
  full: Uint8Array;
  truncated: Uint8Array;
  fullHex: string;
  truncatedHex: string;
  identity: Uint8Array;
  obfuscatedTicketAge: number;
  binder: Uint8Array;
  mode: PskMode;
  extensionOrder: readonly string[];
}

/** Build a resumption ClientHello. Call once with a zero binder, then again with the computed binder. */
export function serializePskClientHello(input: PskClientHelloInput): PskClientHello {
  if (input.random.length !== 32) throw new Error('ClientHello.random must be 32 bytes');
  if (input.keyShare.length !== 32) throw new Error('X25519 key_share must be 32 bytes');
  if (input.identity.length === 0 || input.identity.length > 0xffff) throw new Error('PSK identity length is invalid');
  if (input.binder.length !== BINDER_BYTES) throw new Error(`PSK binder must be ${BINDER_BYTES} bytes`);

  const supportedVersions = extension(EXT_SUPPORTED_VERSIONS, vec(u16(TLS13), 1));
  const keyShareEntry = concatBytes(u16(X25519), vec(input.keyShare, 2));
  const keyShare = extension(EXT_KEY_SHARE, vec(keyShareEntry, 2));
  const earlyData = extension(EXT_EARLY_DATA, new Uint8Array());
  const pskModes = extension(EXT_PSK_MODES, vec(new Uint8Array([modeCode(input.mode)]), 1));

  const identityEntry = concatBytes(vec(input.identity, 2), u32(input.obfuscatedTicketAge >>> 0));
  const identities = vec(identityEntry, 2);
  const binders = vec(vec(input.binder, 1), 2);
  const pskDataLength = identities.length + binders.length;
  const pskHeader = concatBytes(u16(EXT_PRE_SHARED_KEY), u16(pskDataLength));

  const beforeExtensions = concatBytes(
    u16(TLS12_LEGACY),
    input.random,
    vec(new Uint8Array(), 1),
    vec(u16(TLS_AES_128_GCM_SHA256), 2),
    vec(new Uint8Array([0]), 1),
  );
  const earlierExtensions = concatBytes(supportedVersions, keyShare, earlyData, pskModes);
  const extensionsLength = earlierExtensions.length + pskHeader.length + pskDataLength;

  // The outer lengths describe the final ClientHello even though `truncated`
  // stops before the binders vector, exactly as RFC 9846 §4.3.11.2 requires.
  const bodyLength = beforeExtensions.length + 2 + extensionsLength;
  const handshakeHeader = concatBytes(new Uint8Array([HANDSHAKE_CLIENT_HELLO]), u24(bodyLength));
  const prefix = concatBytes(
    handshakeHeader,
    beforeExtensions,
    u16(extensionsLength),
    earlierExtensions,
    pskHeader,
    identities,
  );
  const full = concatBytes(prefix, binders);

  return {
    full,
    truncated: prefix,
    fullHex: toHex(full),
    truncatedHex: toHex(prefix),
    identity: Uint8Array.from(input.identity),
    obfuscatedTicketAge: input.obfuscatedTicketAge >>> 0,
    binder: Uint8Array.from(input.binder),
    mode: input.mode,
    extensionOrder: ['supported_versions', 'key_share', 'early_data', 'psk_key_exchange_modes', 'pre_shared_key'],
  };
}

class Reader {
  offset = 0;
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  take(length: number, label: string): Uint8Array {
    if (length < 0 || this.offset + length > this.bytes.length) throw new Error(`truncated ${label}`);
    const out = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  byte(label: string): number {
    return this.take(1, label)[0]!;
  }

  u16(label: string): number {
    const b = this.take(2, label);
    return (b[0]! << 8) | b[1]!;
  }

  u24(label: string): number {
    const b = this.take(3, label);
    return (b[0]! << 16) | (b[1]! << 8) | b[2]!;
  }

  u32(label: string): number {
    const b = this.take(4, label);
    return ((b[0]! * 0x1000000) + (b[1]! << 16) + (b[2]! << 8) + b[3]!) >>> 0;
  }
}

const EXTENSION_NAMES: Record<number, string> = {
  [EXT_SUPPORTED_VERSIONS]: 'supported_versions',
  [EXT_KEY_SHARE]: 'key_share',
  [EXT_EARLY_DATA]: 'early_data',
  [EXT_PSK_MODES]: 'psk_key_exchange_modes',
  [EXT_PRE_SHARED_KEY]: 'pre_shared_key',
};

/** Parse this lab's ClientHello from recorded wire bytes; rejects malformed or reordered inputs. */
export function parsePskClientHello(full: Uint8Array): PskClientHello {
  const r = new Reader(full);
  if (r.byte('handshake type') !== HANDSHAKE_CLIENT_HELLO) throw new Error('not a ClientHello');
  const declaredBody = r.u24('ClientHello length');
  if (declaredBody !== full.length - 4) throw new Error('ClientHello length mismatch');
  if (r.u16('legacy_version') !== TLS12_LEGACY) throw new Error('unexpected legacy_version');
  r.take(32, 'random');
  r.take(r.byte('session id length'), 'session id');
  r.take(r.u16('cipher suites length'), 'cipher suites');
  r.take(r.byte('compression methods length'), 'compression methods');
  const extensionsLength = r.u16('extensions length');
  const extensionsEnd = r.offset + extensionsLength;
  if (extensionsEnd !== full.length) throw new Error('extensions length mismatch');

  const order: string[] = [];
  let identity: Uint8Array | null = null;
  let identityOffset = -1;
  let age = 0;
  let binder: Uint8Array | null = null;
  let truncatedEnd = -1;
  let mode: PskMode | null = null;

  while (r.offset < extensionsEnd) {
    const type = r.u16('extension type');
    const length = r.u16('extension length');
    const dataStart = r.offset;
    const dataEnd = dataStart + length;
    if (dataEnd > extensionsEnd) throw new Error('extension exceeds ClientHello');
    order.push(EXTENSION_NAMES[type] ?? `0x${type.toString(16).padStart(4, '0')}`);

    if (type === EXT_PSK_MODES) {
      const modesLength = r.byte('psk modes length');
      const modes = r.take(modesLength, 'psk modes');
      if (modes.length !== 1 || (modes[0] !== 0 && modes[0] !== 1)) throw new Error('unsupported PSK mode');
      mode = modes[0] === 1 ? 'psk_dhe_ke' : 'psk_ke';
    } else if (type === EXT_PRE_SHARED_KEY) {
      if (dataEnd !== extensionsEnd) throw new Error('pre_shared_key must be the last ClientHello extension');
      const identitiesLength = r.u16('identities length');
      const identitiesEnd = r.offset + identitiesLength;
      const identityLength = r.u16('identity length');
      identityOffset = r.offset;
      identity = Uint8Array.from(r.take(identityLength, 'identity'));
      age = r.u32('obfuscated_ticket_age');
      if (r.offset !== identitiesEnd) throw new Error('this demo expects exactly one PSK identity');
      truncatedEnd = r.offset;
      const bindersLength = r.u16('binders length');
      const bindersEnd = r.offset + bindersLength;
      const binderLength = r.byte('binder length');
      binder = Uint8Array.from(r.take(binderLength, 'binder'));
      if (binder.length !== BINDER_BYTES || r.offset !== bindersEnd) throw new Error('invalid PSK binder vector');
    } else {
      r.offset = dataEnd;
    }

    if (r.offset !== dataEnd) throw new Error('extension length mismatch');
  }

  const expected = ['supported_versions', 'key_share', 'early_data', 'psk_key_exchange_modes', 'pre_shared_key'];
  if (order.join(',') !== expected.join(',')) throw new Error(`unexpected ClientHello extensions: ${order.join(', ')}`);
  if (!identity || !binder || !mode || truncatedEnd < 0 || identityOffset < 0) throw new Error('incomplete PSK ClientHello');

  return {
    full: Uint8Array.from(full),
    truncated: Uint8Array.from(full.subarray(0, truncatedEnd)),
    fullHex: toHex(full),
    truncatedHex: toHex(full.subarray(0, truncatedEnd)),
    identity,
    obfuscatedTicketAge: age,
    binder,
    mode,
    extensionOrder: order,
  };
}

/** Flip a byte in the offered identity while leaving the original binder untouched. */
export function flipOfferedIdentity(full: Uint8Array, byteIndex = 0): Uint8Array {
  const parsed = parsePskClientHello(full);
  if (byteIndex < 0 || byteIndex >= parsed.identity.length) throw new Error('identity byte index out of range');
  const needle = toHex(parsed.identity);
  const fullHex = toHex(full);
  const at = fullHex.indexOf(needle);
  if (at < 0) throw new Error('identity not found in ClientHello');
  const out = Uint8Array.from(full);
  out[(at / 2) + byteIndex] ^= 0x01;
  return out;
}
