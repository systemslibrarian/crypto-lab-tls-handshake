/**
 * NewSessionTicket and this lab's modelled stateless ticket format.
 *
 * RFC 9846 deliberately treats `ticket` as opaque.  The lab makes one honest,
 * labelled server choice: AES-128-GCM under an in-memory server ticket-
 * encryption key (STEK), over the PSK plus the state needed to enforce age and
 * early-data limits.  Nothing is persisted.
 */
import {
  AEAD_IV_BYTES,
  AES128_KEY_BYTES,
  aesGcmDecrypt,
  aesGcmEncrypt,
  concatBytes,
  randomBytes,
  utf8,
} from './primitives';

export const MAX_TICKET_LIFETIME_SECONDS = 604_800;
export const DEFAULT_TICKET_LIFETIME_SECONDS = 86_400;
export const DEFAULT_MAX_EARLY_DATA = 4_096;

const HANDSHAKE_NEW_SESSION_TICKET = 0x04;
const EXT_EARLY_DATA = 0x002a;
const FORMAT_VERSION = 1;
const TICKET_AAD = utf8('crypto-lab TLS 1.3 modelled ticket v1');

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

function encodeUint64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('issuedAtMs must be a non-negative safe integer');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

function decodeUint64(bytes: Uint8Array): number {
  if (bytes.length !== 8) throw new Error('invalid uint64');
  const value = Number(new DataView(Uint8Array.from(bytes).buffer).getBigUint64(0, false));
  if (!Number.isSafeInteger(value)) throw new Error('uint64 exceeds JavaScript safe integer');
  return value;
}

export interface TicketState {
  psk: Uint8Array;
  issuedAtMs: number;
  lifetimeSeconds: number;
  ticketAgeAdd: number;
  maxEarlyDataSize: number;
  serverName: string;
}

export interface NewSessionTicket {
  ticketLifetime: number;
  ticketAgeAdd: number;
  ticketNonce: Uint8Array;
  ticket: Uint8Array;
  maxEarlyDataSize: number;
  /** Real TLS NewSessionTicket handshake bytes (type + uint24 length + body). */
  wire: Uint8Array;
}

function validateState(state: TicketState): void {
  if (state.psk.length !== 32) throw new Error('ticket PSK must be 32 bytes');
  if (state.lifetimeSeconds < 0 || state.lifetimeSeconds > MAX_TICKET_LIFETIME_SECONDS) {
    throw new Error(`ticket_lifetime must be between 0 and ${MAX_TICKET_LIFETIME_SECONDS} seconds`);
  }
  if (!Number.isInteger(state.ticketAgeAdd) || state.ticketAgeAdd < 0 || state.ticketAgeAdd > 0xffffffff) {
    throw new Error('ticket_age_add is invalid');
  }
  if (!Number.isInteger(state.maxEarlyDataSize) || state.maxEarlyDataSize < 0 || state.maxEarlyDataSize > 0xffffffff) {
    throw new Error('max_early_data_size is invalid');
  }
  const name = utf8(state.serverName);
  if (name.length === 0 || name.length > 0xffff) throw new Error('ticket server name is invalid');
}

function encodeTicketState(state: TicketState): Uint8Array {
  validateState(state);
  const name = utf8(state.serverName);
  return concatBytes(
    new Uint8Array([FORMAT_VERSION]),
    encodeUint64(state.issuedAtMs),
    u32(state.lifetimeSeconds),
    u32(state.ticketAgeAdd),
    u32(state.maxEarlyDataSize),
    vec(name, 2),
    state.psk,
  );
}

function decodeTicketState(plaintext: Uint8Array): TicketState {
  let offset = 0;
  const take = (length: number, label: string): Uint8Array => {
    if (offset + length > plaintext.length) throw new Error(`truncated ticket ${label}`);
    const out = plaintext.subarray(offset, offset + length);
    offset += length;
    return out;
  };
  const readU32 = (label: string): number => {
    const b = take(4, label);
    return ((b[0]! * 0x1000000) + (b[1]! << 16) + (b[2]! << 8) + b[3]!) >>> 0;
  };

  if (take(1, 'version')[0] !== FORMAT_VERSION) throw new Error('unsupported ticket format');
  const issuedAtMs = decodeUint64(take(8, 'issuance time'));
  const lifetimeSeconds = readU32('lifetime');
  const ticketAgeAdd = readU32('ticket age add');
  const maxEarlyDataSize = readU32('early-data limit');
  const nameLenBytes = take(2, 'server-name length');
  const nameLength = (nameLenBytes[0]! << 8) | nameLenBytes[1]!;
  const serverName = new TextDecoder('utf-8', { fatal: true }).decode(take(nameLength, 'server name'));
  const psk = Uint8Array.from(take(32, 'PSK'));
  if (offset !== plaintext.length) throw new Error('ticket has trailing bytes');
  const state = { psk, issuedAtMs, lifetimeSeconds, ticketAgeAdd, maxEarlyDataSize, serverName };
  validateState(state);
  return state;
}

/** AES-128-GCM seal: opaque ticket = random 12-byte nonce || ciphertext || tag. */
export async function sealTicketState(stek: Uint8Array, state: TicketState): Promise<Uint8Array> {
  if (stek.length !== AES128_KEY_BYTES) throw new Error('STEK must be a 16-byte AES-128 key');
  const nonce = randomBytes(AEAD_IV_BYTES);
  const ciphertext = await aesGcmEncrypt(stek, nonce, encodeTicketState(state), TICKET_AAD);
  return concatBytes(nonce, ciphertext);
}

/** Authenticate and open the opaque ticket. AES-GCM failure yields no plaintext. */
export async function openTicketState(stek: Uint8Array, opaqueTicket: Uint8Array): Promise<TicketState> {
  if (stek.length !== AES128_KEY_BYTES) throw new Error('STEK must be a 16-byte AES-128 key');
  if (opaqueTicket.length <= AEAD_IV_BYTES + 16) throw new Error('opaque ticket is too short');
  const nonce = opaqueTicket.subarray(0, AEAD_IV_BYTES);
  const ciphertext = opaqueTicket.subarray(AEAD_IV_BYTES);
  const plaintext = await aesGcmDecrypt(stek, nonce, ciphertext, TICKET_AAD);
  return decodeTicketState(plaintext);
}

/** Encode the RFC 9846 §4.7.1 fields, including the `early_data` extension. */
export function serializeNewSessionTicket(fields: Omit<NewSessionTicket, 'wire'>): Uint8Array {
  if (fields.ticketLifetime > MAX_TICKET_LIFETIME_SECONDS) throw new Error('ticket_lifetime exceeds seven days');
  const earlyDataExtension = concatBytes(u16(EXT_EARLY_DATA), u16(4), u32(fields.maxEarlyDataSize));
  const body = concatBytes(
    u32(fields.ticketLifetime),
    u32(fields.ticketAgeAdd),
    vec(fields.ticketNonce, 1),
    vec(fields.ticket, 2),
    vec(earlyDataExtension, 2),
  );
  return concatBytes(new Uint8Array([HANDSHAKE_NEW_SESSION_TICKET]), u24(body.length), body);
}

export function makeNewSessionTicket(fields: Omit<NewSessionTicket, 'wire'>): NewSessionTicket {
  return { ...fields, wire: serializeNewSessionTicket(fields) };
}

export function randomTicketAgeAdd(): number {
  const bytes = randomBytes(4);
  return ((bytes[0]! * 0x1000000) + (bytes[1]! << 16) + (bytes[2]! << 8) + bytes[3]!) >>> 0;
}

/** RFC 9846 §4.3.11.1: age in milliseconds plus ticket_age_add, modulo 2^32. */
export function obfuscateTicketAge(ageMs: number, ticketAgeAdd: number): number {
  if (!Number.isFinite(ageMs) || ageMs < 0) throw new Error('ticket age must be non-negative');
  return ((Math.floor(ageMs) >>> 0) + (ticketAgeAdd >>> 0)) >>> 0;
}

export function recoverTicketAge(obfuscatedAge: number, ticketAgeAdd: number): number {
  return ((obfuscatedAge >>> 0) - (ticketAgeAdd >>> 0)) >>> 0;
}

export function ticketIsExpired(state: TicketState, nowMs: number): boolean {
  return nowMs - state.issuedAtMs > state.lifetimeSeconds * 1_000;
}
