/** TLS 1.3 PSK/resumption key schedule (RFC 9846 §§4.3.11, 4.7.1, 7.1). */
import {
  HASH_SIZE,
  concatBytes,
  deriveSecret,
  equalBytes,
  hkdfExpandLabel,
  hkdfExtract,
  hmacSha256,
  randomBytes,
  sha256,
} from './primitives';
import {
  serializePskClientHello,
  type PskClientHello,
  type PskClientHelloInput,
  type PskMode,
} from './clienthello-psk';
import {
  DEFAULT_MAX_EARLY_DATA,
  DEFAULT_TICKET_LIFETIME_SECONDS,
  makeNewSessionTicket,
  randomTicketAgeAdd,
  sealTicketState,
  type NewSessionTicket,
} from './ticket';
import { pskOnlyAsymmetricInput } from './broken/psk-ke';

const ZEROS = new Uint8Array(HASH_SIZE);
const EMPTY = new Uint8Array();

async function deriveSecretFromHash(
  secret: Uint8Array,
  label: string,
  transcriptHash: Uint8Array,
): Promise<Uint8Array> {
  if (transcriptHash.length !== HASH_SIZE) throw new Error('transcript hash must be SHA-256 (32 bytes)');
  return hkdfExpandLabel(secret, label, transcriptHash, HASH_SIZE);
}

/** Derive-Secret(Main Secret, "res master", Hash(CH..client Finished)). */
export async function deriveResumptionSecret(
  mainSecret: Uint8Array,
  transcriptToClientFinishedHash: Uint8Array,
): Promise<Uint8Array> {
  return deriveSecretFromHash(mainSecret, 'res master', transcriptToClientFinishedHash);
}

/** HKDF-Expand-Label(resumption_secret, "resumption", ticket_nonce, Hash.length). */
export async function deriveTicketPsk(
  resumptionSecret: Uint8Array,
  ticketNonce: Uint8Array,
): Promise<Uint8Array> {
  return hkdfExpandLabel(resumptionSecret, 'resumption', ticketNonce, HASH_SIZE);
}

export interface BinderDerivation {
  earlySecret: Uint8Array;
  binderKey: Uint8Array;
  finishedKey: Uint8Array;
  transcriptHash: Uint8Array;
  binder: Uint8Array;
}

/**
 * The resumption binder is a Finished-style HMAC over Hash(Truncate(CH)).
 * `deriveSecret(..., "res binder", empty)` intentionally reuses the existing
 * lab helper; there is no second HKDF implementation.
 */
export async function deriveResumptionBinder(
  psk: Uint8Array,
  truncatedClientHello: Uint8Array,
): Promise<BinderDerivation> {
  const earlySecret = await hkdfExtract(ZEROS, psk);
  const binderKey = await deriveSecret(earlySecret, 'res binder', EMPTY);
  const finishedKey = await hkdfExpandLabel(binderKey, 'finished', EMPTY, HASH_SIZE);
  const transcriptHash = await sha256(truncatedClientHello);
  const binder = await hmacSha256(finishedKey, transcriptHash);
  return { earlySecret, binderKey, finishedKey, transcriptHash, binder };
}

export async function verifyResumptionBinder(
  psk: Uint8Array,
  truncatedClientHello: Uint8Array,
  receivedBinder: Uint8Array,
): Promise<boolean> {
  const expected = await deriveResumptionBinder(psk, truncatedClientHello);
  return equalBytes(expected.binder, receivedBinder);
}

/** Build once with the fixed-length placeholder, then MAC the exact truncated bytes. */
export async function buildBoundPskClientHello(
  input: Omit<PskClientHelloInput, 'binder'>,
  psk: Uint8Array,
): Promise<{ hello: PskClientHello; binder: BinderDerivation }> {
  const placeholder = serializePskClientHello({ ...input, binder: ZEROS });
  const binder = await deriveResumptionBinder(psk, placeholder.truncated);
  return { hello: serializePskClientHello({ ...input, binder: binder.binder }), binder };
}

export interface ResumptionSchedule {
  mode: PskMode;
  earlySecret: Uint8Array;
  clientEarlyTrafficSecret: Uint8Array;
  handshakeSecret: Uint8Array;
  clientHandshakeTrafficSecret: Uint8Array;
  serverHandshakeTrafficSecret: Uint8Array;
  mainSecret: Uint8Array;
  clientApplicationTrafficSecret: Uint8Array;
  serverApplicationTrafficSecret: Uint8Array;
}

export interface ResumptionScheduleInput {
  psk: Uint8Array;
  mode: PskMode;
  /** Required for psk_dhe_ke and ignored/rejected for psk_ke. */
  dheSharedSecret?: Uint8Array;
  clientHello: Uint8Array;
  serverHello: Uint8Array;
  transcriptToServerFinished: Uint8Array;
}

/**
 * Run the PSK-aware schedule. psk_ke feeds Hash.length zeros as the asymmetric
 * input; psk_dhe_ke feeds the fresh X25519 result. This function does not alter
 * deriveKeySchedule(), preserving the original full-handshake path bit-for-bit.
 */
export async function deriveResumptionSchedule(input: ResumptionScheduleInput): Promise<ResumptionSchedule> {
  const earlySecret = await hkdfExtract(ZEROS, input.psk);
  const clientEarlyTrafficSecret = await deriveSecret(earlySecret, 'c e traffic', input.clientHello);
  const emptyHash = await sha256(EMPTY);
  const derivedForHandshake = await hkdfExpandLabel(earlySecret, 'derived', emptyHash, HASH_SIZE);

  let asymmetricInput: Uint8Array;
  if (input.mode === 'psk_dhe_ke') {
    if (!input.dheSharedSecret || input.dheSharedSecret.length !== HASH_SIZE) {
      throw new Error('psk_dhe_ke requires a 32-byte X25519 shared secret');
    }
    asymmetricInput = input.dheSharedSecret;
  } else {
    if (input.dheSharedSecret) throw new Error('psk_ke MUST NOT mix a key_share value');
    asymmetricInput = pskOnlyAsymmetricInput(HASH_SIZE);
  }

  const handshakeSecret = await hkdfExtract(derivedForHandshake, asymmetricInput);
  const helloHash = await sha256(concatBytes(input.clientHello, input.serverHello));
  const clientHandshakeTrafficSecret = await deriveSecretFromHash(handshakeSecret, 'c hs traffic', helloHash);
  const serverHandshakeTrafficSecret = await deriveSecretFromHash(handshakeSecret, 's hs traffic', helloHash);

  const derivedForMain = await hkdfExpandLabel(handshakeSecret, 'derived', emptyHash, HASH_SIZE);
  const mainSecret = await hkdfExtract(derivedForMain, ZEROS);
  const serverFinishedHash = await sha256(input.transcriptToServerFinished);
  const clientApplicationTrafficSecret = await deriveSecretFromHash(mainSecret, 'c ap traffic', serverFinishedHash);
  const serverApplicationTrafficSecret = await deriveSecretFromHash(mainSecret, 's ap traffic', serverFinishedHash);

  return {
    mode: input.mode,
    earlySecret,
    clientEarlyTrafficSecret,
    handshakeSecret,
    clientHandshakeTrafficSecret,
    serverHandshakeTrafficSecret,
    mainSecret,
    clientApplicationTrafficSecret,
    serverApplicationTrafficSecret,
  };
}

export interface IssuedResumptionTicket {
  resumptionSecret: Uint8Array;
  psk: Uint8Array;
  ticket: NewSessionTicket;
}

/** Issue one RFC-shaped NewSessionTicket backed by the lab's AES-GCM ticket format. */
export async function issueResumptionTicket(options: {
  mainSecret: Uint8Array;
  transcriptToClientFinishedHash: Uint8Array;
  stek: Uint8Array;
  serverName: string;
  issuedAtMs: number;
  lifetimeSeconds?: number;
  maxEarlyDataSize?: number;
}): Promise<IssuedResumptionTicket> {
  const lifetimeSeconds = options.lifetimeSeconds ?? DEFAULT_TICKET_LIFETIME_SECONDS;
  const maxEarlyDataSize = options.maxEarlyDataSize ?? DEFAULT_MAX_EARLY_DATA;
  const resumptionSecret = await deriveResumptionSecret(
    options.mainSecret,
    options.transcriptToClientFinishedHash,
  );
  const ticketNonce = randomBytes(8);
  const psk = await deriveTicketPsk(resumptionSecret, ticketNonce);
  const ticketAgeAdd = randomTicketAgeAdd();
  const opaqueTicket = await sealTicketState(options.stek, {
    psk,
    issuedAtMs: options.issuedAtMs,
    lifetimeSeconds,
    ticketAgeAdd,
    maxEarlyDataSize,
    serverName: options.serverName,
  });
  const ticket = makeNewSessionTicket({
    ticketLifetime: lifetimeSeconds,
    ticketAgeAdd,
    ticketNonce,
    ticket: opaqueTicket,
    maxEarlyDataSize,
  });
  return { resumptionSecret, psk, ticket };
}
