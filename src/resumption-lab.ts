/** End-to-end resumption scenarios consumed by the UI and phase checks. */
import { recordEarlyFlight, replayEarlyFlight } from './attack/replay';
import {
  exploitLeakedStek,
  type RecordedResumedSession,
  type StekLeakResult,
} from './attack/stek-leak';
import {
  DEFAULT_REPLAY_CONFIGURATION,
  EarlyDataServer,
  type AdmissionResult,
  type RecordedEarlyFlight,
  type ReplayConfiguration,
  type ReplayLogEntry,
} from './antireplay';
import {
  flipOfferedIdentity,
  flipPskBinder,
  parsePskClientHello,
  selectPskMode,
  type PskClientHello,
  type PskMode,
} from './clienthello-psk';
import type { HandshakeTrace } from './handshake';
import { finishedMac } from './keyschedule';
import {
  AES128_KEY_BYTES,
  concatBytes,
  equalBytes,
  randomBytes,
  sha256,
  toHex,
  utf8,
  x25519Keygen,
  x25519SharedSecret,
} from './primitives';
import {
  buildBoundPskClientHello,
  deriveResumptionBinder,
  deriveResumptionSchedule,
  issueResumptionTicket,
  verifyResumptionBinder,
  type BinderDerivation,
  type IssuedResumptionTicket,
  type ResumptionSchedule,
} from './resumption';
import { obfuscateTicketAge, openTicketState } from './ticket';
import { openApplicationRecord, sealApplicationRecord, type ProtectedApplicationRecord } from './zerortt';

export const DEFAULT_PSK_MODE: PskMode = 'psk_dhe_ke';
export const DEFAULT_REPLAY_MODE: ReplayConfiguration = DEFAULT_REPLAY_CONFIGURATION;
export const PAYMENT_REQUEST = 'POST /pay-bill HTTP/1.1\r\nIdempotency-Key: absent\r\nAmount: 125.00\r\n\r\n';
export const ONE_RTT_REQUEST = 'POST /pay-bill HTTP/1.1\r\nMode: after-handshake\r\nAmount: 125.00\r\n\r\n';

const CLIENT_TICKET_AGE_MS = 1_000;
const INSIDE_REPLAY_DELAY_MS = 1_000;
const OUTSIDE_REPLAY_DELAY_MS = 30_000;

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function u24(value: number): Uint8Array {
  return new Uint8Array([(value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function vec(payload: Uint8Array, width: 1 | 2): Uint8Array {
  if (width === 1) return concatBytes(new Uint8Array([payload.length]), payload);
  return concatBytes(u16(payload.length), payload);
}

function extension(type: number, data: Uint8Array): Uint8Array {
  return concatBytes(u16(type), vec(data, 2));
}

function handshake(type: number, body: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([type]), u24(body.length), body);
}

function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) throw new Error('invalid hex');
  return new Uint8Array(hex.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16)));
}

/** Minimal real ServerHello: selected PSK plus a key_share only for psk_dhe_ke. */
export function serializeResumptionServerHello(
  random: Uint8Array,
  mode: PskMode,
  serverKeyShare?: Uint8Array,
): Uint8Array {
  if (random.length !== 32) throw new Error('ServerHello.random must be 32 bytes');
  if (mode === 'psk_dhe_ke' && serverKeyShare?.length !== 32) throw new Error('psk_dhe_ke needs X25519 key_share');
  if (mode === 'psk_ke' && serverKeyShare) throw new Error('psk_ke server MUST NOT send key_share');
  const supportedVersions = extension(0x002b, u16(0x0304));
  const selectedPsk = extension(0x0029, u16(0));
  const keyShare = mode === 'psk_dhe_ke'
    ? extension(0x0033, concatBytes(u16(0x001d), vec(serverKeyShare!, 2)))
    : new Uint8Array();
  const extensions = concatBytes(supportedVersions, selectedPsk, keyShare);
  const body = concatBytes(
    u16(0x0303),
    random,
    vec(new Uint8Array(), 1),
    u16(0x1301),
    new Uint8Array([0]),
    vec(extensions, 2),
  );
  return handshake(0x02, body);
}

function serializeResumedEncryptedExtensions(): Uint8Array {
  return handshake(0x08, vec(extension(0x002a, new Uint8Array()), 2));
}

export interface ResumedSession {
  mode: PskMode;
  clientHello: PskClientHello;
  binder: BinderDerivation;
  binderValid: boolean;
  serverHello: Uint8Array;
  serverRandom: Uint8Array;
  serverSentKeyShare: boolean;
  schedule: ResumptionSchedule;
  transcriptToServerFinished: Uint8Array;
  earlyRecord: ProtectedApplicationRecord;
  oneRttRecord: ProtectedApplicationRecord;
  recorded: RecordedResumedSession;
}

export interface ResumptionLab {
  stek: Uint8Array;
  issuedAtMs: number;
  issued: IssuedResumptionTicket;
  sessions: Record<PskMode, ResumedSession>;
}

async function createResumedSession(
  lab: Pick<ResumptionLab, 'issued' | 'issuedAtMs'>,
  mode: PskMode,
): Promise<ResumedSession> {
  const clientKeys = x25519Keygen();
  const age = obfuscateTicketAge(CLIENT_TICKET_AGE_MS, lab.issued.ticket.ticketAgeAdd);
  const { hello, binder } = await buildBoundPskClientHello(
    {
      random: randomBytes(32),
      identity: lab.issued.ticket.ticket,
      obfuscatedTicketAge: age,
      mode,
      keyShare: clientKeys.publicKey,
    },
    lab.issued.psk,
  );

  const serverRandom = randomBytes(32);
  let serverHello: Uint8Array;
  let sharedSecret: Uint8Array | undefined;
  if (mode === 'psk_dhe_ke') {
    const serverKeys = x25519Keygen();
    sharedSecret = x25519SharedSecret(serverKeys.secretKey, clientKeys.publicKey);
    const clientShared = x25519SharedSecret(clientKeys.secretKey, serverKeys.publicKey);
    if (!equalBytes(sharedSecret, clientShared)) throw new Error('resumption X25519 outputs differ');
    serverHello = serializeResumptionServerHello(serverRandom, mode, serverKeys.publicKey);
  } else {
    serverHello = serializeResumptionServerHello(serverRandom, mode);
  }

  const encryptedExtensions = serializeResumedEncryptedExtensions();
  const provisional = await deriveResumptionSchedule({
    psk: lab.issued.psk,
    mode,
    dheSharedSecret: sharedSecret,
    clientHello: hello.full,
    serverHello,
    transcriptToServerFinished: concatBytes(hello.full, serverHello),
  });
  const beforeFinished = concatBytes(hello.full, serverHello, encryptedExtensions);
  const verifyData = await finishedMac(provisional.serverHandshakeTrafficSecret, await sha256(beforeFinished));
  const serverFinished = handshake(0x14, verifyData);
  const transcriptToServerFinished = concatBytes(beforeFinished, serverFinished);
  const schedule = await deriveResumptionSchedule({
    psk: lab.issued.psk,
    mode,
    dheSharedSecret: sharedSecret,
    clientHello: hello.full,
    serverHello,
    transcriptToServerFinished,
  });

  const earlyRecord = await sealApplicationRecord(schedule.clientEarlyTrafficSecret, utf8(PAYMENT_REQUEST));
  const oneRttRecord = await sealApplicationRecord(schedule.clientApplicationTrafficSecret, utf8(ONE_RTT_REQUEST));
  const recorded: RecordedResumedSession = {
    mode,
    clientHello: Uint8Array.from(hello.full),
    serverHello: Uint8Array.from(serverHello),
    transcriptToServerFinished: Uint8Array.from(transcriptToServerFinished),
    earlyDataRecord: Uint8Array.from(earlyRecord.wire),
    oneRttRecord: Uint8Array.from(oneRttRecord.wire),
  };
  return {
    mode,
    clientHello: hello,
    binder,
    binderValid: await verifyResumptionBinder(lab.issued.psk, hello.truncated, hello.binder),
    serverHello,
    serverRandom,
    serverSentKeyShare: mode === 'psk_dhe_ke',
    schedule,
    transcriptToServerFinished,
    earlyRecord,
    oneRttRecord,
    recorded,
  };
}

export class ResumptionUnavailableError extends Error {}

export async function createResumptionLab(fullHandshake: HandshakeTrace): Promise<ResumptionLab> {
  if (!fullHandshake.chainVerdict.valid || !fullHandshake.certificateVerifyValid ||
      !fullHandshake.serverFinishedValid || !fullHandshake.clientFinishedValid || !fullHandshake.sharedSecretAgrees) {
    throw new ResumptionUnavailableError('A failed full handshake cannot establish a resumption session or issue a usable ticket.');
  }
  const issuedAtMs = Date.now();
  const stek = randomBytes(AES128_KEY_BYTES);
  const clientFinishedHashHex = fullHandshake.steps.find((step) => step.id === 'client-finished')?.transcriptHashHex;
  if (!clientFinishedHashHex) throw new Error('full handshake did not expose the client Finished transcript hash');
  const issued = await issueResumptionTicket({
    mainSecret: fullHandshake.schedule.masterSecret,
    transcriptToClientFinishedHash: fromHex(clientFinishedHashHex),
    stek,
    serverName: fullHandshake.serverName,
    issuedAtMs,
  });
  const partial = { issued, issuedAtMs };
  const pskDhe = await createResumedSession(partial, 'psk_dhe_ke');
  const pskOnly = await createResumedSession(partial, 'psk_ke');
  return { stek, issuedAtMs, issued, sessions: { psk_dhe_ke: pskDhe, psk_ke: pskOnly } };
}

export interface BinderProbe {
  kind: 'genuine' | 'identity' | 'binder';
  ticketValid: boolean;
  valid: boolean;
  field: string;
  earlyPlaintextReleased: boolean;
  clientHello: PskClientHello;
}

export async function runBinderProbe(
  lab: ResumptionLab,
  mode: PskMode,
  kind: BinderProbe['kind'],
): Promise<BinderProbe> {
  const session = lab.sessions[mode];
  const wire = kind === 'identity' ? flipOfferedIdentity(session.clientHello.full)
    : kind === 'binder' ? flipPskBinder(session.clientHello.full) : session.clientHello.full;
  const parsed = parsePskClientHello(wire);
  // Use the real server path: authenticate the offered ticket before checking
  // its binder. This probe's policy declines early data even for a good binder.
  const server = new EarlyDataServer('binder probe', 'ignore-0rtt', lab.stek);
  const admission = await server.receive(
    { clientHello: wire, earlyDataRecord: session.earlyRecord.wire },
    'original', lab.issuedAtMs + CLIENT_TICKET_AGE_MS,
  );
  return {
    kind,
    ticketValid: admission.ticketValid,
    valid: admission.binderValid,
    field: admission.abortField,
    earlyPlaintextReleased: admission.earlyDataDecrypted || admission.plaintext.length > 0,
    clientHello: parsed,
  };
}

export interface LeakComparison {
  pskKe: StekLeakResult;
  pskDhe: StekLeakResult;
}

export async function runStekLeak(lab: ResumptionLab): Promise<LeakComparison> {
  const pskKe = await exploitLeakedStek(lab.sessions.psk_ke.recorded, lab.stek);
  const pskDhe = await exploitLeakedStek(lab.sessions.psk_dhe_ke.recorded, lab.stek);
  return { pskKe, pskDhe };
}

export interface ReplayScenario {
  configuration: ReplayConfiguration;
  regionA: { executedPayments: number; log: ReplayLogEntry[] };
  regionB: { executedPayments: number; log: ReplayLogEntry[] };
  first: AdmissionResult;
  replayA: AdmissionResult;
  replayB: AdmissionResult;
  outsideWindow: AdmissionResult | null;
  oneRttReplayRejected: boolean;
  verdictOk: boolean;
  verdict: string;
}

async function freshServerPair(
  lab: ResumptionLab,
  configuration: ReplayConfiguration,
): Promise<{ a: EarlyDataServer; b: EarlyDataServer }> {
  const sharedUsedTickets = new Set<string>();
  return {
    a: new EarlyDataServer('region A', configuration, lab.stek, {
      usedTickets: sharedUsedTickets,
      clientHellos: new Set(),
    }),
    b: new EarlyDataServer('region B', configuration, lab.stek, {
      usedTickets: sharedUsedTickets,
      clientHellos: new Set(),
    }),
  };
}

async function proveOneRttReplayRejected(lab: ResumptionLab): Promise<boolean> {
  const first = lab.sessions.psk_dhe_ke;
  const second = await createResumedSession({ issued: lab.issued, issuedAtMs: lab.issuedAtMs }, 'psk_dhe_ke');
  try {
    await openApplicationRecord(second.schedule.clientApplicationTrafficSecret, first.oneRttRecord.wire);
    return false;
  } catch {
    return !equalBytes(first.serverRandom, second.serverRandom);
  }
}

export async function runReplayScenario(
  lab: ResumptionLab,
  configuration: ReplayConfiguration,
): Promise<ReplayScenario> {
  const session = lab.sessions.psk_dhe_ke;
  const original: RecordedEarlyFlight = {
    clientHello: session.clientHello.full,
    earlyDataRecord: session.earlyRecord.wire,
  };
  const recording = recordEarlyFlight(original);
  const replay = replayEarlyFlight(recording);
  const { a, b } = await freshServerPair(lab, configuration);
  const originalTime = lab.issuedAtMs + CLIENT_TICKET_AGE_MS;
  const first = await a.receive(original, 'original', originalTime);
  const replayA = await a.receive(replay, 'replay', originalTime + INSIDE_REPLAY_DELAY_MS);
  const replayB = await b.receive(replay, 'replay', originalTime + INSIDE_REPLAY_DELAY_MS);

  let outsideWindow: AdmissionResult | null = null;
  if (configuration === 'freshness-window') {
    const outside = (await freshServerPair(lab, configuration)).a;
    await outside.receive(original, 'original', originalTime);
    outsideWindow = await outside.receive(replay, 'replay', originalTime + OUTSIDE_REPLAY_DELAY_MS);
  }

  let oneRttReplayRejected = false;
  if (configuration === 'ignore-0rtt') {
    const opened = await openApplicationRecord(session.schedule.clientApplicationTrafficSecret, session.oneRttRecord.wire);
    a.recordOneRttExecution(opened);
    oneRttReplayRejected = await proveOneRttReplayRejected(lab);
  }

  let verdictOk: boolean;
  let verdict: string;
  switch (configuration) {
    case 'no-anti-replay':
      verdictOk = a.executedPayments < 2;
      verdict = a.executedPayments === 2 ? 'ALARM — EXECUTED TWICE' : 'REPLAY REFUSED';
      break;
    case 'single-use-ticket':
      verdictOk = a.executedPayments === 1 && !replayA.accepted0Rtt && !replayB.accepted0Rtt;
      verdict = verdictOk ? 'REPLAY REFUSED — TICKET ALREADY USED' : 'ALARM — REPLAY ACCEPTED';
      break;
    case 'clienthello-recording':
      verdictOk = !replayA.accepted0Rtt && !replayB.accepted0Rtt;
      verdict = replayB.executedPayment
        ? 'ALARM — REGION B EXECUTED'
        : 'REPLAY REFUSED — CLIENTHELLO RECORDED';
      break;
    case 'freshness-window':
      verdictOk = a.executedPayments < 2;
      verdict = a.executedPayments === 2
        ? 'ALARM — INSIDE WINDOW EXECUTED TWICE'
        : 'REPLAY REFUSED — OUTSIDE WINDOW';
      break;
    case 'ignore-0rtt':
      verdictOk = a.executedPayments === 1 && oneRttReplayRejected;
      verdict = verdictOk ? 'REPLAY REFUSED — 1-RTT BINDS SERVER NONCE' : 'ALARM — 1-RTT REPLAYED';
      break;
  }

  return {
    configuration,
    regionA: { executedPayments: a.executedPayments, log: [...a.log] },
    regionB: { executedPayments: b.executedPayments, log: [...b.log] },
    first,
    replayA,
    replayB,
    outsideWindow,
    oneRttReplayRejected,
    verdictOk,
    verdict,
  };
}

export interface EdgeCases {
  expiredTicket: AdmissionResult;
  tamperedTicket: AdmissionResult;
  untruncatedBinderValid: boolean;
  pskKeRejectedByDheOnlyServer: boolean;
  freshnessFallback: AdmissionResult;
}

export async function runEdgeCases(lab: ResumptionLab): Promise<EdgeCases> {
  const session = lab.sessions.psk_dhe_ke;
  const original = { clientHello: session.clientHello.full, earlyDataRecord: session.earlyRecord.wire };
  const expiredServer = new EarlyDataServer('region A', 'single-use-ticket', lab.stek);
  const expiredTicket = await expiredServer.receive(
    original,
    'replay',
    lab.issuedAtMs + (lab.issued.ticket.ticketLifetime + 1) * 1_000,
  );

  const tamperedWire = flipOfferedIdentity(session.clientHello.full);
  const tamperedServer = new EarlyDataServer('region A', 'single-use-ticket', lab.stek);
  const tamperedTicket = await tamperedServer.receive(
    { clientHello: tamperedWire, earlyDataRecord: session.earlyRecord.wire },
    'replay',
    lab.issuedAtMs + CLIENT_TICKET_AGE_MS,
  );

  const wrongBinder = await deriveResumptionBinder(lab.issued.psk, session.clientHello.full);
  const untruncatedBinderValid = await verifyResumptionBinder(
    lab.issued.psk,
    session.clientHello.truncated,
    wrongBinder.binder,
  );

  const freshness = await runReplayScenario(lab, 'freshness-window');
  if (!freshness.outsideWindow) throw new Error('freshness scenario omitted outside-window result');
  return {
    expiredTicket,
    tamperedTicket,
    untruncatedBinderValid,
    pskKeRejectedByDheOnlyServer: selectPskMode(['psk_ke'], ['psk_dhe_ke']) === null,
    freshnessFallback: freshness.outsideWindow,
  };
}

/** Test helper: prove the opaque ticket really contains the PSK the client derived. */
export async function ticketPskRoundTrip(lab: ResumptionLab): Promise<boolean> {
  const state = await openTicketState(lab.stek, lab.issued.ticket.ticket);
  return equalBytes(state.psk, lab.issued.psk) && toHex(state.psk) === toHex(lab.issued.psk);
}
