/** Server-side 0-RTT admission policies from RFC 9846 §§8.1–8.3. */
import { acceptWithoutReplayProtection } from './broken/no-anti-replay';
import { parsePskClientHello } from './clienthello-psk';
import { deriveSecret, equalBytes, hkdfExtract, sha256, toHex, utf8 } from './primitives';
import { verifyResumptionBinder } from './resumption';
import { openTicketState, recoverTicketAge, ticketIsExpired } from './ticket';
import { openApplicationRecord } from './zerortt';

export type ReplayConfiguration =
  | 'no-anti-replay'
  | 'single-use-ticket'
  | 'clienthello-recording'
  | 'freshness-window'
  | 'ignore-0rtt';

export const DEFAULT_REPLAY_CONFIGURATION: ReplayConfiguration = 'single-use-ticket';

export const REPLAY_CONFIGURATIONS: readonly {
  id: ReplayConfiguration;
  label: string;
  broken?: boolean;
}[] = [
  { id: 'single-use-ticket', label: 'Single-use ticket' },
  { id: 'clienthello-recording', label: 'ClientHello recording' },
  { id: 'freshness-window', label: 'Freshness window' },
  { id: 'ignore-0rtt', label: 'Ignore 0-RTT' },
  { id: 'no-anti-replay', label: 'No anti-replay', broken: true },
];

export interface RecordedEarlyFlight {
  /** Recorded wire bytes only; no PSK or endpoint secret is carried here. */
  clientHello: Uint8Array;
  earlyDataRecord: Uint8Array;
}

export interface ReplayStores {
  usedTickets: Set<string>;
  clientHellos: Set<string>;
}

export interface AdmissionResult {
  region: string;
  ticketValid: boolean;
  binderValid: boolean;
  earlyDataDecrypted: boolean;
  accepted0Rtt: boolean;
  executedPayment: boolean;
  oneRttFallback: boolean;
  abortField: string;
  reason: string;
  plaintext: string;
}

export interface ReplayLogEntry extends AdmissionResult {
  arrival: 'original' | 'replay';
}

export class EarlyDataServer {
  readonly log: ReplayLogEntry[] = [];
  executedPayments = 0;
  readonly region: string;
  private readonly configuration: ReplayConfiguration;
  private readonly stek: Uint8Array;
  private readonly stores: ReplayStores;
  private readonly freshnessToleranceMs: number;

  constructor(
    region: string,
    configuration: ReplayConfiguration,
    stek: Uint8Array,
    stores: ReplayStores = { usedTickets: new Set(), clientHellos: new Set() },
    freshnessToleranceMs = 10_000,
  ) {
    this.region = region;
    this.configuration = configuration;
    this.stek = stek;
    this.stores = stores;
    this.freshnessToleranceMs = freshnessToleranceMs;
  }

  async receive(
    flight: RecordedEarlyFlight,
    arrival: 'original' | 'replay',
    arrivalTimeMs: number,
  ): Promise<AdmissionResult> {
    const base = {
      region: this.region,
      ticketValid: false,
      binderValid: false,
      earlyDataDecrypted: false,
      accepted0Rtt: false,
      executedPayment: false,
      oneRttFallback: false,
      abortField: '',
      reason: '',
      plaintext: '',
    };

    let hello;
    try {
      hello = parsePskClientHello(flight.clientHello);
    } catch (error) {
      return this.record(arrival, { ...base, abortField: 'ClientHello', reason: message(error) });
    }

    let ticket;
    try {
      ticket = await openTicketState(this.stek, hello.identity);
      base.ticketValid = true;
    } catch {
      return this.record(arrival, {
        ...base,
        oneRttFallback: true,
        abortField: 'pre_shared_key.identities[0]',
        reason: 'ticket AEAD rejected; continue with a full handshake',
      });
    }

    if (ticketIsExpired(ticket, arrivalTimeMs)) {
      return this.record(arrival, {
        ...base,
        ticketValid: false,
        oneRttFallback: true,
        reason: 'ticket_lifetime expired; continue with a full handshake',
      });
    }

    // SECURITY ORDERING: recover the PSK from the authenticated ticket, then
    // verify the binder before any call that can decrypt early application data.
    const binderValid = await verifyResumptionBinder(ticket.psk, hello.truncated, hello.binder);
    base.binderValid = binderValid;
    if (!binderValid) {
      return this.record(arrival, {
        ...base,
        abortField: 'pre_shared_key.binders[0]',
        reason: 'pre_shared_key.binders[0] mismatch; no early plaintext released',
      });
    }

    const encodedPayloadBytes = Math.max(0, flight.earlyDataRecord.length - 5 - 16 - 1);
    if (encodedPayloadBytes > ticket.maxEarlyDataSize) {
      return this.record(arrival, { ...base, reason: 'max_early_data_size exceeded' });
    }

    if (this.configuration === 'freshness-window') {
      const clientAge = recoverTicketAge(hello.obfuscatedTicketAge, ticket.ticketAgeAdd);
      const serverAge = Math.max(0, arrivalTimeMs - ticket.issuedAtMs);
      if (Math.abs(clientAge - serverAge) > this.freshnessToleranceMs) {
        return this.record(arrival, {
          ...base,
          oneRttFallback: true,
          reason: 'outside the freshness window; reject 0-RTT but allow 1-RTT',
        });
      }
    }

    if (this.configuration === 'ignore-0rtt') {
      return this.record(arrival, {
        ...base,
        oneRttFallback: true,
        reason: 'server ignored early_data; client may resend after the handshake',
      });
    }

    const ticketId = toHex(hello.identity);
    if (this.configuration === 'single-use-ticket') {
      if (this.stores.usedTickets.has(ticketId)) {
        return this.record(arrival, { ...base, oneRttFallback: true, reason: 'single-use ticket already consumed' });
      }
      this.stores.usedTickets.add(ticketId);
    }

    if (this.configuration === 'clienthello-recording') {
      const fingerprint = toHex(await sha256(hello.full));
      if (this.stores.clientHellos.has(fingerprint)) {
        return this.record(arrival, {
          ...base,
          oneRttFallback: true,
          reason: 'matching validated ClientHello already recorded in this region',
        });
      }
      this.stores.clientHellos.add(fingerprint);
    }

    if (this.configuration === 'no-anti-replay') {
      // The intentionally unsafe decision lives in src/broken/no-anti-replay.ts.
      acceptWithoutReplayProtection();
    }

    let plaintext: Uint8Array;
    try {
      const pskEarlySecret = await hkdfExtract(new Uint8Array(32), ticket.psk);
      const clientEarlyTrafficSecret = await deriveSecret(pskEarlySecret, 'c e traffic', hello.full);
      plaintext = await openApplicationRecord(clientEarlyTrafficSecret, flight.earlyDataRecord);
    } catch {
      return this.record(arrival, { ...base, reason: 'early-data AEAD rejected' });
    }

    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const isPayment = text.startsWith('POST /pay-bill ') && equalBytes(utf8(text), plaintext);
    if (isPayment) this.executedPayments += 1;
    return this.record(arrival, {
      ...base,
      earlyDataDecrypted: true,
      accepted0Rtt: true,
      executedPayment: isPayment,
      reason: isPayment ? 'authenticated early data accepted and payment executed' : 'early data accepted',
      plaintext: text,
    });
  }

  /** Used only after a completed handshake in the ignore-0RTT configuration. */
  recordOneRttExecution(plaintext: Uint8Array): void {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const executedPayment = text.startsWith('POST /pay-bill ');
    if (executedPayment) this.executedPayments += 1;
    this.log.push({
      arrival: 'original',
      region: this.region,
      ticketValid: true,
      binderValid: true,
      earlyDataDecrypted: false,
      accepted0Rtt: false,
      executedPayment,
      oneRttFallback: true,
      abortField: '',
      reason: 'post-handshake 1-RTT resend executed under a server-nonce-bound key',
      plaintext: text,
    });
  }

  private record(arrival: 'original' | 'replay', result: AdmissionResult): AdmissionResult {
    this.log.push({ arrival, ...result });
    return result;
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
