/**
 * Post-compromise attack using exactly recorded wire bytes plus a leaked STEK.
 * No endpoint PSK, X25519 private key, or live-session object is accepted.
 */
import { parsePskClientHello, type PskMode } from '../clienthello-psk';
import { deriveResumptionSchedule, verifyResumptionBinder } from '../resumption';
import { openTicketState } from '../ticket';
import { openApplicationRecord } from '../zerortt';

export interface RecordedResumedSession {
  mode: PskMode;
  clientHello: Uint8Array;
  serverHello: Uint8Array;
  transcriptToServerFinished: Uint8Array;
  earlyDataRecord: Uint8Array;
  oneRttRecord: Uint8Array;
}

export interface StekLeakResult {
  recoveredPsk: Uint8Array;
  binderValid: boolean;
  earlyDataReadable: boolean;
  earlyPlaintext: string;
  oneRttReadable: boolean;
  oneRttPlaintext: string;
}

export async function exploitLeakedStek(
  recorded: RecordedResumedSession,
  leakedStek: Uint8Array,
): Promise<StekLeakResult> {
  const hello = parsePskClientHello(recorded.clientHello);
  const ticket = await openTicketState(leakedStek, hello.identity);
  const binderValid = await verifyResumptionBinder(ticket.psk, hello.truncated, hello.binder);

  const wrongDheGuess = new Uint8Array(32);
  const schedule = await deriveResumptionSchedule({
    psk: ticket.psk,
    mode: recorded.mode,
    dheSharedSecret: recorded.mode === 'psk_dhe_ke' ? wrongDheGuess : undefined,
    clientHello: recorded.clientHello,
    serverHello: recorded.serverHello,
    transcriptToServerFinished: recorded.transcriptToServerFinished,
  });

  let earlyPlaintext = '';
  let earlyDataReadable = false;
  try {
    const opened = await openApplicationRecord(schedule.clientEarlyTrafficSecret, recorded.earlyDataRecord);
    earlyPlaintext = new TextDecoder('utf-8', { fatal: true }).decode(opened);
    earlyDataReadable = true;
  } catch {
    earlyDataReadable = false;
  }

  let oneRttPlaintext = '';
  let oneRttReadable = false;
  try {
    const opened = await openApplicationRecord(
      schedule.clientApplicationTrafficSecret,
      recorded.oneRttRecord,
    );
    oneRttPlaintext = new TextDecoder('utf-8', { fatal: true }).decode(opened);
    oneRttReadable = true;
  } catch {
    oneRttReadable = false;
  }

  return {
    recoveredPsk: ticket.psk,
    binderValid,
    earlyDataReadable,
    earlyPlaintext,
    oneRttReadable,
    oneRttPlaintext,
  };
}
