import { expect, test } from '@playwright/test';
import { EarlyDataServer, REPLAY_CONFIGURATIONS } from '../src/antireplay';
import { parsePskClientHello } from '../src/clienthello-psk';
import { runFullHandshake } from '../src/handshake';
import { deriveSecret, hkdfExtract, utf8 } from '../src/primitives';
import { buildBoundPskClientHello } from '../src/resumption';
import { createResumptionLab, PAYMENT_REQUEST, ResumptionUnavailableError } from '../src/resumption-lab';
import { obfuscateTicketAge, sealTicketState, serializeNewSessionTicket } from '../src/ticket';
import { sealApplicationRecord } from '../src/zerortt';

const issuedAtMs = 1_700_000_000_000;
const psk = new Uint8Array(32).fill(7);
const stek = new Uint8Array(16).fill(9);
const ticketAgeAdd = 0xfffffff0; // Exercise uint32 wrap in the age encoding.

async function flight(identity: Uint8Array, ageMs: number) {
  const { hello } = await buildBoundPskClientHello({
    random: new Uint8Array(32).fill(3), keyShare: new Uint8Array(32).fill(5),
    identity, mode: 'psk_dhe_ke', obfuscatedTicketAge: obfuscateTicketAge(ageMs, ticketAgeAdd),
  }, psk);
  const earlySecret = await hkdfExtract(new Uint8Array(32), psk);
  const trafficSecret = await deriveSecret(earlySecret, 'c e traffic', hello.full);
  const record = await sealApplicationRecord(trafficSecret, utf8(PAYMENT_REQUEST));
  return { clientHello: hello.full, earlyDataRecord: record.wire };
}

async function ticket(lifetimeSeconds = 86_400) {
  return sealTicketState(stek, {
    psk, issuedAtMs, lifetimeSeconds, ticketAgeAdd, maxEarlyDataSize: 4096, serverName: 'example.com',
  });
}

/** Independent wire walk, including every enclosing length, without the lab parser. */
function extensions(bytes: Uint8Array) {
  const wire = Buffer.from(bytes);
  expect(wire[0]).toBe(1);
  expect(wire.readUIntBE(1, 3)).toBe(wire.length - 4);
  let at = 4 + 2 + 32;
  at += 1 + wire[at]!;
  at += 2 + wire.readUInt16BE(at);
  at += 1 + wire[at]!;
  const lengthOffset = at;
  const end = at + 2 + wire.readUInt16BE(at);
  expect(end).toBe(wire.length);
  at += 2;
  const out: { type: number; header: number; body: Buffer }[] = [];
  while (at < end) {
    const length = wire.readUInt16BE(at + 2);
    expect(at + 4 + length).toBeLessThanOrEqual(end);
    out.push({ type: wire.readUInt16BE(at), header: at, body: wire.subarray(at + 4, at + 4 + length) });
    at += 4 + length;
  }
  expect(at).toBe(end);
  return { out, lengthOffset };
}

test('[verdict:hello-groups] every encoded key share has an advertised group and certificate fallback offers Ed25519', async () => {
  const original = await flight(await ticket(), 1000);
  const { out, lengthOffset } = extensions(original.clientHello);
  const groups = out.find((ext) => ext.type === 0x000a);
  expect(groups, 'key_share requires supported_groups').toBeDefined();
  expect(groups!.body.toString('hex')).toBe('0002001d');
  const share = out.find((ext) => ext.type === 0x0033)!;
  expect(share.body.readUInt16BE(0)).toBe(36);
  expect(share.body.readUInt16BE(2)).toBe(groups!.body.readUInt16BE(2));
  expect(out.find((ext) => ext.type === 0x000d)!.body.toString('hex')).toBe('00020807');
  expect(out.at(-1)!.type).toBe(0x0029);
  expect(parsePskClientHello(original.clientHello).mode).toBe('psk_dhe_ke');

  // A well-framed ClientHello with no supported_groups must also be refused.
  const absent = Buffer.concat([
    original.clientHello.subarray(0, groups!.header),
    original.clientHello.subarray(groups!.header + 4 + groups!.body.length),
  ]);
  absent.writeUIntBE(absent.length - 4, 1, 3);
  absent.writeUInt16BE(absent.length - lengthOffset - 2, lengthOffset);
  expect(() => parsePskClientHello(absent)).toThrow(/extensions/);
  const mismatched = Buffer.from(original.clientHello);
  mismatched.writeUInt16BE(0x0017, share.header + 6);
  expect(() => parsePskClientHello(mismatched)).toThrow(/not advertised/);
});

test('[verdict:ticket-freshness] every policy rejects a stale first arrival before decrypting or consuming its ticket', async () => {
  const identity = await ticket();
  const stale = await flight(identity, 1000);
  for (const { id } of REPLAY_CONFIGURATIONS) {
    const server = new EarlyDataServer('freshness test', id, stek);
    const result = await server.receive(stale, 'original', issuedAtMs + 3_600_000);
    expect(result.ticketValid, id).toBe(true);
    expect(result.binderValid, id).toBe(true);
    expect(result.earlyDataDecrypted, id).toBe(false);
    expect(result.executedPayment, id).toBe(false);
    expect(result.plaintext, id).toBe('');
    expect(result.oneRttFallback, id).toBe(true);
    expect(server.executedPayments, id).toBe(0);
    if (id !== 'ignore-0rtt') {
      const fresh = await server.receive(await flight(identity, 3_600_001), 'original', issuedAtMs + 3_600_001);
      expect(fresh.executedPayment, `${id}: stale rejection must not consume the ticket`).toBe(true);
    }
  }
});

test('[verdict:ticket-expiry] zero lifetime is immediately unusable and the exact deadline is expired', async () => {
  const zero = await new EarlyDataServer('zero', 'single-use-ticket', stek)
    .receive(await flight(await ticket(0), 0), 'original', issuedAtMs);
  expect(zero.ticketValid).toBe(false);
  expect(zero.executedPayment).toBe(false);
  expect(zero.earlyDataDecrypted).toBe(false);
  expect(zero.oneRttFallback).toBe(true);

  const identity = await ticket(1);
  const before = await new EarlyDataServer('before deadline', 'single-use-ticket', stek)
    .receive(await flight(identity, 999), 'original', issuedAtMs + 999);
  expect(before.executedPayment).toBe(true);
  const deadline = await new EarlyDataServer('at deadline', 'single-use-ticket', stek)
    .receive(await flight(identity, 1000), 'original', issuedAtMs + 1000);
  expect(deadline.ticketValid).toBe(false);
  expect(deadline.earlyDataDecrypted).toBe(false);
  expect(deadline.oneRttFallback).toBe(true);
});

test('ticket encoders reject non-integer, negative, non-finite, and over-limit lifetimes', async () => {
  for (const lifetime of [-1, 0.5, NaN, Infinity, 604801]) {
    await expect(ticket(lifetime)).rejects.toThrow(/ticket_lifetime/);
    expect(() => serializeNewSessionTicket({
      ticketLifetime: lifetime, ticketAgeAdd, ticketNonce: new Uint8Array(8),
      ticket: new Uint8Array(32), maxEarlyDataSize: 4096,
    })).toThrow(/ticket_lifetime/);
  }
});

test('each full-handshake authentication condition independently prevents ticket issuance', async () => {
  const honest = await runFullHandshake();
  const failed = [
    { ...honest, chainVerdict: { ...honest.chainVerdict, valid: false } },
    ...(['certificateVerifyValid', 'serverFinishedValid', 'clientFinishedValid', 'sharedSecretAgrees'] as const)
      .map((field) => ({ ...honest, [field]: false })),
  ];
  for (const trace of failed) {
    await expect(createResumptionLab(trace)).rejects.toBeInstanceOf(ResumptionUnavailableError);
  }
});
