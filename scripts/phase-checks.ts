/**
 * Runnable verification gates for crypto-lab-tls-handshake.
 *
 * These assert real, checkable properties — not that "the demo runs":
 *  - keyschedule: RFC 8448 HKDF-Expand-Label vector + key-schedule determinism
 *  - auth:        cert chain accepts the good chain / rejects every tampered one,
 *                 CertificateVerify accepts genuine and rejects forged, MITM blocked
 *  - record:      AES-128-GCM round-trips, tampering is rejected, nonces are unique
 *  - handshake:   the full handshake agrees end-to-end across many runs
 *  - (always)     no Math.random in src/ — cryptographic randomness only
 *
 * Run all: `npm test`  ·  one phase: `tsx scripts/phase-checks.ts <phase>`
 */
import {
  concatBytes,
  ed25519Keygen,
  ed25519Sign,
  ed25519Verify,
  equalBytes,
  hkdfExpandLabel,
  hkdfExtract,
  recordNonce,
  toHex,
  utf8,
} from '../src/primitives';
import { deriveKeySchedule, deriveTrafficKeys, finishedMac, verifyFinished } from '../src/keyschedule';
import {
  certificateVerifyContent,
  issueChain,
  signCertificateVerify,
  verifyCertificateVerify,
  verifyChain,
} from '../src/certs';
import { runFullHandshake, runMitmAttempt } from '../src/handshake';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Scan production source for a forbidden pattern; return offending files. */
function scanSource(pattern: RegExp): string[] {
  const dir = join(process.cwd(), 'src');
  const hits: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry.endsWith('.ts') && pattern.test(readFileSync(join(dir, entry), 'utf8'))) {
      hits.push(entry);
    }
  }
  return hits;
}

async function phaseKeySchedule(): Promise<void> {
  // RFC 8448 §3 "Simple 1-RTT Handshake": Derive-Secret(Early Secret, "derived", "").
  const earlyPrk = fromHex('33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a');
  const emptyHash = fromHex('e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55');
  const expected = fromHex('6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba');
  const got = await hkdfExpandLabel(earlyPrk, 'derived', emptyHash, 32);
  assert(equalBytes(got, expected), 'HKDF-Expand-Label does not match RFC 8448 "derived" vector');

  // Early Secret with no PSK is HKDF-Extract(0^32, 0^32) and is the well-known constant.
  const earlySecret = await hkdfExtract(new Uint8Array(32), new Uint8Array(32));
  assert(equalBytes(earlySecret, earlyPrk), 'Early Secret (no PSK) must equal the RFC 8448 constant');

  // The full schedule must be deterministic in its inputs and produce distinct,
  // 32-byte secrets at every stage (no accidental aliasing of secrets).
  const shared = fromHex('01'.repeat(32));
  const thA = fromHex('aa'.repeat(32));
  const thB = fromHex('bb'.repeat(32));
  const s1 = await deriveKeySchedule(shared, thA, thB);
  const s2 = await deriveKeySchedule(shared, thA, thB);
  const secrets = [
    s1.earlySecret,
    s1.handshakeSecret,
    s1.masterSecret,
    s1.clientHandshakeTrafficSecret,
    s1.serverHandshakeTrafficSecret,
    s1.clientApplicationTrafficSecret,
    s1.serverApplicationTrafficSecret,
    s1.exporterMasterSecret,
  ];
  for (const sec of secrets) {
    assert(sec.length === 32, 'Every schedule secret must be 32 bytes');
  }
  assert(equalBytes(s1.handshakeSecret, s2.handshakeSecret), 'Key schedule must be deterministic');
  const seen = new Set(secrets.map(toHex));
  assert(seen.size === secrets.length, 'Schedule secrets must all be distinct (no aliasing)');

  // Changing the (EC)DHE input must change the handshake secret.
  const s3 = await deriveKeySchedule(fromHex('02'.repeat(32)), thA, thB);
  assert(!equalBytes(s1.handshakeSecret, s3.handshakeSecret), 'Different ECDHE input must change handshake secret');

  // Finished MAC verifies for the right transcript and rejects a changed one.
  const fin = await finishedMac(s1.serverHandshakeTrafficSecret, thA);
  assert(fin.length === 32, 'Finished verify_data must be 32 bytes');
  assert(await verifyFinished(s1.serverHandshakeTrafficSecret, thA, fin), 'Finished must verify for its transcript');
  assert(!(await verifyFinished(s1.serverHandshakeTrafficSecret, thB, fin)), 'Finished must reject a different transcript');

  console.log('keyschedule gates: PASS');
}

async function phaseAuth(): Promise<void> {
  const chain = issueChain('example.com');

  // Good chain validates against its own root.
  const good = verifyChain(chain, chain.rootPublicKey);
  assert(good.valid && good.rootSelfSignatureValid && good.leafSignatureValid && good.trustAnchorMatches, 'Genuine chain must validate');

  // Wrong trust anchor → trustAnchorMatches false, overall invalid.
  const otherRoot = ed25519Keygen().publicKey;
  assert(!verifyChain(chain, otherRoot).valid, 'Chain must fail against an untrusted root');

  // Tampered leaf public key → leaf signature must fail.
  const tamperedLeaf = {
    ...chain,
    leaf: { ...chain.leaf, publicKey: (() => { const p = Uint8Array.from(chain.leaf.publicKey); p[0] ^= 1; return p; })() },
  };
  assert(!verifyChain(tamperedLeaf, chain.rootPublicKey).leafSignatureValid, 'Tampered leaf key must break the leaf signature');

  // CertificateVerify: genuine signature accepts, forged (wrong key) rejects.
  const th = fromHex('cc'.repeat(32));
  const sig = signCertificateVerify(th, chain.leafSecretKey);
  assert(verifyCertificateVerify(th, sig, chain.leaf.publicKey), 'Genuine CertificateVerify must verify');
  const wrongKey = ed25519Keygen();
  const forged = signCertificateVerify(th, wrongKey.secretKey);
  assert(!verifyCertificateVerify(th, forged, chain.leaf.publicKey), 'Forged CertificateVerify must be rejected');
  // A genuine signature over a DIFFERENT transcript must not transfer.
  assert(!verifyCertificateVerify(fromHex('dd'.repeat(32)), sig, chain.leaf.publicKey), 'CertificateVerify must bind the transcript');

  // The signed content matches RFC 8446 §4.4.3 framing (64x 0x20 ‖ ctx ‖ 0x00 ‖ hash).
  const content = certificateVerifyContent(th);
  const prefix = concatBytes(new Uint8Array(64).fill(0x20), utf8('TLS 1.3, server CertificateVerify'), new Uint8Array([0]));
  assert(equalBytes(content.subarray(0, prefix.length), prefix), 'CertificateVerify content prefix must match RFC 8446');
  assert(equalBytes(content.subarray(prefix.length), th), 'CertificateVerify must end with the transcript hash');

  // Raw Ed25519 sanity (round-trip + tamper).
  const k = ed25519Keygen();
  const m = utf8('handshake');
  const s = ed25519Sign(m, k.secretKey);
  assert(ed25519Verify(s, m, k.publicKey), 'Ed25519 round-trip failed');
  const m2 = Uint8Array.from(m); m2[0] ^= 1;
  assert(!ed25519Verify(s, m2, k.publicKey), 'Ed25519 must reject a tampered message');

  // MITM is blocked precisely because the attacker cannot forge CertificateVerify.
  const mitm = await runMitmAttempt('example.com');
  assert(mitm.keyExchangeSucceeded, 'MITM ECDHE should succeed (proves key exchange alone is insufficient)');
  assert(!mitm.certificateVerifyAccepted, 'MITM forged CertificateVerify must be rejected');
  assert(mitm.attackBlocked, 'MITM attack must be blocked by authentication');

  console.log('auth gates: PASS');
}

async function phaseRecord(): Promise<void> {
  const trace = await runFullHandshake('example.com');
  const r = trace.record;
  assert(r.roundTripOk, 'AES-128-GCM record must decrypt back to the plaintext');
  assert(r.tamperRejected, 'A flipped ciphertext byte must be rejected by GCM');
  assert(r.ciphertextBytes >= r.plaintext.length + 16, 'Ciphertext must include the 16-byte GCM tag (and inner content type)');

  // Per-record nonces must differ per sequence number and reduce to write_iv at seq 0... no:
  // seq 0 XORs nothing into the low bytes, so nonce(seq0) == write_iv; nonce(seq1) differs.
  const iv = trace.clientAppKeys.iv;
  const n0 = recordNonce(iv, 0);
  const n1 = recordNonce(iv, 1);
  const n2 = recordNonce(iv, 258);
  assert(equalBytes(n0, iv), 'Record nonce at seq 0 must equal write_iv');
  assert(!equalBytes(n0, n1) && !equalBytes(n1, n2) && !equalBytes(n0, n2), 'Record nonces must be unique per sequence number');
  assert(n0.length === 12 && n1.length === 12, 'Record nonce must be 12 bytes');

  // Record key/iv are real HKDF-Expand-Label outputs of the expected sizes.
  const keys = await deriveTrafficKeys(trace.schedule.serverApplicationTrafficSecret);
  assert(keys.key.length === 16 && keys.iv.length === 12, 'Traffic key=16B, iv=12B');
  assert(!equalBytes(keys.key.subarray(0, 12), keys.iv), 'key and iv must be independent derivations');

  console.log('record gates: PASS');
}

async function phaseHandshake(): Promise<void> {
  const trace = await runFullHandshake('example.com');
  assert(trace.sharedSecretAgrees, 'Client and server must compute the same ECDHE secret');
  assert(trace.certificateVerifyValid, 'CertificateVerify must verify in a genuine handshake');
  assert(trace.serverFinishedValid, 'Server Finished must verify');
  assert(trace.clientFinishedValid, 'Client Finished must verify');
  assert(trace.chainVerdict.valid, 'Certificate chain must validate');
  assert(trace.steps.length === 8, `Expected 8 handshake steps, got ${trace.steps.length}`);

  // The trace must move through all three flights in order.
  const flights = trace.steps.map((s) => s.flight);
  for (let i = 1; i < flights.length; i += 1) {
    assert(flights[i] >= flights[i - 1], 'Handshake steps must be in flight order');
  }
  assert(flights[0] === 1 && flights[flights.length - 1] === 3, 'First flight 1, last flight 3');

  // Real wire sizes: ClientHello is a small plaintext; the server flight (with
  // the certificate chain) is the bulk of the handshake.
  assert(trace.clientHelloBytes > 40 && trace.clientHelloBytes < 512, `ClientHello size unexpected: ${trace.clientHelloBytes}`);
  assert(trace.serverFlightBytes > trace.clientHelloBytes, 'Server flight should be larger than ClientHello');

  // End-to-end determinism of correctness across many fresh sessions.
  for (let i = 0; i < 40; i += 1) {
    const t = await runFullHandshake('host-' + i + '.example');
    assert(
      t.sharedSecretAgrees && t.certificateVerifyValid && t.serverFinishedValid && t.clientFinishedValid && t.chainVerdict.valid,
      `Handshake run ${i} failed an end-to-end check`,
    );
  }

  console.log('handshake gates: PASS');
}

function phaseDiscipline(): void {
  const hits = scanSource(/Math\.random/);
  assert(hits.length === 0, `Math.random found in src/: ${hits.join(', ')} (use crypto.getRandomValues)`);
  console.log('discipline gate (no Math.random in src/): PASS');
}

async function main(): Promise<void> {
  const phase = process.argv[2] ?? 'all';
  const run: Record<string, () => Promise<void> | void> = {
    keyschedule: phaseKeySchedule,
    auth: phaseAuth,
    record: phaseRecord,
    handshake: phaseHandshake,
    discipline: phaseDiscipline,
  };

  if (phase === 'all') {
    phaseDiscipline();
    await phaseKeySchedule();
    await phaseAuth();
    await phaseRecord();
    await phaseHandshake();
    console.log('\nALL GATES PASS');
    return;
  }

  const fn = run[phase];
  if (!fn) {
    throw new Error(`Usage: tsx scripts/phase-checks.ts <all|keyschedule|auth|record|handshake|discipline>`);
  }
  await fn();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
