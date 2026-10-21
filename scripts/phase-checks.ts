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
  hkdfExpand,
  hkdfExpandLabel,
  hkdfExtract,
  recordNonce,
  sha256,
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
import {
  deriveResumptionBinder,
  deriveResumptionSchedule,
  deriveResumptionSecret,
  deriveTicketPsk,
} from '../src/resumption';
import { parsePskClientHello } from '../src/clienthello-psk';
import { openApplicationRecord, sealApplicationRecord } from '../src/zerortt';
import {
  PAYMENT_REQUEST,
  createResumptionLab,
  runBinderProbe,
  runEdgeCases,
  runReplayScenario,
  runStekLeak,
  ticketPskRoundTrip,
} from '../src/resumption-lab';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

let assertionCount = 0;

function assert(condition: boolean, message: string): void {
  assertionCount += 1;
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
  const visit = (current: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else if (entry.name.endsWith('.ts') && pattern.test(readFileSync(path, 'utf8'))) {
        hits.push(path.slice(dir.length + 1));
      }
    }
  };
  visit(dir);
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
  // ...and reject when the two sides did not agree on the ECDHE secret. This is
  // the property that makes runFullHandshake's serverFinishedValid /
  // clientFinishedValid meaningful: the verifier derives its finished_key from
  // its OWN X25519 output, so a disagreement has to surface here.
  assert(
    !(await verifyFinished(s3.serverHandshakeTrafficSecret, thA, fin)),
    'Finished must reject a peer that derived from a different ECDHE secret',
  );

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

  // The signed content matches RFC 9846 §4.5.2 framing (64x 0x20 ‖ ctx ‖ 0x00 ‖ hash).
  const content = certificateVerifyContent(th);
  const prefix = concatBytes(new Uint8Array(64).fill(0x20), utf8('TLS 1.3, server CertificateVerify'), new Uint8Array([0]));
  assert(equalBytes(content.subarray(0, prefix.length), prefix), 'CertificateVerify content prefix must match RFC 9846');
  assert(equalBytes(content.subarray(prefix.length), th), 'CertificateVerify must end with the transcript hash');

  // Raw Ed25519 sanity (round-trip + tamper).
  const k = ed25519Keygen();
  const m = utf8('handshake');
  const s = ed25519Sign(m, k.secretKey);
  assert(ed25519Verify(s, m, k.publicKey), 'Ed25519 round-trip failed');
  const m2 = Uint8Array.from(m); m2[0] ^= 1;
  assert(!ed25519Verify(s, m2, k.publicKey), 'Ed25519 must reject a tampered message');

  // --- The server's certificate key must actually be LONG-TERM --------------
  // Section 5 tells the reader that an attacker who later steals the server's
  // long-term certificate key still cannot recover past session keys. That claim
  // is empty if the certificate key is minted fresh every session, so assert the
  // model has one identity and many sessions.
  const sessionA = await runFullHandshake('longterm.example');
  const sessionB = await runFullHandshake('longterm.example');
  assert(
    equalBytes(sessionA.chain.leaf.publicKey, sessionB.chain.leaf.publicKey),
    'Server leaf certificate key must persist across sessions (it is the long-term identity)',
  );
  assert(
    sessionA.keyExchange.serverPublicHex !== sessionB.keyExchange.serverPublicHex,
    'Ephemeral key shares must NOT persist across sessions',
  );
  assert(
    !equalBytes(sessionA.schedule.handshakeSecret, sessionB.schedule.handshakeSecret),
    'Session secrets must NOT persist across sessions',
  );

  // --- The MITM exhibit must attack THIS session's real material ------------
  const trace = await runFullHandshake('example.com');
  const materials = trace.sessionMaterials;
  const attacks = ['reuse-cert', 'own-key', 'relay'] as const;
  for (const attack of attacks) {
    const m = await runMitmAttempt(materials, attack);
    assert(
      m.sessionTranscriptHex === trace.certVerifyTranscriptHex,
      `MITM (${attack}) must report the session's real CertificateVerify transcript, not a separate invention`,
    );
    assert(m.keyExchangeSucceeded, `MITM (${attack}): the client always completes ECDHE with the peer it saw`);
    assert(m.attackBlocked, `MITM (${attack}) must not yield a readable session to the attacker`);
  }

  // Reuse the server's certificate: the chain is genuine and validates, but the
  // attacker has no leaf private key, and the server's own signature cannot be
  // moved onto the transcript the attacker's key share created.
  const reuse = await runMitmAttempt(materials, 'reuse-cert');
  assert(reuse.chainVerdict.valid, 'A replayed genuine chain must still validate — certificates are public');
  assert(!reuse.certificateVerifyAccepted, 'An attacker without the leaf private key must fail CertificateVerify');
  assert(reuse.transcriptsDiffer, 'Injecting its own key share must change the transcript the client hashes');
  assert(!reuse.replayedSignatureAccepted, "The server's genuine signature must not satisfy the attacker's transcript");
  assert(!reuse.clientAccepts, 'Client must reject the reuse-certificate attack');
  assert(reuse.attackerHoldsSessionSecret, 'The attacker does complete ECDHE — key exchange alone proves nothing');

  // Sign with its own key: the signature is perfectly valid under the key the
  // attacker presented. What stops it is the trust anchor, not the signature.
  const own = await runMitmAttempt(materials, 'own-key');
  assert(
    own.certificateVerifyAccepted,
    'An attacker signing with its own leaf key produces a signature that DOES verify under that leaf',
  );
  assert(!own.chainVerdict.trustAnchorMatches, "An attacker-minted root must not match the client's trust anchor");
  assert(!own.chainVerdict.valid, 'An attacker-minted chain must fail chain validation');
  assert(!own.clientAccepts, 'Client must reject the sign-with-own-key attack');

  // Relay unchanged: every check passes, because the client really is talking to
  // the real server. The attacker gains nothing — it never injected a key share.
  const relay = await runMitmAttempt(materials, 'relay');
  assert(!relay.transcriptsDiffer, 'Relaying unchanged must reproduce the genuine transcript exactly');
  assert(
    relay.chainVerdict.valid && relay.certificateVerifyAccepted && relay.clientAccepts,
    'A pure relay is indistinguishable from the real server, so the client accepts',
  );
  assert(!relay.attackerHoldsSessionSecret, 'A pure relay never obtains the session secret');

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

  // Every step's transcript chip must name the run of messages it is actually a
  // hash of. The chip used to be labelled "SHA-256(messages 1..N)" with N the
  // step's own ordinal, which was wrong wherever a signature or MAC covers the
  // transcript ending just BEFORE its own message.
  for (const s of trace.steps) {
    assert(s.transcriptCovers.length > 0, `Step ${s.id} must say what its transcript hash covers`);
  }
  const covers = (id: string): string => trace.steps.find((s) => s.id === id)!.transcriptCovers;
  const hashOf = (id: string): string => trace.steps.find((s) => s.id === id)!.transcriptHashHex;
  assert(covers('certificate-verify') === 'ClientHello..Certificate', 'CertificateVerify signs the transcript ending at Certificate');
  assert(covers('server-finished') === 'ClientHello..CertificateVerify', 'Server Finished MACs the transcript ending at CertificateVerify');
  // Tie the label to the cryptography, not just to a string: the hash the
  // CertificateVerify step displays must be the one the real signature verifies
  // over. If the chip ever showed a different transcript, this fails.
  assert(hashOf('certificate-verify') === trace.certVerifyTranscriptHex, 'CertificateVerify chip must show the signed transcript');
  assert(
    verifyCertificateVerify(
      fromHex(hashOf('certificate-verify')),
      trace.sessionMaterials.certVerifySignature,
      trace.chain.leaf.publicKey,
    ),
    'The transcript hash the CertificateVerify step displays must be the one its signature actually verifies over',
  );
  assert(hashOf('server-finished') !== hashOf('certificate-verify'), 'Appending CertificateVerify must move the transcript on');

  // The page's "Break this handshake" controls must produce real failures, not a
  // relabelled honest run. Each fault is re-run here and every verdict the panel
  // prints is asserted against what that fault should actually do — including
  // the checks it must NOT break, since that separation is the lesson.
  assert(trace.fault === 'none' && trace.faultDetail === '', 'A default run must report no injected fault');

  const ecdhe = await runFullHandshake('example.com', 'ecdhe');
  assert(!ecdhe.sharedSecretAgrees, 'ecdhe fault: the two ECDHE outputs must differ');
  assert(!ecdhe.serverFinishedValid, 'ecdhe fault: the client must reject the server Finished');
  assert(!ecdhe.clientFinishedValid, 'ecdhe fault: the server must reject the client Finished');
  assert(ecdhe.certificateVerifyValid, 'ecdhe fault: CertificateVerify must still verify — the transcript is untouched');
  assert(ecdhe.chainVerdict.valid, 'ecdhe fault: the chain must still validate');
  assert(ecdhe.faultDetail.length > 0, 'ecdhe fault: the panel must describe the injection from the run');

  const tampered = await runFullHandshake('example.com', 'transcript');
  assert(!tampered.certificateVerifyValid, 'transcript fault: the signature must not fit the transcript the client hashed');
  assert(!tampered.serverFinishedValid, 'transcript fault: the server Finished MAC must not verify');
  assert(!tampered.clientFinishedValid, 'transcript fault: the client Finished MAC must not verify');
  assert(tampered.sharedSecretAgrees, 'transcript fault: ECDHE is untouched, so the secrets must still agree');
  assert(tampered.chainVerdict.valid, 'transcript fault: the chain itself is untouched, so it must still validate');
  assert(tampered.faultDetail.length > 0, 'transcript fault: the panel must describe the injection from the run');

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

/**
 * Published TLS 1.3 resumption ground truth.
 *
 * These are copied from RFC 8448 §§3–4 (not generated by this lab).  The
 * 477-byte ClientHello prefix ends after OfferedPsks.identities; its enclosing
 * lengths already describe the final 512-byte ClientHello.  Appending the
 * binder vector therefore gives the exact wire message whose transcript feeds
 * early traffic and the resumed key schedule.
 */
async function phaseResumption(): Promise<void> {
  const rfcMainSecret = fromHex('18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919');
  const transcriptToClientFinishedHash = fromHex('209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d');
  const expectedResumptionSecret = fromHex('7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c');
  const ticketNonce = fromHex('0000');
  const expectedPsk = fromHex('4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3');

  const prefix = fromHex(
    '010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb',
  );
  const expectedBinder = fromHex('3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d');
  const clientHello = concatBytes(prefix, fromHex('002120'), expectedBinder);
  const serverHello = fromHex(
    '0200005c03033ccfd2dec890222763472ae8136777c9d7358777bb66e91ea5122495f559ea2d00130100003400290002000000330024001d0020121761ee42c333e1b9e77b60dd57c2053cd94512ab47f115e86eff50942cea31002b00020304',
  );

  const resumptionSecret = await deriveResumptionSecret(rfcMainSecret, transcriptToClientFinishedHash);
  assert(equalBytes(resumptionSecret, expectedResumptionSecret), 'RFC 8448 resumption master secret mismatch');
  const psk = await deriveTicketPsk(resumptionSecret, ticketNonce);
  assert(equalBytes(psk, expectedPsk), 'RFC 8448 ticket PSK mismatch');

  const binder = await deriveResumptionBinder(psk, prefix);
  assert(
    equalBytes(binder.earlySecret, fromHex('9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c')),
    'RFC 8448 PSK Early Secret mismatch',
  );
  assert(
    equalBytes(binder.transcriptHash, fromHex('63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14')),
    'RFC 8448 binder transcript hash mismatch',
  );
  assert(
    equalBytes(binder.binderKey, fromHex('69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256')),
    'RFC 8448 binder key mismatch',
  );
  assert(
    equalBytes(binder.finishedKey, fromHex('5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa')),
    'RFC 8448 binder finished key mismatch',
  );
  assert(equalBytes(binder.binder, expectedBinder), 'RFC 8448 binder mismatch');

  const schedule = await deriveResumptionSchedule({
    psk,
    mode: 'psk_dhe_ke',
    dheSharedSecret: fromHex('f44194756ff9ec9d25180635d66ea6824c6ab3bf179977be37f723570e7ccb2e'),
    clientHello,
    serverHello,
    // Main Secret does not depend on this later transcript.  The lab supplies
    // a real byte transcript here and checks its published earlier stages.
    transcriptToServerFinished: concatBytes(clientHello, serverHello),
  });
  assert(
    equalBytes(schedule.clientEarlyTrafficSecret, fromHex('3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62')),
    'RFC 8448 client early traffic secret mismatch',
  );
  assert(
    equalBytes(schedule.handshakeSecret, fromHex('005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6')),
    'RFC 8448 Handshake Secret mismatch',
  );
  assert(
    equalBytes(schedule.clientHandshakeTrafficSecret, fromHex('2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f')),
    'RFC 8448 client handshake traffic secret mismatch',
  );
  assert(
    equalBytes(schedule.serverHandshakeTrafficSecret, fromHex('fe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803')),
    'RFC 8448 server handshake traffic secret mismatch',
  );
  assert(
    equalBytes(schedule.mainSecret, fromHex('e2d32d4ed66dd37897a0e80c84107503ce58bf8aad4cb55a5002d77ecb890ece')),
    'RFC 8448 Main Secret mismatch',
  );
  const rfcEarlyRecord = fromHex('1703030017ab1df420e75c457a7cc5d2844f76d5aee4b4edbf049be0');
  const openedRfcEarly = await openApplicationRecord(schedule.clientEarlyTrafficSecret, rfcEarlyRecord);
  assert(equalBytes(openedRfcEarly, utf8('ABCDEF')), 'RFC 8448 encrypted early-data record did not open to ABCDEF');

  // Integration: the lab's generated bytes, not fixture booleans, must drive
  // every verdict.  PAYMENT_REQUEST spans multiple AES blocks.
  const full = await runFullHandshake('example.com');
  const lab = await createResumptionLab(full);
  assert(await ticketPskRoundTrip(lab), 'ticket did not carry the PSK derived by the client');
  assert(lab.issued.ticket.ticketLifetime <= 604_800, 'ticket lifetime exceeds the RFC maximum');
  assert(PAYMENT_REQUEST.length > 16, '0-RTT integration plaintext must exceed one AES block');
  const parsed = parsePskClientHello(lab.sessions.psk_dhe_ke.clientHello.full);
  assert(parsed.extensionOrder.at(-1) === 'pre_shared_key', 'pre_shared_key must be last');
  assert(parsed.truncated.length < parsed.full.length, 'binder transcript was not truncated');
  assert((await runBinderProbe(lab, 'psk_dhe_ke', false)).valid, 'genuine binder must verify');
  const flipped = await runBinderProbe(lab, 'psk_dhe_ke', true);
  assert(!flipped.valid && !flipped.earlyPlaintextReleased, 'changed identity must fail before early decrypt');

  const leak = await runStekLeak(lab);
  assert(leak.pskKe.binderValid && leak.pskKe.earlyDataReadable, 'STEK leak must recover PSK-only early data');
  assert(leak.pskKe.oneRttReadable, 'STEK leak must recover PSK-only 1-RTT data');
  assert(leak.pskDhe.binderValid && leak.pskDhe.earlyDataReadable, 'STEK leak must recover DHE-mode early data');
  assert(!leak.pskDhe.oneRttReadable, 'fresh X25519 must seal DHE-mode 1-RTT data after a STEK leak');

  const expectations: Record<string, { payments: number; ok: boolean }> = {
    'no-anti-replay': { payments: 2, ok: false },
    'single-use-ticket': { payments: 1, ok: true },
    'clienthello-recording': { payments: 1, ok: false },
    'freshness-window': { payments: 2, ok: false },
    'ignore-0rtt': { payments: 1, ok: true },
  };
  for (const configuration of Object.keys(expectations) as (keyof typeof expectations)[]) {
    const scenario = await runReplayScenario(lab, configuration);
    assert(
      scenario.regionA.executedPayments === expectations[configuration].payments,
      `${configuration}: displayed execution count must come from accepted plaintexts`,
    );
    assert(scenario.verdictOk === expectations[configuration].ok, `${configuration}: unexpected replay verdict`);
    assert(
      scenario.regionA.executedPayments === scenario.regionA.log.filter((entry) => entry.executedPayment).length,
      `${configuration}: execution counter must equal the execution log`,
    );
    if (configuration === 'clienthello-recording') {
      assert(!scenario.replayA.accepted0Rtt && scenario.replayB.accepted0Rtt, 'recording must be region-local');
    }
    if (configuration === 'ignore-0rtt') {
      assert(scenario.oneRttReplayRejected, 'resending after the handshake must bind a fresh server nonce');
    }
  }

  const edges = await runEdgeCases(lab);
  assert(edges.expiredTicket.oneRttFallback, 'expired ticket must fall back to a full handshake');
  assert(edges.tamperedTicket.oneRttFallback, 'tampered ticket must fall back without plaintext');
  assert(!edges.untruncatedBinderValid, 'binder over an untruncated ClientHello must fail');
  assert(edges.pskKeRejectedByDheOnlyServer, 'a DHE-only server must reject psk_ke');
  assert(edges.freshnessFallback.oneRttFallback, 'outside-window 0-RTT must allow 1-RTT fallback');

  const longRecord = await sealApplicationRecord(schedule.clientEarlyTrafficSecret, utf8(PAYMENT_REQUEST));
  assert(
    equalBytes(await openApplicationRecord(schedule.clientEarlyTrafficSecret, longRecord.wire), utf8(PAYMENT_REQUEST)),
    'multi-block early-data record failed its real AEAD round trip',
  );

  // The original no-PSK function remains bit-for-bit deterministic after the
  // extension; the new schedule lives on a separate call path.
  const shared = fromHex('01'.repeat(32));
  const helloHash = fromHex('aa'.repeat(32));
  const finishedHash = fromHex('bb'.repeat(32));
  const before = await deriveKeySchedule(shared, helloHash, finishedHash);
  await deriveResumptionSchedule({ psk, mode: 'psk_ke', clientHello, serverHello, transcriptToServerFinished: clientHello });
  const after = await deriveKeySchedule(shared, helloHash, finishedHash);
  assert(JSON.stringify(Object.fromEntries(Object.entries(before).map(([k, v]) => [k, toHex(v)]))) ===
    JSON.stringify(Object.fromEntries(Object.entries(after).map(([k, v]) => [k, toHex(v)]))),
  'resumption calls must not mutate the original full-handshake schedule');

  const attackSources = ['src/attack/replay.ts', 'src/attack/stek-leak.ts'].map((path) => readFileSync(path, 'utf8')).join('\n');
  assert(!/secretKey|privateKey|sessionMaterials|ResumptionLab/.test(attackSources), 'attack modules crossed the wire-only import boundary');

  console.log('13 published TLS resumption assertions matched (RFC 8448 §§3–4).');
  console.log('resumption, 0-RTT, replay, and STEK-leak gates: PASS');
}

function phaseDiscipline(): void {
  const hits = scanSource(/Math\.random/);
  assert(hits.length === 0, `Math.random found in src/: ${hits.join(', ')} (use crypto.getRandomValues)`);
  console.log('discipline gate (no Math.random in src/): PASS');
}


/* RFC 5869 Appendix A test vectors for HKDF-SHA-256, GROUND TRUTH for the
 * Extract-and-Expand implementation in src/primitives.ts.
 *
 * COPIED FROM THE PUBLICATION, not reproduced from a library. The bytes were
 * extracted from the RFC's own text at https://www.rfc-editor.org/rfc/rfc5869.txt
 * and each one's length matches the octet count the RFC states beside it. A
 * vector regenerated from WebCrypto would agree with this code for the same
 * reason it agrees with itself, and would prove nothing.
 *
 * Only the three SHA-256 cases are here. A.4 to A.7 are SHA-1, which this lab
 * does not implement, and asserting them would mean adding an algorithm to pass
 * a test rather than testing the algorithm the lab has.
 *
 * Case A.3 is the one that mattered: its salt is absent, which RFC 5869 section
 * 2.2 defines as HashLen zeros, and hkdfExtract passed the empty array straight
 * to WebCrypto -- which throws `Zero-length key is not supported`. The existing
 * RFC 8448 assertions could not catch it, because they exercise
 * HKDF-Expand-Label with a 32-byte secret and never reach the default. */
const RFC5869_SHA256_VECTORS = [
  {
    name: 'RFC 5869 Appendix A.1',
    ikm:
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt:
      '000102030405060708090a0b0c',
    info:
      'f0f1f2f3f4f5f6f7f8f9',
    length: 42,
    prk:
      '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
    okm:
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
      '34007208d5b887185865',
  },
  {
    name: 'RFC 5869 Appendix A.2',
    ikm:
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
      '404142434445464748494a4b4c4d4e4f',
    salt:
      '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
      'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info:
      'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
      'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
      'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    length: 82,
    prk:
      '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
    okm:
      'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c' +
      '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71' +
      'cc30c58179ec3e87c14c01d5c1f3434f1d87',
  },
  {
    name: 'RFC 5869 Appendix A.3',
    ikm:
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt:'',
    info:'',
    length: 42,
    prk:
      '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
    okm:
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d' +
      '9d201395faa4b61a96c8',
  },
] as const;

async function phaseRfc5869(): Promise<void> {
  for (const v of RFC5869_SHA256_VECTORS) {
    const prk = await hkdfExtract(fromHex(v.salt), fromHex(v.ikm));
    assert(equalBytes(prk, fromHex(v.prk)), `${v.name}: HKDF-Extract PRK does not match the published value`);
    const okm = await hkdfExpand(prk, fromHex(v.info), v.length);
    assert(equalBytes(okm, fromHex(v.okm)), `${v.name}: HKDF-Expand OKM does not match the published value`);
    console.log(`PASS  ${v.name} -- PRK and ${v.length}-byte OKM match the published vector`);
  }
  console.log(`\n${RFC5869_SHA256_VECTORS.length * 2} published HKDF assertions matched (RFC 5869 Appendix A, SHA-256).`);
}

async function main(): Promise<void> {
  const phase = process.argv[2] ?? 'all';
  const run: Record<string, () => Promise<void> | void> = {
    keyschedule: phaseKeySchedule,
    auth: phaseAuth,
    record: phaseRecord,
    handshake: phaseHandshake,
    discipline: phaseDiscipline,
    rfc5869: phaseRfc5869,
    resumption: phaseResumption,
  };

  if (phase === 'all') {
    phaseDiscipline();
    await phaseKeySchedule();
    await phaseAuth();
    await phaseRecord();
    await phaseHandshake();
    await phaseRfc5869();
    await phaseResumption();
    console.log(`\nALL GATES PASS (${assertionCount} assertions)`);
    return;
  }

  const fn = run[phase];
  if (!fn) {
    throw new Error(`Usage: tsx scripts/phase-checks.ts <all|keyschedule|auth|record|handshake|discipline|rfc5869|resumption>`);
  }
  await fn();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
